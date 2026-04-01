import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Cleaner/2.0"

# الحد الأقصى لحجم كل جزء (بالميجابايت)
MAX_PART_SIZE_MB = 10

def clean_domain(domain):
    """تنظيف النطاق من الرموز غير المسموحة"""
    domain = domain.strip().lower()
    # إزالة الشرطات الزائدة
    domain = domain.strip('-')
    # منع الشرطات المتتالية
    if '--' in domain:
        return None
    # منع النطاق الذي يبدأ برقم يليه شرطة
    if re.match(r'^[0-9]+-', domain):
        return None
    # منع النطاق الذي يبدأ أو ينتهي بنقطة
    if domain.startswith('.') or domain.endswith('.'):
        return None
    # منع النطاق القصير جداً
    if len(domain) < 4:
        return None
    # منع الأحرف غير المسموحة
    if re.search(r'[^a-z0-9\.\-]', domain):
        return None
    # يجب أن يحتوي على نقطة على الأقل
    if '.' not in domain:
        return None
    return domain

def extract_domain_only(line):
    """استخراج النطاق فقط من أي قاعدة، مع تجاهل الشروط والنجوم"""
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None, None

    is_exception = line.startswith('@@')
    content = line[2:] if is_exception else line

    # إزالة أي شيء بعد $ (شروط)
    content = content.split('$')[0]
    # إزالة أي شيء بعد / (إن وجد)
    content = content.split('/')[0]
    # إزالة النجمة * (لا يمكن استخدامها في DNS)
    content = content.replace('*', '')

    # البحث عن نطاق صالح: يبدأ بحرف أو رقم، ثم أي عدد من الحروف/الأرقام/الشرطات/النقاط، وينتهي بـ TLD
    # نستخدم نمطاً صارماً يمنع الأرقام كبداية غير طبيعية
    match = re.search(r'([a-z][a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]{2,}|[a-z][a-z0-9\-]*\.[a-z]{2,})', content, re.IGNORECASE)
    if not match:
        return None, None

    domain = match.group(1).lower()
    domain = clean_domain(domain)
    if not domain:
        return None, None

    return domain, is_exception

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        r.raise_for_status()
        domains = set()
        exceptions = set()
        for line in r.text.splitlines():
            domain, is_exception = extract_domain_only(line)
            if domain:
                if is_exception:
                    exceptions.add(domain)
                else:
                    domains.add(domain)
        return domains, exceptions, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return set(), set(), url

def process_filters(urls):
    all_domains = set()
    all_exceptions = set()
    total = len(urls)
    print(f"🔍 معالجة {total} مصدر (استخراج النطاقات الصالحة فقط)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            domains, exceptions, url = future.result()
            new_domains = domains - all_domains
            new_exceptions = exceptions - all_exceptions
            all_domains.update(domains)
            all_exceptions.update(exceptions)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: +{len(new_domains)} حظر, +{len(new_exceptions)} استثناء")
            if i < total:
                time.sleep(REQUEST_DELAY)

    final_domains = all_domains - all_exceptions
    return sorted(final_domains), sorted(all_exceptions)

def split_and_save(domains, exceptions, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)

    # إنشاء القائمة الكاملة كسلسلة
    lines = []
    for d in domains:
        lines.append(f"||{d}^")
    for e in exceptions:
        lines.append(f"@@||{e}^")

    total_lines = len(lines)
    if total_lines == 0:
        print("⚠️ لا توجد قواعد للكتابة")
        return

    # تقدير حجم الملف لكل جزء
    # نحاول تقسيم بناءً على حجم الملف المقدر (بافتراض 30 بايت لكل سطر)
    avg_bytes_per_line = 30
    max_lines_per_part = int((MAX_PART_SIZE_MB * 1024 * 1024) / avg_bytes_per_line)

    if total_lines <= max_lines_per_part:
        # ملف واحد فقط
        main_file = os.path.join(output_dir, "adguard_app_filter.txt")
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write("! Title: AdGuard App Filter (Clean)\n")
            f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
            f.write(f"! Total rules: {total_lines}\n\n")
            f.write("\n".join(lines))
        size_mb = os.path.getsize(main_file) / (1024 * 1024)
        print(f"\n✅ تم حفظ {total_lines} قاعدة في ملف واحد (حجم {size_mb:.2f} ميجابايت)")
    else:
        # تقسيم إلى أجزاء
        num_parts = (total_lines + max_lines_per_part - 1) // max_lines_per_part
        print(f"\n📦 تقسيم {total_lines} قاعدة إلى {num_parts} جزء (حد أقصى {MAX_PART_SIZE_MB} ميجابايت لكل جزء)")

        for i in range(num_parts):
            start = i * max_lines_per_part
            end = min(start + max_lines_per_part, total_lines)
            part_lines = lines[start:end]
            part_file = os.path.join(output_dir, f"adguard_app_filter_part_{i+1}.txt")
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write("! Title: AdGuard App Filter (Part {})\n".format(i+1))
                f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
                f.write(f"! Total rules: {len(part_lines)}\n\n")
                f.write("\n".join(part_lines))
            size_mb = os.path.getsize(part_file) / (1024 * 1024)
            print(f"   ✅ الجزء {i+1}: {len(part_lines)} قاعدة (حجم {size_mb:.2f} ميجابايت)")

        # إنشاء ملف فهرس (اختياري)
        with open(os.path.join(output_dir, "parts_index.txt"), 'w', encoding='utf-8') as f:
            f.write("! قائمة الأجزاء (أضف كل رابط في تطبيق AdGuard)\n")
            base_url = "https://raw.githubusercontent.com/elqiser00/1002/main/merged_filters/"
            for i in range(num_parts):
                f.write(f"{base_url}adguard_app_filter_part_{i+1}.txt\n")

        print("\n🔗 روابط الأجزاء:")
        base_url = "https://raw.githubusercontent.com/elqiser00/1002/main/merged_filters/"
        for i in range(num_parts):
            print(f"   {base_url}adguard_app_filter_part_{i+1}.txt")

if __name__ == "__main__":
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        exit(1)

    if not urls:
        print("❌ لا توجد روابط")
        exit(1)

    start = time.time()
    domains, exceptions = process_filters(urls)
    split_and_save(domains, exceptions)
    print(f"\n⏱️ الوقت: {time.time() - start:.2f} ثانية")
