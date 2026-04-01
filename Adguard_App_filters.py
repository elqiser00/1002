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
USER_AGENT = "AdGuard-Cleaner/1.0"

def extract_domain_only(line):
    """
    استخراج النطاق من أي قاعدة وتجاهل أي شيء آخر
    الإخراج: (domain, is_exception) أو (None, None)
    """
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None, None

    # تحديد إذا كانت استثناء
    is_exception = line.startswith('@@')
    # إزالة @@ إن وجدت
    content = line[2:] if is_exception else line

    # إزالة أي شيء بعد $ (الشروط)
    content = content.split('$')[0]
    # إزالة أي شيء بعد / (إذا كان هناك regex)
    content = content.split('/')[0]

    # البحث عن نطاق صالح (يتكون من حروف/أرقام/نقاط/شرطات ويحتوي على نقطة)
    # نمط النطاق: يبدأ بحرف أو رقم (لكن ليس شرطة) ويحتوي على نقطة
    # نستخدم نمطاً صارماً: يبدأ بحرف أو رقم، ثم أي عدد من الأحرف/الأرقام/الشرطات/النقاط، وينتهي بـ TLD حروف
    match = re.search(r'([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})', content, re.IGNORECASE)
    if not match:
        return None, None

    domain = match.group(1).lower()
    # تنظيف: إزالة الشرطات الزائدة من البداية والنهاية
    domain = domain.strip('-')
    # منع الشرطات المتتالية
    if '--' in domain:
        return None, None
    # منع النطاق الذي يبدأ برقم يليه شرطة مباشرة
    if re.match(r'^[0-9]+-', domain):
        return None, None
    # منع النطاق القصير جداً
    if len(domain) < 4:
        return None, None
    # منع النطاق الذي لا يحتوي على نقطة
    if '.' not in domain:
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
    print(f"🔍 معالجة {total} مصدر (استخراج النطاقات فقط)...")
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

    # إزالة المستثناة من قائمة الحظر
    final_domains = all_domains - all_exceptions
    return sorted(final_domains), sorted(all_exceptions)

def save_filters(domains, exceptions, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Filter (Clean Domains Only)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total blocked domains: {len(domains)}\n")
        f.write(f"! Total exceptions: {len(exceptions)}\n\n")
        for d in domains:
            f.write(f"||{d}^\n")
        for e in exceptions:
            f.write(f"@@||{e}^\n")
    size_mb = os.path.getsize(main_file) / (1024 * 1024)
    print(f"\n✅ تم حفظ {len(domains)} قاعدة حظر و {len(exceptions)} استثناء في {main_file}")
    print(f"📦 حجم الملف: {size_mb:.2f} ميجابايت")

    # عرض عينة
    print("\n🔍 عينة من القواعد النهائية (يجب أن تكون فقط بصيغة ||domain^ أو @@||domain^):")
    sample = []
    for d in list(domains)[:5]:
        sample.append(f"||{d}^")
    for e in list(exceptions)[:3]:
        sample.append(f"@@||{e}^")
    for s in sample:
        print(f"   {s}")

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
    save_filters(domains, exceptions)
    print(f"\n⏱️ الوقت: {time.time() - start:.2f} ثانية")
