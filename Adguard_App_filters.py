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
USER_AGENT = "AdGuard-Merger/15.0"

# الحد الأقصى لحجم الملف الواحد بالميجابايت (إذا تجاوز، نقسم)
MAX_SINGLE_FILE_MB = 90

def clean_domain(domain):
    """تنظيف النطاق من الشرطات الزائدة والتحقق من الصلاحية"""
    domain = domain.strip().lower()
    domain = domain.strip('-')
    if not domain or len(domain) < 4:
        return None
    if '--' in domain:
        return None
    if domain.startswith('.') or domain.endswith('.'):
        return None
    if re.match(r'^[0-9]+-', domain):
        return None
    if re.search(r'[^a-z0-9\.\-]', domain):
        return None
    if '.' not in domain:
        return None
    return domain

def extract_rule(line):
    """
    استخراج القاعدة بالصيغة المطلوبة:
    - حظر: ||domain^$important
    - استثناء: @@||domain^$important
    """
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None

    is_exception = line.startswith('@@')
    content = line[2:] if is_exception else line

    # إزالة الشروط المتقدمة التي تسبب مشاكل (نحتفظ فقط بالنطاق)
    # لكننا سنضيف $important لاحقًا
    content = content.split('$')[0]
    content = content.split('/')[0]
    content = content.replace('*', '')

    # استخراج النطاق: يجب أن يبدأ بحرف (a-z) ويحتوي على نقطة
    match = re.search(r'([a-z][a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]{2,}|[a-z][a-z0-9\-]*\.[a-z]{2,})', content, re.IGNORECASE)
    if not match:
        return None

    domain = match.group(1).lower()
    domain = clean_domain(domain)
    if not domain:
        return None

    # بناء القاعدة بالصيغة المطلوبة
    if is_exception:
        return f"@@||{domain}^$important"
    else:
        return f"||{domain}^$important"

def download_source(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        r.raise_for_status()
        rules = set()
        for line in r.text.splitlines():
            rule = extract_rule(line)
            if rule:
                rules.add(rule)
        return rules, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return set(), url

def merge_sources(urls):
    all_rules = set()
    total = len(urls)
    print(f"🔍 معالجة {total} مصدر (استخراج القواعد بالصيغة المطلوبة)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_source, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            rules, url = future.result()
            new_rules = rules - all_rules
            all_rules.update(rules)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: +{len(new_rules)} قاعدة")
            if i < total:
                time.sleep(REQUEST_DELAY)
    return sorted(all_rules)

def save_split(block_rules, allow_rules, out_dir="merged_filters"):
    """
    حفظ القواعد في ملفين:
    - blocklist.txt : قواعد الحظر (تبدأ بـ ||)
    - allowlist.txt : قواعد الاستثناء (تبدأ بـ @@)
    """
    os.makedirs(out_dir, exist_ok=True)
    block_path = os.path.join(out_dir, "blocklist.txt")
    allow_path = os.path.join(out_dir, "allowlist.txt")

    with open(block_path, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard Blocklist (with $important)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(block_rules)}\n\n")
        f.write("\n".join(block_rules))

    with open(allow_path, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard Allowlist (with $important)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(allow_rules)}\n\n")
        f.write("\n".join(allow_rules))

    block_size = os.path.getsize(block_path) / (1024 * 1024)
    allow_size = os.path.getsize(allow_path) / (1024 * 1024)
    print(f"\n✅ تم حفظ {len(block_rules)} قاعدة حظر في {block_path} (حجم {block_size:.2f} ميجابايت)")
    print(f"✅ تم حفظ {len(allow_rules)} قاعدة استثناء في {allow_path} (حجم {allow_size:.2f} ميجابايت)")
    return block_path, allow_path

def save_single_file(block_rules, allow_rules, out_dir="merged_filters"):
    """
    حفظ جميع القواعد في ملف واحد (حظر + استثناء)
    """
    os.makedirs(out_dir, exist_ok=True)
    file_path = os.path.join(out_dir, "adguard_app_filter.txt")
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Filter (with $important)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(block_rules) + len(allow_rules)}\n\n")
        f.write("\n".join(block_rules))
        if allow_rules:
            f.write("\n! Exceptions\n")
            f.write("\n".join(allow_rules))
    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"\n✅ تم حفظ {len(block_rules)} قاعدة حظر و {len(allow_rules)} استثناء في {file_path} (حجم {size_mb:.2f} ميجابايت)")
    return file_path

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
    all_rules = merge_sources(urls)

    # فصل قواعد الحظر عن الاستثناء
    block = [r for r in all_rules if not r.startswith('@@')]
    allow = [r for r in all_rules if r.startswith('@@')]

    # تقدير حجم الملف الواحد (محاكاة)
    estimated_size = (len(block) + len(allow)) * 40 / (1024 * 1024)  # 40 بايت لكل سطر تقريباً
    if estimated_size > MAX_SINGLE_FILE_MB:
        print(f"\n⚠️  الحجم المقدر {estimated_size:.1f} ميجابايت يتجاوز الحد {MAX_SINGLE_FILE_MB} ميجابايت.")
        print("📦 سيتم التقسيم إلى blocklist.txt و allowlist.txt")
        save_split(block, allow)
    else:
        save_single_file(block, allow)

    print(f"\n⏱️ الوقت الإجمالي: {time.time() - start:.2f} ثانية")
