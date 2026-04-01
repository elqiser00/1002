import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات التكوين
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-App-Filter-Merger/5.0"

def load_filter_urls():
    """تحميل روابط الفلاتر من ملف list.txt"""
    try:
        with open("list.txt", "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file if line.strip() and not line.startswith("#")]
        return urls
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def is_valid_domain(domain):
    """التحقق من صحة النطاق (لا يحتوي على رموز غير صالحة)"""
    if not domain:
        return False
    # إزالة الشرطات من البداية والنهاية
    domain = domain.strip('-')
    # التحقق من أن النطاق يحتوي على نقطة على الأقل
    if '.' not in domain:
        return False
    # منع النطاق الذي يبدأ أو ينتهي بنقطة
    if domain.startswith('.') or domain.endswith('.'):
        return False
    # منع الأحرف غير المسموحة
    if re.search(r'[^a-z0-9\.\-]', domain.lower()):
        return False
    return True

def extract_domain_from_rule(rule):
    """استخراج النطاق من أي صيغة قاعدة وتحويلها إلى صيغة موحدة"""
    rule = rule.strip()
    # تجاهل التعليقات
    if rule.startswith('!') or rule.startswith('#'):
        return None, None
    # التحقق إذا كانت القاعدة استثناء
    is_exception = rule.startswith('@@')
    clean_rule = rule[2:] if is_exception else rule

    # أنماط استخراج النطاق
    patterns = [
        (r'^\|\|([a-z0-9\-\.]+)\^$', r'\1'),           # ||example.com^
        (r'^\|\|([a-z0-9\-\.]+)$', r'\1'),             # ||example.com
        (r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9\-\.]+)$', r'\1'),  # hosts
        (r'^([a-z0-9\-\.]+\.[a-z]{2,})$', r'\1'),      # plain domain
        (r'^\*\.([a-z0-9\-\.]+\.[a-z]{2,})$', r'\1'),  # *.example.com
        (r'^/([a-z0-9\-\.]+\.[a-z]{2,})/$', r'\1'),    # /example.com/
        (r'^-([a-z0-9\-\.]+\.[a-z]{2,})$', r'\1'),     # -example.com
    ]
    for pattern, replacement in patterns:
        match = re.match(pattern, clean_rule, re.IGNORECASE)
        if match:
            domain = match.group(1).lower().strip('-')
            return domain, is_exception
    # محاولة استخراج أي نطاق من النص
    domain_match = re.search(r'([a-z0-9\-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)', clean_rule, re.IGNORECASE)
    if domain_match:
        domain = domain_match.group(1).lower().strip('-')
        if is_valid_domain(domain):
            return domain, is_exception
    return None, None

def download_and_extract_domains(url):
    """تحميل الفلتر واستخراج النطاقات فقط"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        domains = set()
        exceptions = set()
        for line in response.text.splitlines():
            domain, is_exception = extract_domain_from_rule(line)
            if domain and is_valid_domain(domain):
                if is_exception:
                    exceptions.add(domain)
                else:
                    domains.add(domain)
        domains -= exceptions  # إزالة المستثناة من الحظر
        return list(domains), list(exceptions), url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], [], url

def process_filters(urls):
    """معالجة جميع الفلاتر وتوحيد النطاقات"""
    all_domains = set()
    all_exceptions = set()
    total_urls = len(urls)
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...\n")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_and_extract_domains, url): url for url in urls}
        for i, future in enumerate(as_completed(future_to_url), 1):
            domains, exceptions, url = future.result()
            new_domains = [d for d in domains if d not in all_domains]
            new_exceptions = [e for e in exceptions if e not in all_exceptions]
            all_domains.update(domains)
            all_exceptions.update(exceptions)
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: +{len(new_domains)} حظر / +{len(new_exceptions)} استثناء")
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    final_domains = all_domains - all_exceptions
    print(f"\n📈 النتائج: {len(final_domains)} نطاق محظور، {len(all_exceptions)} استثناء")
    return sorted(final_domains), sorted(all_exceptions)

def save_single_filter(domains, exceptions, output_dir="merged_filters"):
    """حفظ الملف الوحيد (بدون تعليقات)"""
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        for domain in domains:
            f.write(f"{domain}\n")
        for exception in exceptions:
            f.write(f"@@{exception}\n")
    print(f"\n✅ تم حفظ {len(domains)} نطاق محظور و {len(exceptions)} استثناء في {main_file}")
    return main_file

if __name__ == "__main__":
    FILTER_URLS = load_filter_urls()
    if not FILTER_URLS:
        print("❌ لا توجد روابط فلاتر للمعالجة")
        exit(1)
    start_time = time.time()
    try:
        print("🚀 بدء دمج الفلاتر (ملف واحد فقط)...")
        print("=" * 50)
        domains, exceptions = process_filters(FILTER_URLS)
        save_single_filter(domains, exceptions)
        print("=" * 50)
        print(f"⏱️ الوقت: {time.time() - start_time:.2f} ثانية")
        print(f"📊 الإجمالي: {len(domains)} قاعدة (بدون تعليقات)")
        if domains:
            print("\n🔍 أمثلة:")
            for d in list(domains)[:5]:
                print(f"   {d}")
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
