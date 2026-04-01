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
USER_AGENT = "AdGuard-App-Filter-Merger/7.0"

def clean_rule(rule):
    """تنظيف القاعدة: إزالة التعليقات، الشرطات الزائدة، وإرجاع القاعدة النظيفة"""
    rule = rule.strip()
    if not rule or rule.startswith('!') or rule.startswith('#'):
        return None, None

    is_exception = rule.startswith('@@')
    clean = rule[2:] if is_exception else rule

    # محاولة استخراج نطاق (حتى لو بدأ برقم)
    # نبحث عن أي جزء يحتوي على نقطة ويمثل نطاقًا محتملاً
    domain_match = re.search(r'([a-z0-9\-]+\.[a-z0-9\-\.]+)', clean, re.IGNORECASE)
    if domain_match:
        domain = domain_match.group(1).lower()
        # إزالة الشرطات الزائدة من البداية والنهاية
        domain = domain.strip('-')
        # إذا كان النطاق صالحًا (يحتوي على نقطة)، نحتفظ به
        if '.' in domain:
            return domain, is_exception

    # إذا لم نجد نطاقًا، نعيد السطر الأصلي (ربما يكون قاعدة غير قياسية)
    return clean, is_exception

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        domains = []
        exceptions = []
        for line in response.text.splitlines():
            domain, is_exception = clean_rule(line)
            if domain:
                if is_exception:
                    exceptions.append(domain)
                else:
                    domains.append(domain)
        return list(set(domains)), list(set(exceptions)), url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return [], [], url

def process_filters(urls):
    all_domains = set()
    all_exceptions = set()
    total_urls = len(urls)
    print(f"🔍 معالجة {total_urls} مصدر...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(future_to_url), 1):
            domains, exceptions, url = future.result()
            new_domains = [d for d in domains if d not in all_domains]
            new_exceptions = [e for e in exceptions if e not in all_exceptions]
            all_domains.update(domains)
            all_exceptions.update(exceptions)
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: +{len(new_domains)} حظر, +{len(new_exceptions)} استثناء")
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    final_domains = all_domains - all_exceptions
    print(f"\n📈 النتائج: {len(final_domains)} نطاق فريد, {len(all_exceptions)} استثناء")
    return sorted(final_domains), sorted(all_exceptions)

def save_filters(domains, exceptions, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        # رأس بسيط
        f.write(f"! Title: AdGuard App Filter\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(domains) + len(exceptions)}\n\n")
        for d in domains:
            f.write(f"{d}\n")
        for e in exceptions:
            f.write(f"@@{e}\n")
    print(f"\n✅ حفظ {len(domains)} قاعدة حظر و {len(exceptions)} استثناء في {main_file}")

if __name__ == "__main__":
    # تحميل الروابط من list.txt
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        exit(1)

    if not urls:
        print("❌ لا توجد روابط في list.txt")
        exit(1)

    start = time.time()
    domains, exceptions = process_filters(urls)
    save_filters(domains, exceptions)
    print(f"⏱️ الوقت: {time.time() - start:.2f} ثانية")
