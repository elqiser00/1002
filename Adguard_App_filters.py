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
USER_AGENT = "AdGuard-Merger/12.0"

def extract_domain(line):
    """استخراج النطاق وتحويله إلى ||domain^ أو @@||domain^ (صيغة DNS صالحة)"""
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None

    is_exception = line.startswith('@@')
    clean = line[2:] if is_exception else line

    # محاولة استخراج نطاق صالح (يتكون من حروف/أرقام/نقاط/شرطات، ويحتوي على نقطة)
    # نطاق عادي: example.com أو sub.example.com
    match = re.search(r'([a-z0-9][a-z0-9\-]*\.[a-z0-9][a-z0-9\-]*\.[a-z]{2,}|[a-z0-9][a-z0-9\-]*\.[a-z]{2,})', clean, re.IGNORECASE)
    if match:
        domain = match.group(1).lower()
        # إزالة الشرطات من البداية والنهاية
        domain = domain.strip('-')
        # التأكد من أن النطاق لا يحتوي على شرطات متتالية ولا يبدأ برقم
        if '--' in domain or re.match(r'^[0-9]', domain):
            return None
        if '.' in domain and len(domain) > 3:
            if is_exception:
                return f"@@||{domain}^"
            else:
                return f"||{domain}^"
    return None

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        rules = []
        for line in response.text.splitlines():
            rule = extract_domain(line)
            if rule:
                rules.append(rule)
        return rules, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    seen = set()
    total = len(urls)
    all_rules = []
    print(f"🔍 معالجة {total} مصدر (استخراج النطاقات الصالحة فقط)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = 0
            for r in rules:
                if r not in seen:
                    seen.add(r)
                    all_rules.append(r)
                    new_rules += 1
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: +{new_rules} قاعدة جديدة")
            if i < total:
                time.sleep(REQUEST_DELAY)
    return all_rules

def save_filters(rules, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Filter (DNS Compatible)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(rules)}\n\n")
        f.write("\n".join(rules))
    size_mb = os.path.getsize(main_file) / (1024 * 1024)
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في {main_file} (حجم {size_mb:.2f} ميجابايت)")

if __name__ == "__main__":
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
    rules = process_filters(urls)
    save_filters(rules)
    print(f"⏱️ الوقت: {time.time() - start:.2f} ثانية")
