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
USER_AGENT = "AdGuard-App-Filter-Merger/8.0"

# الأنماط المدعومة من تطبيق AdGuard (بدون تحويل)
VALID_PATTERNS = [
    # استثناءات AdGuard
    r'^@@\|\|[^\s]+\^$',
    # قواعد AdGuard العادية
    r'^\|\|[^\s]+\^$',
    # استثناءات hosts
    r'^@@(0\.0\.0\.0|127\.0\.0\.1)\s+[^\s]+$',
    # قواعد hosts
    r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[^\s]+$',
    # نطاقات عادية (مع أو بدون @@)
    r'^(@@)?[a-z0-9.-]+\.[a-z]{2,}$',
    # قواعد AdGuard بدون ^
    r'^(@@)?\|\|[a-z0-9.-]+\.[a-z]{2,}$',
    # صيغة /domain/ (نادرة)
    r'^/[a-z0-9.-]+\.[a-z]{2,}/$',
]

def is_valid_rule(line):
    """التحقق من أن القاعدة تطابق أحد الأنماط المدعومة"""
    line = line.strip()
    if not line:
        return False
    if line.startswith('!') or line.startswith('#'):
        return False
    for pattern in VALID_PATTERNS:
        if re.match(pattern, line, re.IGNORECASE):
            return True
    return False

def download_filter(url):
    """تحميل الفلتر والاحتفاظ بالقواعد الصالحة فقط"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        rules = []
        for line in response.text.splitlines():
            if is_valid_rule(line):
                rules.append(line.strip())
        return rules, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """دمج الفلاتر وإزالة المكرر"""
    seen = set()
    total_urls = len(urls)
    all_rules = []
    print(f"🔍 معالجة {total_urls} مصدر...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = []
            for r in rules:
                if r not in seen:
                    seen.add(r)
                    new_rules.append(r)
            all_rules.extend(new_rules)
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: {len(rules)} قاعدة → {len(new_rules)} جديدة")
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    return all_rules

def save_filters(rules, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Custom Filter\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(rules)}\n\n")
        f.write("\n".join(rules))
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في {main_file}")

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
    print(f"📊 الإجمالي: {len(rules)} قاعدة فريدة")
