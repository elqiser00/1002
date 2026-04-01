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
USER_AGENT = "AdGuard-App-Merger/9.0"

# الأنماط التي يقبلها تطبيق AdGuard للأندرويد (DNS filtering)
SAFE_PATTERNS = [
    r'^\|\|[^\s]+\^$',                     # ||example.com^
    r'^@@\|\|[^\s]+\^$',                   # @@||example.com^
    r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[^\s]+$',  # 0.0.0.0 example.com
    r'^@@(0\.0\.0\.0|127\.0\.0\.1)\s+[^\s]+$', # @@0.0.0.0 example.com
    r'^[a-z0-9.-]+\.[a-z]{2,}$',           # example.com
    r'^@@[a-z0-9.-]+\.[a-z]{2,}$',         # @@example.com
    r'^\|\|[a-z0-9.-]+\.[a-z]{2,}$',       # ||example.com (بدون ^)
]

def is_safe_rule(line):
    """تحديد إذا كانت القاعدة آمنة (يقبلها التطبيق)"""
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#'):
        return False
    for pattern in SAFE_PATTERNS:
        if re.match(pattern, line, re.IGNORECASE):
            return True
    return False

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        r.raise_for_status()
        safe = []
        unsafe = []
        for line in r.text.splitlines():
            if is_safe_rule(line):
                safe.append(line.strip())
            elif line.strip() and not line.startswith(('!', '#')):
                unsafe.append(line.strip())
        return safe, unsafe, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return [], [], url

def process_filters(urls):
    all_safe = set()
    all_unsafe = set()
    total = len(urls)
    print(f"🔍 معالجة {total} مصدر...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            safe, unsafe, url = future.result()
            new_safe = [s for s in safe if s not in all_safe]
            new_unsafe = [u for u in unsafe if u not in all_unsafe]
            all_safe.update(safe)
            all_unsafe.update(unsafe)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: +{len(new_safe)} آمنة, +{len(new_unsafe)} متقدمة")
            if i < total:
                time.sleep(REQUEST_DELAY)
    return sorted(all_safe), sorted(all_unsafe)

def save_filters(safe, unsafe, out_dir="merged_filters"):
    os.makedirs(out_dir, exist_ok=True)
    main_file = os.path.join(out_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Filter (Safe Rules)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total safe rules: {len(safe)}\n\n")
        f.write("\n".join(safe))
    print(f"\n✅ {len(safe)} قاعدة آمنة في {main_file}")
    if unsafe:
        adv_file = os.path.join(out_dir, "advanced_rules.txt")
        with open(adv_file, 'w', encoding='utf-8') as f:
            f.write("! Advanced rules not supported by DNS filtering\n")
            f.write("! You can add them manually via AdGuard's 'User rules' (DNS → User rules)\n\n")
            f.write("\n".join(unsafe))
        print(f"⚠️ {len(unsafe)} قاعدة متقدمة (غير مدعومة DNS) في {adv_file}")

if __name__ == "__main__":
    try:
        with open("list.txt", "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        exit(1)
    if not urls:
        print("❌ لا توجد روابط")
        exit(1)
    start = time.time()
    safe, unsafe = process_filters(urls)
    save_filters(safe, unsafe)
    print(f"⏱️ الوقت: {time.time()-start:.2f} ثانية")
