import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# الإعدادات
MAX_SIMPLE_FILE_MB = 15   # الملف الأساسي بحد أقصى 15 ميجا (آمن للأندرويد)
MAX_ADVANCED_FILE_MB = 50 # المتقدم 60 ميجا (لـ AdGuard Home)
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/2.0"
MAX_RETRIES = 3

OUTPUT_DIR = "merged_filters"

def load_filter_urls():
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def is_simple_rule(rule):
    """القواعد البسيطة التي يدعمها AdGuard للأندرويد بثبات"""
    rule = rule.strip()
    # قواعد الشبكة الأساسية ||domain^ أو @@||domain^
    if re.match(r'^(@@)?\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', rule, re.IGNORECASE):
        return True
    # استثناءات بسيطة (بدون خيارات)
    if re.match(r'^@@\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', rule, re.IGNORECASE):
        return True
    return False

def clean_rule(line):
    line = line.strip()
    if not line or line.startswith(('#', '!')):
        return None
    if len(line) > MAX_LINE_LENGTH:
        return None
    # تحويل hosts
    match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if match:
        return f"||{match.group(2)}^"
    match_ex = re.match(r'^@@(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if match_ex:
        return f"@@||{match_ex.group(2)}^"
    return line

def download_filter(url):
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': USER_AGENT}, verify=False)
            resp.raise_for_status()
            rules = []
            for raw in resp.text.splitlines():
                clean = clean_rule(raw)
                if clean:
                    rules.append(clean)
            return rules, url
        except Exception as e:
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
            else:
                print(f"❌ فشل {urlparse(url).netloc}: {e}")
                return [], url
    return [], url

def process_filters(urls):
    seen = set()
    total = len(urls)
    print(f"🔍 معالجة {total} مصدر...")
    all_rules = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(download_filter, url): url for url in urls}
        for i, f in enumerate(as_completed(futures), 1):
            rules, url = f.result()
            new = [r for r in rules if r not in seen]
            seen.update(new)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: {len(new)} جديدة (إجمالي {len(seen)})")
            all_rules.extend(new)
            if i < total:
                time.sleep(REQUEST_DELAY)
    all_rules.sort(key=lambda x: (not x.startswith('@@'), x))
    return all_rules

def save_by_size(rules, base_name, max_mb):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not rules:
        return []
    max_bytes = max_mb * 1024 * 1024
    parts = []
    current_size = 0
    current = []
    part_num = 1
    for rule in rules:
        sz = len(rule.encode('utf-8')) + 1
        if current_size + sz > max_bytes and current:
            fname = f"{base_name}_part{part_num}.txt"
            fpath = os.path.join(OUTPUT_DIR, fname)
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write("\n".join(current))
            parts.append(fpath)
            print(f"✅ {fname}: {len(current)} قاعدة, {os.path.getsize(fpath)/(1024*1024):.2f} MB")
            part_num += 1
            current = []
            current_size = 0
        current.append(rule)
        current_size += sz
    if current:
        fname = f"{base_name}_part{part_num}.txt"
        fpath = os.path.join(OUTPUT_DIR, fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write("\n".join(current))
        parts.append(fpath)
        print(f"✅ {fname}: {len(current)} قاعدة, {os.path.getsize(fpath)/(1024*1024):.2f} MB")
    return parts

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        exit(1)
    start = time.time()
    try:
        all_rules = process_filters(urls)
        simple = [r for r in all_rules if is_simple_rule(r)]
        advanced = [r for r in all_rules if not is_simple_rule(r)]
        print(f"\n📊 التصنيف: {len(simple)} قاعدة بسيطة, {len(advanced)} قاعدة متقدمة")
        if simple:
            save_by_size(simple, "adguard_simple", MAX_SIMPLE_FILE_MB)
        if advanced:
            save_by_size(advanced, "adguard_advanced", MAX_ADVANCED_FILE_MB)
        print(f"\n⏱️ {time.time()-start:.2f} ثانية")
    except Exception as e:
        print(f"❌ {e}")
