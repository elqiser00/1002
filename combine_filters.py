import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== الإعدادات ==================
MAX_LINES_PER_PART = 2_000_000
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/2.0"

# 🔧 اسم ملف المخرجات الأساسي (عدله كما تشاء)
OUTPUT_BASE_NAME = "final_filters.txt"

def load_filter_urls():
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return urls
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def convert_hosts_rule(line):
    match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line.strip())
    if match:
        return f"||{match.group(2)}^"
    match_ex = re.match(r'^@@(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line.strip())
    if match_ex:
        return f"@@||{match_ex.group(2)}^"
    return None

def is_comment_or_empty(line):
    stripped = line.strip()
    return not stripped or stripped.startswith(('#', '!'))

def clean_rule(line):
    line = line.strip()
    if is_comment_or_empty(line) or len(line) > MAX_LINE_LENGTH:
        return None
    converted = convert_hosts_rule(line)
    return converted if converted else line

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        resp.raise_for_status()
        rules = []
        for raw_line in resp.text.splitlines():
            rule = clean_rule(raw_line)
            if rule:
                rules.append(rule)
        return rules, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    seen = set()
    total = len(urls)
    print(f"🔍 بدء معالجة {total} مصدر فلتر ...")
    all_rules = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            rules, url = future.result()
            new_rules = [r for r in rules if r not in seen]
            seen.update(new_rules)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: {len(new_rules)} قاعدة جديدة (إجمالي فريد: {len(seen)})")
            all_rules.extend(new_rules)
            if i < total:
                time.sleep(REQUEST_DELAY)
    all_rules.sort(key=lambda x: (not x.startswith('@@'), x))
    return all_rules

def save_filters(rules, out_dir="merged_filters"):
    os.makedirs(out_dir, exist_ok=True)
    base_name = OUTPUT_BASE_NAME
    main_path = os.path.join(out_dir, base_name)
    with open(main_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(rules))
    print(f"\n✅ تم حفظ {len(rules)} قاعدة فريدة في {main_path}")

    if len(rules) > MAX_LINES_PER_PART:
        name, ext = os.path.splitext(base_name)
        parts = (len(rules) // MAX_LINES_PER_PART) + 1
        print(f"📦 تقسيم الملف إلى {parts} أجزاء ...")
        for i in range(parts):
            part_file = os.path.join(out_dir, f"{name}_part_{i+1}{ext}")
            start = i * MAX_LINES_PER_PART
            end = start + MAX_LINES_PER_PART
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(rules[start:end]))
            print(f"   ✅ الجزء {i+1}: {len(rules[start:end])} قاعدة")

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        print("❌ لا توجد روابط للمعالجة")
        exit(1)

    start = time.time()
    print("🚀 بدء دمج وتنظيف الفلاتر...")
    try:
        final_rules = process_filters(urls)
        save_filters(final_rules)
        print(f"\n⏱️ الوقت المستغرق: {time.time() - start:.2f} ثانية")
        print(f"✨ الإحصائيات النهائية: {len(final_rules)} قاعدة فريدة")
    except Exception as e:
        print(f"❌ خطأ: {e}")
