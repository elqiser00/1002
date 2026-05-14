import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== الإعدادات ==================
MAX_FILE_SIZE_MB = 95               # أقصى حجم لكل ملف بالميجابايت (آمن لـ GitHub)
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/2.0"

# اسم الملف الأساسي (سيتم إضافة _part1, _part2, ...)
OUTPUT_BASE_NAME = "final_filters"
OUTPUT_DIR = "merged_filters"

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
    # ترتيب: الاستثناءات أولاً
    all_rules.sort(key=lambda x: (not x.startswith('@@'), x))
    return all_rules

def save_filters_by_size(rules):
    """حفظ القواعد في ملفات متعددة كل منها لا يتجاوز MAX_FILE_SIZE_MB ميجابايت"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not rules:
        print("⚠️ لا توجد قواعد للحفظ.")
        return

    max_size_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
    current_part = 1
    current_size = 0
    current_rules = []
    
    # تقدير حجم كل قاعدة: طول السطر + 1 (لـ newline)
    for rule in rules:
        rule_size = len(rule.encode('utf-8')) + 1  # +1 for newline
        # إذا كانت القاعدة وحدها أكبر من الحد الأقصى (نادراً) يتم تخطيها أو تحذير
        if rule_size > max_size_bytes:
            print(f"⚠️ قاعدة طويلة جداً ({rule_size} بايت) سيتم تخطيها: {rule[:50]}...")
            continue
            
        # إذا إضافة هذه القاعدة ستتجاوز الحجم، نكتب الملف الحالي ونبدأ جديداً
        if current_size + rule_size > max_size_bytes and current_rules:
            # كتابة الملف الحالي
            filename = f"{OUTPUT_BASE_NAME}_part{current_part}.txt"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(current_rules))
            actual_size_mb = os.path.getsize(filepath) / (1024*1024)
            print(f"✅ {filename}: {len(current_rules)} قاعدة, {actual_size_mb:.2f} MB")
            # بدء جزء جديد
            current_part += 1
            current_rules = []
            current_size = 0
        
        # إضافة القاعدة إلى الجزء الحالي
        current_rules.append(rule)
        current_size += rule_size
    
    # كتابة آخر جزء إذا كان فيه قواعد
    if current_rules:
        filename = f"{OUTPUT_BASE_NAME}_part{current_part}.txt"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(current_rules))
        actual_size_mb = os.path.getsize(filepath) / (1024*1024)
        print(f"✅ {filename}: {len(current_rules)} قاعدة, {actual_size_mb:.2f} MB")
    
    # إجمالي الإحصاءات
    total_files = current_part
    print(f"\n📦 تم إنشاء {total_files} ملف (كل ملف ≤ {MAX_FILE_SIZE_MB} MB)")

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        print("❌ لا توجد روابط للمعالجة")
        exit(1)

    start = time.time()
    print(f"🚀 بدء الدمج... الحد الأقصى لكل ملف: {MAX_FILE_SIZE_MB} MB")
    try:
        final_rules = process_filters(urls)
        save_filters_by_size(final_rules)
        print(f"\n⏱️ الوقت المستغرق: {time.time() - start:.2f} ثانية")
        print(f"✨ إجمالي القواعد الفريدة: {len(final_rules)}")
    except Exception as e:
        print(f"❌ خطأ: {e}")
