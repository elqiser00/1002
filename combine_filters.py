import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# الإعدادات
MAX_SIMPLE_FILE_MB = 60           # أقصى حجم لكل ملف بسيط (10 ميجابايت آمن)
MAX_RULES_PER_FILE = 1_000_000      # أقصى عدد قواعد لكل ملف
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/2.0"
MAX_RETRIES = 3

OUTPUT_DIR = "merged_filters"
SIMPLE_HEADER = "[Adblock Plus 2.0]\n"

def load_filter_urls():
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def is_simple_rule(rule):
    """قواعد بسيطة: ||domain^ أو @@||domain^ فقط"""
    rule = rule.strip()
    # تطابق تام مع ||domain^ أو @@||domain^
    if re.match(r'^(@@)?\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', rule, re.IGNORECASE):
        return True
    # تحويل 0.0.0.0 domain -> ||domain^ يتم في clean_rule، لكن سيتم اعتباره بسيطاً بعد التحويل
    return False

def clean_rule(line):
    line = line.strip()
    if not line or line.startswith(('#', '!')):
        return None
    if len(line) > MAX_LINE_LENGTH:
        return None
    # تحويل hosts إلى ||domain^
    match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if match:
        return f"||{match.group(2)}^"
    match_ex = re.match(r'^@@(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if match_ex:
        return f"@@||{match_ex.group(2)}^"
    # أي قاعدة أخرى تترك كما هي (لكنها لن تمر is_simple_rule لاحقاً)
    return line

def download_filter(url):
    for attempt in range(MAX_RETRIES + 1):
        try:
            headers = {'User-Agent': USER_AGENT}
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
            resp.raise_for_status()
            rules = []
            for raw in resp.text.splitlines():
                cleaned = clean_rule(raw)
                if cleaned:
                    rules.append(cleaned)
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
            new_rules = [r for r in rules if r not in seen]
            seen.update(new_rules)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: {len(new_rules)} جديدة (إجمالي {len(seen)})")
            all_rules.extend(new_rules)
            if i < total:
                time.sleep(REQUEST_DELAY)
    # ترتيب: الاستثناءات أولاً
    all_rules.sort(key=lambda x: (not x.startswith('@@'), x))
    return all_rules

def save_simple_files(rules):
    """حفظ القواعد البسيطة في ملفات مع HEADER، مع مراعاة الحدود"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not rules:
        print("⚠️ لا توجد قواعد بسيطة للحفظ.")
        return []

    max_bytes = MAX_SIMPLE_FILE_MB * 1024 * 1024
    parts = []
    current_rules = []
    current_size = len(SIMPLE_HEADER.encode('utf-8'))  # حساب حجم الهيدر
    part_num = 1

    for rule in rules:
        rule_size = len(rule.encode('utf-8')) + 1  # +1 newline
        # التحقق من عدد القواعد قبل إضافة القاعدة
        if (current_size + rule_size > max_bytes or len(current_rules) >= MAX_RULES_PER_FILE) and current_rules:
            # حفظ الجزء الحالي
            filename = f"adguard_simple_part{part_num}.txt"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(SIMPLE_HEADER)
                f.write("\n".join(current_rules))
            actual_size_mb = os.path.getsize(filepath) / (1024*1024)
            print(f"✅ {filename}: {len(current_rules)} قاعدة, {actual_size_mb:.2f} MB")
            parts.append(filepath)
            part_num += 1
            current_rules = []
            current_size = len(SIMPLE_HEADER.encode('utf-8'))
        
        current_rules.append(rule)
        current_size += rule_size

    # آخر جزء
    if current_rules:
        filename = f"adguard_simple_part{part_num}.txt"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(SIMPLE_HEADER)
            f.write("\n".join(current_rules))
        actual_size_mb = os.path.getsize(filepath) / (1024*1024)
        print(f"✅ {filename}: {len(current_rules)} قاعدة, {actual_size_mb:.2f} MB")
        parts.append(filepath)
    
    return parts

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        exit(1)
    start = time.time()
    try:
        all_cleaned = process_filters(urls)
        simple_rules = [r for r in all_cleaned if is_simple_rule(r)]
        print(f"\n📊 إجمالي القواعد الفريدة: {len(all_cleaned)}")
        print(f"📊 القواعد البسيطة (||domain^): {len(simple_rules)}")
        
        if simple_rules:
            save_simple_files(simple_rules)
        else:
            print("⚠️ لا توجد قواعد بسيطة للحفظ.")
    except Exception as e:
        print(f"❌ خطأ: {e}")
    finally:
        print(f"\n⏱️ الوقت: {time.time()-start:.2f} ثانية")
