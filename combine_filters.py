import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== الإعدادات ==================
MAX_LINES_PER_PART = 500_000          # 500 ألف سطر لكل جزء (حجم أقل من 50 ميجابايت)
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/2.0"

# 🔧 اسم ملف المخرجات الأساسي (عدله كما تشاء)
OUTPUT_BASE_NAME = "final_filters.txt"

def load_filter_urls():
    """تحميل روابط الفلاتر من ملف list.txt"""
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return urls
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def convert_hosts_rule(line):
    """تحويل قاعدة hosts (0.0.0.0 domain) إلى ||domain^"""
    match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line.strip())
    if match:
        return f"||{match.group(2)}^"
    match_ex = re.match(r'^@@(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line.strip())
    if match_ex:
        return f"@@||{match_ex.group(2)}^"
    return None

def is_comment_or_empty(line):
    """تجاهل التعليقات والأسطر الفارغة"""
    stripped = line.strip()
    return not stripped or stripped.startswith(('#', '!'))

def clean_rule(line):
    """تنظيف السطر: إزالة التعليقات، تحويل hosts، وتصفية الطول"""
    line = line.strip()
    if is_comment_or_empty(line) or len(line) > MAX_LINE_LENGTH:
        return None
    converted = convert_hosts_rule(line)
    return converted if converted else line

def download_filter(url):
    """تحميل فلتر من رابط مع تنظيف أولي"""
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
    """معالجة جميع الفلاتر وإزالة التكرار الحرفي"""
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
    # ترتيب: الاستثناءات أولاً ثم الباقي
    all_rules.sort(key=lambda x: (not x.startswith('@@'), x))
    return all_rules

def save_filters(rules, out_dir="merged_filters"):
    """حفظ القواعد في أجزاء صغيرة (تجنب الملفات الضخمة)"""
    os.makedirs(out_dir, exist_ok=True)
    base_name = OUTPUT_BASE_NAME
    name, ext = os.path.splitext(base_name)
    
    total_rules = len(rules)
    print(f"\n💾 حفظ {total_rules} قاعدة فريدة...")
    
    # إذا كان العدد أقل من حد التقسيم، احفظ ملفاً واحداً
    if total_rules <= MAX_LINES_PER_PART:
        main_path = os.path.join(out_dir, base_name)
        with open(main_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(rules))
        size_mb = os.path.getsize(main_path) / (1024*1024)
        print(f"✅ تم حفظ {total_rules} قاعدة في ملف واحد: {main_path} ({size_mb:.2f} MB)")
    else:
        # تقسيم إلى أجزاء
        part_size = MAX_LINES_PER_PART
        total_parts = (total_rules + part_size - 1) // part_size
        print(f"📦 تقسيم إلى {total_parts} جزء (كل جزء حتى {part_size} سطر) ...")
        
        for i in range(total_parts):
            part_file = os.path.join(out_dir, f"{name}_part_{i+1}{ext}")
            start = i * part_size
            end = min(start + part_size, total_rules)
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(rules[start:end]))
            size_mb = os.path.getsize(part_file) / (1024*1024)
            print(f"   ✅ الجزء {i+1}: {len(rules[start:end])} قاعدة ({size_mb:.2f} MB)")
        
        print(f"\n⚠️ الملف الرئيسي لم يتم إنشاؤه لأنه كبير جداً. استخدم الأجزاء بدلاً من ذلك.")

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        print("❌ لا توجد روابط للمعالجة")
        exit(1)

    start = time.time()
    print("🚀 بدء دمج وتنظيف الفلاتر (سيتم تجنب الملفات الضخمة)...")
    try:
        final_rules = process_filters(urls)
        save_filters(final_rules)
        print(f"\n⏱️ الوقت المستغرق: {time.time() - start:.2f} ثانية")
        print(f"✨ الإحصائيات النهائية: {len(final_rules)} قاعدة فريدة")
    except Exception as e:
        print(f"❌ خطأ: {e}")
