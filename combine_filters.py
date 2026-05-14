import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== الإعدادات ==================
MAX_FILE_SIZE_MB = 50                # أقصى حجم لكل ملف
MAX_LINE_LENGTH = 5000               # أقصى طول للسطر
REQUEST_TIMEOUT = 60                 # مهلة الطلب
REQUEST_DELAY = 0.5                  # تأخير بين المصادر
MAX_WORKERS = 10                     # عدد التنزيلات المتزامنة
USER_AGENT = "AdGuard-Merger/2.0"
MAX_RETRIES = 3                      # عدد محاولات إعادة التحميل
RETRY_BACKOFF = 2                    # انتظار متزايد بين المحاولات

OUTPUT_BASE_NAME = "final_filters"   # اسم الملف الأساسي
OUTPUT_DIR = "merged_filters"        # مجلد الإخراج

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

def clean_rule(line):
    """
    تنظيف القاعدة:
    - إزالة التعليقات والأسطر الفارغة.
    - تحويل hosts إلى ||domain^ (لتوحيد الشكل وتجنب التكرار).
    - الاحتفاظ بكل القواعد الأخرى كما هي (تجميل، شبكة، regex، إلخ).
    """
    line = line.strip()
    if not line or line.startswith(('#', '!')):
        return None
    if len(line) > MAX_LINE_LENGTH:
        return None

    # تحويل قواعد hosts إلى صيغة AdGuard (اختياري)
    converted = convert_hosts_rule(line)
    if converted:
        return converted

    # جميع القواعد الأخرى تُحتفظ بها كما هي (بما فيها العناصر، scriptlets، regex)
    return line

def download_filter(url):
    """تحميل فلتر مع إعادة محاولة تلقائية وحل مشاكل SSL"""
    headers = {'User-Agent': USER_AGENT}
    session = requests.Session()
    session.verify = False  # تجاهل مشاكل شهادات SSL
    # إعداد محول لإعادة المحاولة
    adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            rules = []
            for raw_line in resp.text.splitlines():
                rule = clean_rule(raw_line)
                if rule:
                    rules.append(rule)
            return rules, url
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException) as e:
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF ** attempt
                print(f"⚠️ محاولة {attempt+1}/{MAX_RETRIES+1} فشلت لـ {urlparse(url).netloc}: {str(e)}. انتظار {wait}s...")
                time.sleep(wait)
            else:
                print(f"❌ فشل تحميل {urlparse(url).netloc} بعد {MAX_RETRIES+1} محاولات: {str(e)}")
                return [], url
    return [], url

def process_filters(urls):
    """معالجة جميع الفلاتر وإزالة التكرار الحرفي"""
    seen = set()
    total = len(urls)
    print(f"🔍 بدء معالجة {total} مصدر فلتر (سيتم الاحتفاظ بجميع أنواع القواعد)...")
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

    # ترتيب: الاستثناءات (التي تبدأ بـ @@) أولاً، ثم الباقي (اختياري)
    all_rules.sort(key=lambda x: (not x.startswith('@@'), x))
    return all_rules

def save_filters_by_size(rules):
    """حفظ القواعد في ملفات متعددة لا يتجاوز كل منها MAX_FILE_SIZE_MB"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not rules:
        print("⚠️ لا توجد قواعد للحفظ.")
        return

    max_size_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
    current_part = 1
    current_size = 0
    current_rules = []

    for rule in rules:
        rule_size = len(rule.encode('utf-8')) + 1  # +1 لسطر جديد
        # إذا كانت القاعدة وحدها أكبر من الحد الأقصى (نادر)، نتخطاها مع تحذير
        if rule_size > max_size_bytes:
            print(f"⚠️ قاعدة طويلة جداً ({rule_size} بايت) سيتم تخطيها: {rule[:50]}...")
            continue

        # إذا تجاوزت الإضافة الحجم، نكتب الملف الحالي ونبدأ ملفاً جديداً
        if current_size + rule_size > max_size_bytes and current_rules:
            filename = f"{OUTPUT_BASE_NAME}_part{current_part}.txt"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(current_rules))
            actual_size_mb = os.path.getsize(filepath) / (1024*1024)
            print(f"✅ {filename}: {len(current_rules)} قاعدة, {actual_size_mb:.2f} MB")
            current_part += 1
            current_rules = []
            current_size = 0

        current_rules.append(rule)
        current_size += rule_size

    # كتابة آخر جزء
    if current_rules:
        filename = f"{OUTPUT_BASE_NAME}_part{current_part}.txt"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(current_rules))
        actual_size_mb = os.path.getsize(filepath) / (1024*1024)
        print(f"✅ {filename}: {len(current_rules)} قاعدة, {actual_size_mb:.2f} MB")

    print(f"\n📦 تم إنشاء {current_part} ملف (كل ملف ≤ {MAX_FILE_SIZE_MB} MB)")

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        print("❌ لا توجد روابط للمعالجة")
        exit(1)

    start_time = time.time()
    print(f"🚀 بدء دمج الفلاتر... الحد الأقصى لكل ملف: {MAX_FILE_SIZE_MB} MB")
    print("📝 سيتم الاحتفاظ بجميع أنواع القواعد:")
    print("   - قواعد الشبكة (||example.org^)")
    print("   - قواعد الاستثناء (@@||example.org^)")
    print("   - قواعد التجميل (example.org##.adbox)")
    print("   - قواعد Scriptlet (example.org#%#//scriptlet)")
    print("   - قواعد Regex (/ad.*\\.js/$domain=...)")
    print("   - تحويل hosts إلى ||domain^ لتجنب التكرار")
    print("🔐 تجاهل أخطاء SSL وإعادة المحاولة تلقائياً\n")

    try:
        final_rules = process_filters(urls)
        save_filters_by_size(final_rules)
        print(f"\n⏱️ الوقت المستغرق: {time.time() - start_time:.2f} ثانية")
        print(f"✨ إجمالي القواعد الفريدة: {len(final_rules)}")
        print("\n🔗 روابط الملفات الناتجة (أضفها في AdGuard):")
        total_parts = (len(final_rules) // (MAX_FILE_SIZE_MB * 1024 * 1024 // 50) + 1)  # تقدير تقريبي
        # طباعة الروابط بشكل صحيح حسب الأجزاء الموجودة
        import glob
        files = sorted(glob.glob(os.path.join(OUTPUT_DIR, f"{OUTPUT_BASE_NAME}_part*.txt")))
        for i, f in enumerate(files, 1):
            print(f"   part{i}: https://raw.githubusercontent.com/elqiser00/1002/main/{OUTPUT_DIR}/{os.path.basename(f)}")
    except Exception as e:
        print(f"❌ خطأ غير متوقع: {e}")
