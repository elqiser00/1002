import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== الإعدادات ==================
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/2.0"

# 🔧 اسم ملف المخرجات الوحيد
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

def save_single_file(rules, out_dir="merged_filters"):
    """حفظ كل القواعد في ملف واحد فقط (بدون تقسيم)"""
    os.makedirs(out_dir, exist_ok=True)
    output_path = os.path.join(out_dir, OUTPUT_BASE_NAME)
    
    print(f"\n💾 حفظ {len(rules)} قاعدة في ملف واحد: {output_path}")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(rules))
    
    # الحصول على حجم الملف بالميجابايت
    size_bytes = os.path.getsize(output_path)
    size_mb = size_bytes / (1024 * 1024)
    
    print(f"✅ تم الحفظ بنجاح. حجم الملف: {size_mb:.2f} MB")
    
    # تحذير إذا تجاوز 95 ميجابايت (قريب من حد GitHub 100 ميجابايت)
    if size_mb > 95:
        print(f"\n⚠️ تحذير: حجم الملف ({size_mb:.2f} MB) يقترب من الحد الأقصى لـ GitHub (100 MB).")
        print("⚠️ قد يفشل رفع الملف إلى المستودع. يُنصح بتقليل عدد الفلاتر أو استخدام تقسيم إلى أجزاء.")
    elif size_mb > 100:
        print(f"\n❌ خطأ: حجم الملف ({size_mb:.2f} MB) يتجاوز الحد الأقصى لـ GitHub (100 MB).")
        print("❌ لن يتم قبول الدفع. يجب تقليل عدد القواعد أو استخدام التقسيم.")
    else:
        print(f"✅ حجم الملف مناسب (أقل من 100 MB). يمكن رفعه إلى GitHub.")

if __name__ == "__main__":
    urls = load_filter_urls()
    if not urls:
        print("❌ لا توجد روابط للمعالجة")
        exit(1)

    start = time.time()
    print("🚀 بدء دمج وتنظيف الفلاتر (ملف واحد نهائي)...")
    print("⚠️ تذكر: إذا تجاوز الحجم 100 MB، سيفشل رفع الملف إلى GitHub.")
    try:
        final_rules = process_filters(urls)
        save_single_file(final_rules)
        print(f"\n⏱️ الوقت المستغرق: {time.time() - start:.2f} ثانية")
        print(f"✨ الإحصائيات النهائية: {len(final_rules)} قاعدة فريدة (في ملف واحد)")
    except Exception as e:
        print(f"❌ خطأ: {e}")
