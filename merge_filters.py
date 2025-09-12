import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات التكوين
MAX_LINES_PER_PART = 2_000_000
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuardHome-Filter-Merger/13.0"

def load_filter_urls():
    """تحميل روابط الفلاتر من ملف list.txt"""
    try:
        with open("list.txt", "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file if line.strip() and not line.startswith("#")]
        return urls
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def is_valid_rule(line):
    """تحديد إذا كانت القاعدة من الأنواع المطلوبة فقط"""
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return False
    
    # تجاهل أي شيء يبدأ بـ ! أو # أو [ أو & أو $
    if re.match(r'^[!#\[&$]', line):
        return False
    
    # قبول فقط:
    # 1. قواعد AdGuard الأساسية (بما فيها التي تحتوي على -)
    # 2. قواعد DNS (127.0.0.1 أو 0.0.0.0)
    return (
        re.fullmatch(r'^(@@\|\|)?\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE) or
        re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE)
    )

def convert_rule(line):
    """تحويل القواعد مع تجاهل كل ما عدا الأساسيات"""
    line = line.strip()
    if not is_valid_rule(line):
        return None
    
    # تحويل قواعد DNS إلى صيغة AdGuard
    if re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        domain = line.split()[1]
        return f"||{domain}^"
    
    return line

def download_filter(url):
    """تحميل الفلتر مع التصفية الشاملة"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        valid_rules = []
        for line in response.text.splitlines():
            rule = convert_rule(line)
            if rule:
                valid_rules.append(rule)
                
        return valid_rules, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """المعالجة النهائية مع التنظيف الكامل"""
    seen_rules = set()
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر (سيتم تنظيف كل التعليقات والمعلومات غير الضرورية)...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        results = []
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = [r for r in rules if r not in seen_rules]
            seen_rules.update(new_rules)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: تمت إضافة {len(new_rules)} قاعدة نظيفة")
            results.extend(new_rules)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    # ترتيب النتائج: الاستثناءات أولاً
    return sorted(results, key=lambda x: (not x.startswith('@@'), x))

def save_filters(rules, output_dir="merged_filters"):
    """حفظ القواعد النظيفة"""
    os.makedirs(output_dir, exist_ok=True)
    
    main_file = os.path.join(output_dir, "adguard_rules.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة نظيفة فقط في {main_file}")
    
    # التقسيم التلقائي
    if len(rules) > MAX_LINES_PER_PART:
        parts = (len(rules) // MAX_LINES_PER_PART) + 1
        print(f"📦 تقسيم إلى {parts} أجزاء...")
        
        for i in range(parts):
            part_file = os.path.join(output_dir, f"adguard_rules_part_{i+1}.txt")
            with open(part_file, 'w', encoding='utf-8') as f:
                start = i * MAX_LINES_PER_PART
                end = start + MAX_LINES_PER_PART
                f.write("\n".join(rules[start:end]))
            
            print(f"✅ الجزء {i+1}: {len(rules[start:end])} قاعدة")

if __name__ == "__main__":
    # تحميل الروابط من ملف list.txt
    FILTER_URLS = load_filter_urls()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط فلاتر للمعالجة")
        exit(1)
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية التنظيف والدمج...")
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تمت إزالة جميع التعليقات والمعلومات غير الضرورية بنجاح!")
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
