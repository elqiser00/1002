import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات التكوين
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-App-Filter-Merger/2.0"

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
    """تحديد إذا كانت القاعدة من الأنواع المطلوبة لتطبيق AdGuard"""
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return False
    
    # تجاهل التعليقات والرؤوس
    if re.match(r'^[!#\[\]\(\)]', line):
        return False
    
    # تجاهل قواعد الـ regex المعقدة (قد تسبب مشاكل في التطبيق)
    if re.match(r'^/.*/\w*$', line):
        return False
    
    # تجاهل القواعد التي تحتوي على عناصر CSS أو HTML (غير مدعومة في DNS)
    if any(x in line for x in ['$domain=', '$important', '$popup', '$document', '$stylesheet']):
        return False
    
    # قبول الأنواع التالية (متوافقة مع تطبيق AdGuard):
    return (
        # صيغة AdGuard الأساسية
        re.fullmatch(r'^(@@\|\|)?\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE) or
        # صيغة domain.com البسيطة
        re.fullmatch(r'^(@@)?([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE) or
        # صيغة hosts
        re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE) or
        # استثناءات hosts
        re.fullmatch(r'^@@(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE) or
        # صيغة ||domain.com (بدون ^)
        re.fullmatch(r'^(@@)?\|\|([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE)
    )

def convert_rule(line):
    """تحويل القواعد إلى صيغة متوافقة مع تطبيق AdGuard"""
    line = line.strip()
    if not is_valid_rule(line):
        return None
    
    # تحويل قواعد hosts العادية
    if re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        domain = line.split()[1]
        return domain
    
    # تحويل قواعد hosts مع استثناءات
    if re.fullmatch(r'^@@(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        domain = line.split()[1]
        return f"@@{domain}"
    
    # تحويل ||domain.com (بدون ^) إلى صيغة مناسبة
    if re.fullmatch(r'^(@@)?\|\|([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        if line.startswith('@@'):
            domain = line[2:]
            return f"@@{domain}"
        else:
            return line
    
    # تحويل domain.com البسيطة
    if re.fullmatch(r'^(@@)?([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        return line
    
    # إذا كانت القاعدة بصيغة AdGuard كاملة (||domain^) نحولها للصيغة البسيطة
    if re.fullmatch(r'^(@@\|\|)?\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE):
        if line.startswith('@@'):
            domain = line[2:].strip('^')
            return f"@@{domain}"
        else:
            domain = line.strip('^')
            return domain
    
    return line

def download_filter(url):
    """تحميل الفلتر مع التصفية لتطبيق AdGuard"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        valid_rules = []
        for line in response.text.splitlines():
            rule = convert_rule(line)
            if rule:
                rule = rule.strip()
                if rule.startswith('@@'):
                    rule = rule.strip('@@')
                    rule = f"@@{rule}"
                valid_rules.append(rule)
                
        return valid_rules, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """المعالجة النهائية مع التنظيف وإزالة التكرار"""
    seen_rules = set()
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر (تحسين لتطبيق AdGuard)...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        results = []
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = []
            for r in rules:
                if r not in seen_rules:
                    seen_rules.add(r)
                    new_rules.append(r)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: تمت إضافة {len(new_rules)} قاعدة")
            results.extend(new_rules)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    # ترتيب النتائج: الاستثناءات أولاً
    return sorted(results, key=lambda x: (not x.startswith('@@'), x))

def save_filters(rules, output_dir="merged_filters"):
    """حفظ القواعد في ملف واحد فقط (بدون تقسيم)"""
    os.makedirs(output_dir, exist_ok=True)
    
    # إضافة رأس الملف لتطبيق AdGuard
    header = f"""! Title: AdGuard App Custom Filter
! Description: Merged filter for AdGuard App (Android)
! Expires: 6 hours
! Version: {time.strftime("%Y.%m.%d")}
! Homepage: https://github.com/elqiser00/1002
! Total Rules: {len(rules)}
!
"""
    
    # ملف واحد فقط - الفلتر الرئيسي
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في ملف واحد: {main_file}")
    
    # إنشاء ملف بصيغة hosts إضافية (اختياري)
    hosts_file = os.path.join(output_dir, "hosts_format.txt")
    with open(hosts_file, 'w', encoding='utf-8') as f:
        f.write("# Hosts format for AdGuard App\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total Rules: {len(rules)}\n\n")
        for rule in rules:
            if not rule.startswith('@@'):
                f.write(f"0.0.0.0 {rule}\n")
    
    print(f"✅ تم إنشاء نسخة بصيغة hosts في {hosts_file}")

def create_metadata():
    """إنشاء ملف metadata.json لتطبيق AdGuard"""
    import json
    
    metadata = {
        "name": "AdGuard App Custom Filter",
        "description": "Merged filter from multiple sources optimized for AdGuard App on Android",
        "homepage": "https://github.com/elqiser00/1002",
        "version": time.strftime("%Y.%m.%d"),
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rules_count": 0
    }
    
    # قراءة العدد الفعلي من الملف الرئيسي
    try:
        with open("merged_filters/adguard_app_filter.txt", "r", encoding="utf-8") as f:
            lines = [l for l in f.readlines() if not l.startswith('!') and l.strip()]
            metadata["rules_count"] = len(lines)
    except:
        pass
    
    with open("merged_filters/metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    
    print(f"✅ تم إنشاء ملف metadata.json")

if __name__ == "__main__":
    # تحميل الروابط من ملف list.txt
    FILTER_URLS = load_filter_urls()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط فلاتر للمعالجة")
        exit(1)
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية تحويل الفلاتر لتطبيق AdGuard...")
        print("📝 الصيغ المدعومة في تطبيق AdGuard:")
        print("   - domain.com (صيغة بسيطة)")
        print("   - @@domain.com (استثناء)")
        print("   - ||domain^ (صيغة AdGuard الكلاسيكية)")
        print("   - 0.0.0.0 domain.com (صيغة hosts)")
        print("🗑️  سيتم حذف: التعقيدات غير المدعومة في التطبيق")
        
        rules = process_filters(FILTER_URLS)
        save_filters(rules)  # بدون تقسيم
        create_metadata()
        
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تم تحويل الفلاتر بنجاح لتطبيق AdGuard!")
        print(f"📊 الإحصائيات النهائية: {len(rules)} قاعدة في ملف واحد")
        
        # عرض بعض الأمثلة
        if rules:
            print("\n🔍 أمثلة على القواعد المحفوظة (متوافقة مع تطبيق AdGuard):")
            for i, rule in enumerate(rules[:5]):
                print(f"   {i+1}. {rule}")
            if len(rules) > 5:
                print(f"   ... و{len(rules) - 5} قاعدة أخرى")
                
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
