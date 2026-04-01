import requests
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات التكوين
MAX_LINE_LENGTH = 10000  # زيادة الحد الأقصى لطول السطر
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-App-Filter-Merger/3.0"

def load_filter_urls():
    """تحميل روابط الفلاتر من ملف list.txt"""
    try:
        with open("list.txt", "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file if line.strip() and not line.startswith("#")]
        return urls
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def clean_line(line):
    """تنظيف السطر فقط من المسافات والتأكد من أنه ليس فارغاً"""
    line = line.strip()
    if not line:
        return None
    # تجاهل التعليقات فقط (السطور التي تبدأ بـ ! أو #)
    if line.startswith('!') or line.startswith('#'):
        return None
    return line

def download_filter(url):
    """تحميل الفلتر بدون أي تعديل (الحفاظ على كل القواعد)"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        valid_lines = []
        for line in response.text.splitlines():
            cleaned = clean_line(line)
            if cleaned:
                valid_lines.append(cleaned)
                
        return valid_lines, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """جمع كل القواعد من جميع المصادر وإزالة المكرر فقط"""
    seen_rules = set()
    total_urls = len(urls)
    total_before_dedup = 0
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    print("📝 سيتم الاحتفاظ بجميع أنواع القواعد (hosts, AdGuard, etc.)")
    print("🗑️ سيتم حذف المكرر فقط")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        results = []
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            total_before_dedup += len(rules)
            
            new_rules = []
            for r in rules:
                if r not in seen_rules:
                    seen_rules.add(r)
                    new_rules.append(r)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: {len(rules)} قاعدة → {len(new_rules)} قاعدة جديدة (تم إزالة {len(rules) - len(new_rules)} مكرر)")
            results.extend(new_rules)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    print(f"\n📈 إجمالي القواعد قبل إزالة المكرر: {total_before_dedup}")
    print(f"📈 إجمالي القواعد بعد إزالة المكرر: {len(results)}")
    
    return results

def save_filters(rules, output_dir="merged_filters"):
    """حفظ جميع القواعد في ملف واحد (بدون أي تعديل)"""
    os.makedirs(output_dir, exist_ok=True)
    
    # إضافة رأس الملف
    header = f"""! Title: AdGuard App Custom Filter (Merged)
! Description: Merged filter from multiple sources - all rules preserved
! Expires: 6 hours
! Version: {time.strftime("%Y.%m.%d")}
! Homepage: https://github.com/elqiser00/1002
! Total Rules: {len(rules)}
! Note: All original rules kept as-is, only duplicates removed
!
"""
    
    # الملف الرئيسي - كل القواعد كما هي
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في ملف واحد: {main_file}")

def create_metadata():
    """إنشاء ملف metadata.json"""
    import json
    
    metadata = {
        "name": "AdGuard App Custom Filter",
        "description": "Merged filter from multiple sources - all rules preserved, duplicates removed only",
        "homepage": "https://github.com/elqiser00/1002",
        "version": time.strftime("%Y.%m.%d"),
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rules_count": 0
    }
    
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
    FILTER_URLS = load_filter_urls()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط فلاتر للمعالجة")
        exit(1)
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية دمج الفلاتر...")
        print("=" * 50)
        
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        create_metadata()
        
        print("=" * 50)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تم دمج الفلاتر بنجاح!")
        print(f"📊 الإحصائيات النهائية: {len(rules)} قاعدة (جميع الأنواع محفوظة)")
        
        # عرض أمثلة على أنواع القواعد المحفوظة
        if rules:
            print("\n🔍 أمثلة على القواعد المحفوظة (بجميع أنواعها):")
            example_types = []
            for rule in rules[:10]:
                if rule.startswith('@@'):
                    example_types.append(f"استثناء: {rule}")
                elif rule.startswith('||'):
                    example_types.append(f"AdGuard: {rule}")
                elif rule.startswith('0.0.0.0') or rule.startswith('127.0.0.1'):
                    example_types.append(f"Hosts: {rule}")
                elif '.' in rule and not rule.startswith('!'):
                    example_types.append(f"نطاق: {rule}")
            
            for i, ex in enumerate(example_types[:5]):
                print(f"   {i+1}. {ex}")
            if len(rules) > 5:
                print(f"   ... و{len(rules) - 5} قاعدة أخرى")
                
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
