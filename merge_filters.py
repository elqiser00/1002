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

def is_valid_domain(domain):
    """التحقق من صحة النطاق"""
    if not domain or len(domain) < 4:
        return False
    
    # لا يبدأ بشرطة أو نقطة أو رقم
    if re.match(r'^[-\.0-9]', domain):
        return False
    
    # لا ينتهي بشرطة أو نقطة
    if re.match(r'[-\.]$', domain):
        return False
    
    # يحتوي على نقطة على الأقل
    if '.' not in domain:
        return False
    
    # الجزء الأخير (TLD) يجب أن يكون حروف فقط وطوله بين 2-10 أحرف
    tld = domain.split('.')[-1]
    if not re.match(r'^[a-zA-Z]{2,10}$', tld):
        return False
    
    # لا يحتوي على أحرف غير مسموح بها
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return False
    
    # الطول المعقول للنطاق
    if len(domain) > 63:
        return False
    
    # كل جزء بين النقاط لا يزيد عن 63 حرف
    parts = domain.split('.')
    for part in parts:
        if len(part) > 63:
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True

def remove_duplicate_domains(rules):
    """إزالة التكرارات بناءً على النطاق الأساسي (بدون www)"""
    seen_domains = set()
    unique_rules = []
    
    for rule in rules:
        # استخراج النطاق من القاعدة
        domain_match = re.search(r'\|\|([^\/\^]+)\^', rule)
        if domain_match:
            domain = domain_match.group(1)
            
            # إزالة www. للحصول على النطاق الأساسي
            base_domain = re.sub(r'^www\.', '', domain)
            
            if base_domain not in seen_domains:
                seen_domains.add(base_domain)
                unique_rules.append(rule)
        else:
            unique_rules.append(rule)
    
    return unique_rules

def convert_rule(line):
    """تحويل القواعد المختلفة إلى صيغة AdGuard"""
    line = line.strip()
    
    if not line:
        return None
    
    # 1. تجاهل التعبيرات العادية تماماً
    if re.match(r'^/.*/$', line):
        return None
    
    # 2. التعليقات - نتجاهلها
    if re.match(r'^[!#]', line):
        return None
    
    # 3. البيانات الوصفية - نتجاهلها
    if re.match(r'^[\[&$]', line):
        return None
    
    # 4. قواعد AdGuard الأساسية (نتحقق من صحتها أولاً)
    ag_match = re.match(r'^(@@\|\|)?\|\|([^\/\^]+)\^$', line)
    if ag_match:
        domain = ag_match.group(2)
        if is_valid_domain(domain):
            return line
        else:
            return None
    
    # 5. تحويل قواعد 127.0.0.1 أو 0.0.0.0
    dns_match = re.match(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line)
    if dns_match:
        domain = dns_match.group(2)
        if is_valid_domain(domain):
            return f"||{domain}^"
        else:
            return None
    
    # 6. قواعد النطاقات مع النقطتين
    colon_match = re.match(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):$', line)
    if colon_match:
        domain = colon_match.group(1)
        if is_valid_domain(domain):
            return f"||{domain}^"
        else:
            return None
    
    # 7. قواعد المضيف (hosts) بدون عنوان IP
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
        if is_valid_domain(line):
            return f"||{line}^"
        else:
            return None
    
    # تجاهل أي شيء آخر لا يتطابق مع الأنواع المطلوبة
    return None

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
    removed_count = 0
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر (سيتم إزالة التعبيرات العادية والتعليقات والنطاقات غير الصالحة)...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        results = []
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = [r for r in rules if r not in seen_rules]
            seen_rules.update(new_rules)
            
            # حساب القواعد المرفوضة
            rejected = len(rules) - len(new_rules)
            removed_count += rejected
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: تمت إضافة {len(new_rules)} قاعدة نظيفة")
            results.extend(new_rules)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    print(f"🗑️ تم إزالة {removed_count} قاعدة مكررة أو غير صالحة")
    
    # 🔥 إزالة التكرارات بناءً على النطاق الأساسي
    results = remove_duplicate_domains(results)
    print(f"🔥 تم إزالة التكرارات الإضافية بناءً على النطاق الأساسي")
    
    # ترتيب النتائج: الاستثناءات أولاً
    return sorted(results, key=lambda x: (not x.startswith('@@'), x))

def save_filters(rules, output_dir="merged_filters"):
    """حفظ القواعد النظيفة"""
    os.makedirs(output_dir, exist_ok=True)
    
    main_file = os.path.join(output_dir, "adguard_rules.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة نظيفة فقط في {main_file}")
    print("🗑️ تم إزالة جميع التعبيرات العادية والتعليقات والنطاقات غير الصالحة")
    
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
        print("⚠️ سيتم إزالة جميع التعبيرات العادية والنطاقات غير الصالحة من الفلاتر النهائية")
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تمت إزالة جميع التعبيرات العادية والتعليقات والنطاقات غير الصالحة بنجاح!")
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
