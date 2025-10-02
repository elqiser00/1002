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
REQUEST_TIMEOUT = 30
REQUEST_DELAY = 0.1
MAX_WORKERS = 20
USER_AGENT = "AdGuardHome-Filter-Merger/13.0"
CHUNK_SIZE = 1000

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
    """التحقق من صحة النطاق بشكل صارم"""
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
    
    # الطول المعقول للنطاق (لا يزيد عن 63 حرف للنطاق الكامل)
    if len(domain) > 63:
        return False
    
    # كل جزء بين النقاط لا يزيد عن 63 حرف ولا يبدأ/ينتهي بشرطة
    parts = domain.split('.')
    for part in parts:
        if len(part) > 63:
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
        if not part:  # جزء فارغ
            return False
        # رفض أي جزء يبدأ برقم
        if re.match(r'^[0-9]', part):
            return False
    
    # 🔥 **فحص إضافي: رفض الدومينات التي تحتوي على أنماط مشبوهة**
    
    # رفض الدومينات التي تحتوي على hash طويل (أكثر من 12 حرف أبجدي رقمي)
    if re.search(r'[a-f0-9]{12,}', domain.lower()):
        return False
    
    # رفض الدومينات التي تحتوي على أرقام متتالية طويلة (أكثر من 4 أرقام)
    if re.search(r'\d{5,}', domain):
        return False
    
    # رفض الدومينات التي تحتوي على أجزاء كلها أرقام وحروف عشوائية
    for part in parts[:-1]:  # كل الأجزاء عدا TLD
        # إذا كان الجزء يحتوي على أكثر من 70% أرقام وحروف hex
        if len(part) > 8:
            hex_chars = re.findall(r'[a-f0-9]', part.lower())
            if len(hex_chars) / len(part) > 0.7:
                return False
    
    return True

def remove_duplicate_domains(rules):
    """إزالة التكرارات بناءً على النطاق الأساسي"""
    seen_domains = set()
    unique_rules = []
    removed_count = 0
    
    for rule in rules:
        domain_match = re.search(r'\|\|([^\/\^]+)\^', rule)
        if domain_match:
            domain = domain_match.group(1)
            base_domain = re.sub(r'^www\.', '', domain)
            
            if base_domain not in seen_domains:
                seen_domains.add(base_domain)
                unique_rules.append(rule)
            else:
                removed_count += 1
        else:
            unique_rules.append(rule)
    
    if removed_count > 0:
        print(f"🗑️ تم إزالة {removed_count} قاعدة مكررة بناءً على النطاق الأساسي")
    
    return unique_rules

def convert_rules_batch(lines):
    """تحويل مجموعة من القواعد دفعة واحدة مع فحص صارم"""
    valid_rules = []
    rejected_count = 0
    
    for line in lines:
        line = line.strip()
        
        if not line:
            continue
            
        # تجاهل التعبيرات العادية والتعليقات والبيانات الوصفية بسرعة
        if (re.match(r'^[!#\[&$/]', line) or 
            len(line) > MAX_LINE_LENGTH):
            rejected_count += 1
            continue
        
        rule = None
        
        # 1. قواعد AdGuard الأساسية - فحص صارم
        ag_match = re.match(r'^(@@\|\|)?\|\|([^\/\^]+)\^$', line)
        if ag_match:
            domain = ag_match.group(2)
            if is_valid_domain(domain):
                rule = line
            else:
                rejected_count += 1
                continue
        
        # 2. تحويل قواعد DNS
        elif re.match(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', line):
            dns_match = re.match(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line)
            if dns_match:
                domain = dns_match.group(2)
                if is_valid_domain(domain):
                    rule = f"||{domain}^"
                else:
                    rejected_count += 1
                    continue
        
        # 3. قواعد النطاقات مع النقطتين
        elif line.endswith(':'):
            colon_match = re.match(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):$', line)
            if colon_match:
                domain = colon_match.group(1)
                if is_valid_domain(domain):
                    rule = f"||{domain}^"
                else:
                    rejected_count += 1
                    continue
        
        # 4. قواعد المضيف بدون عنوان IP
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
            if is_valid_domain(line):
                rule = f"||{line}^"
            else:
                rejected_count += 1
                continue
        else:
            rejected_count += 1
            continue
        
        if rule:
            valid_rules.append(rule)
    
    return valid_rules

def download_filter_fast(url):
    """تحميل الفلتر بسرعة مع التصفية الصارمة"""
    try:
        headers = {
            'User-Agent': USER_AGENT,
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache'
        }
        
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        lines = response.text.splitlines()
        valid_rules = []
        
        for i in range(0, len(lines), CHUNK_SIZE):
            chunk = lines[i:i + CHUNK_SIZE]
            chunk_rules = convert_rules_batch(chunk)
            valid_rules.extend(chunk_rules)
                
        return valid_rules, url
        
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters_fast(urls):
    """المعالجة النهائية السريعة مع فحص صارم"""
    seen_rules = set()
    total_urls = len(urls)
    total_rules = 0
    total_rejected = 0
    
    print(f"🚀 بدء المعالجة السريعة لـ {total_urls} مصدر فلتر...")
    print("🔍 سيتم فحص جميع النطاقات بشكل صارم وإزالة غير الصالحة")
    print("⚠️ سيتم رفض الدومينات التي تحتوي على:")
    print("   - أجزاء تبدأ بأرقام")
    print("   - hash طويل (أكثر من 12 حرف)")
    print("   - أرقام متتالية طويلة")
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter_fast, url): url for url in urls}
        
        results = []
        completed = 0
        
        for future in as_completed(future_to_url):
            rules, url = future.result()
            new_rules = [r for r in rules if r not in seen_rules]
            rejected_in_url = len(rules) - len(new_rules)
            total_rejected += rejected_in_url
            
            seen_rules.update(new_rules)
            
            completed += 1
            total_rules += len(new_rules)
            
            print(f"📊 [{completed}/{total_urls}] {urlparse(url).netloc}: {len(new_rules)} قاعدة صالحة")
            results.extend(new_rules)
    
    processing_time = time.time() - start_time
    print(f"⏱️ وقت المعالجة: {processing_time:.2f} ثانية")
    print(f"📈 متوسط السرعة: {total_rules/processing_time:.1f} قاعدة/ثانية")
    print(f"🗑️ إجمالي القواعد المرفوضة: {total_rejected} قاعدة")
    
    # إزالة التكرارات النهائية
    final_count_before = len(results)
    results = remove_duplicate_domains(results)
    final_count_after = len(results)
    
    print(f"🔥 تم إزالة {final_count_before - final_count_after} قاعدة مكررة إضافية")
    
    # ترتيب النتائج: الاستثناءات أولاً
    return sorted(results, key=lambda x: (not x.startswith('@@'), x))

def save_filters_fast(rules, output_dir="merged_filters"):
    """حفظ سريع للقواعد"""
    os.makedirs(output_dir, exist_ok=True)
    
    main_file = os.path.join(output_dir, "adguard_rules.txt")
    
    with open(main_file, 'w', encoding='utf-8', buffering=8192) as f:
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة نظيفة في {main_file}")
    
    # التقسيم التلقائي السريع
    if len(rules) > MAX_LINES_PER_PART:
        parts = (len(rules) // MAX_LINES_PER_PART) + 1
        print(f"📦 تقسيم إلى {parts} أجزاء...")
        
        for i in range(parts):
            part_file = os.path.join(output_dir, f"adguard_rules_part_{i+1}.txt")
            start = i * MAX_LINES_PER_PART
            end = start + MAX_LINES_PER_PART
            
            with open(part_file, 'w', encoding='utf-8', buffering=8192) as f:
                f.write("\n".join(rules[start:end]))
            
            print(f"✅ الجزء {i+1}: {len(rules[start:end])} قاعدة")

if __name__ == "__main__":
    FILTER_URLS = load_filter_urls()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط فلاتر للمعالجة")
        exit(1)
    
    total_start_time = time.time()
    try:
        print("⚡ بدء عملية الدمج السريع مع الفحص الصارم...")
        rules = process_filters_fast(FILTER_URLS)
        save_filters_fast(rules)
        
        total_time = time.time() - total_start_time
        print(f"\n🎉 اكتملت العملية في {total_time:.2f} ثانية")
        print(f"📊 إجمالي القواعد الصالحة: {len(rules):,} قاعدة")
        print(f"🚀 متوسط الأداء: {len(rules)/total_time:.1f} قاعدة/ثانية")
        
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
