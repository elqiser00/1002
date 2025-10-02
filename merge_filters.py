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
    if not domain or len(domain) < 4 or len(domain) > 255:
        return False
    
    # يجب أن يحتوي على نقطة على الأقل
    if '.' not in domain:
        return False
    
    # يجب أن ينتهي بـ TLD صالح
    valid_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 
                  'io', 'co', 'info', 'biz', 'me', 'tv', 'us', 'uk',
                  'ca', 'de', 'fr', 'jp', 'cn', 'in', 'ru', 'br', 'au']
    
    tld = domain.split('.')[-1].lower()
    if tld not in valid_tlds and len(tld) < 2:
        return False
    
    # يجب أن يحتوي على أحرف وأرقام وشرطات فقط
    if not re.match(r'^[a-z0-9-\.]+$', domain, re.IGNORECASE):
        return False
    
    # لا يمكن أن يبدأ أو ينتهي بشرطة أو نقطة
    if domain.startswith('-') or domain.endswith('-') or domain.startswith('.') or domain.endswith('.'):
        return False
    
    # يجب أن يحتوي على جزء اسم نطاق على الأقل
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    # كل جزء يجب أن يكون بين 1 و 63 حرف
    for part in parts:
        if len(part) < 1 or len(part) > 63:
            return False
    
    return True

def extract_domain(line):
    """استخراج النطاق من أي صيغة وتحويلها لصيغة AdGuard"""
    line = line.strip()
    
    # تجاهل التعليقات والأسطر الفارغة
    if not line or line.startswith('!') or line.startswith('#') or line.startswith('/'):
        return None
    
    # تجاهل الأسطر التي تبدأ بـ [ أو &
    if line.startswith('[') or line.startswith('&'):
        return None
    
    # تنظيف التعليقات من نهاية السطر
    line = re.sub(r'\s*[#!].*$', '', line)
    line = line.strip()
    
    if not line:
        return None
    
    # تحديد إذا كانت قاعدة استثناء
    is_exception = line.startswith('@@')
    
    # استخراج النطاق من مختلف الصيغ
    domain = None
    extracted_domain = None
    
    # 1. صيغة AdGuard: @@||example.com^ أو ||example.com^
    match = re.search(r'@@\|\|([a-z0-9-]+\.[a-z0-9-\.]+)\^', line, re.IGNORECASE)
    if match:
        extracted_domain = match.group(1)
        domain = f"||{extracted_domain}^"
    
    # 2. صيغة DNS قديمة: 0.0.0.0 example.com أو 127.0.0.1 example.com
    if not domain:
        match = re.search(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.[a-z0-9-\.]+)', line, re.IGNORECASE)
        if match:
            extracted_domain = match.group(2)
            domain = f"||{extracted_domain}^"
    
    # 3. صيغة HOSTS بدون IP: example.com
    if not domain:
        match = re.search(r'^\s*([a-z0-9-]+\.[a-z0-9-\.]+)\s*$', line, re.IGNORECASE)
        if match:
            extracted_domain = match.group(1).strip()
            domain = f"||{extracted_domain}^"
    
    # 4. صيغة مع التعليقات: 127.0.0.1 example.org # تعليق
    if not domain:
        match = re.search(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.[a-z0-9-\.]+)', line, re.IGNORECASE)
        if match:
            extracted_domain = match.group(2)
            domain = f"||{extracted_domain}^"
    
    # التحقق من صحة النطاق المستخرج
    if domain and extracted_domain:
        if is_valid_domain(extracted_domain):
            # إضافة @@ إذا كانت قاعدة استثناء
            if is_exception:
                return f"@@{domain}"
            return domain
    
    return None

def download_filter(url):
    """تحميل الفلتر وتحويل جميع القواعد لصيغة AdGuard"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        valid_rules = []
        for line in response.text.splitlines():
            rule = extract_domain(line)
            if rule:
                valid_rules.append(rule)
                
        return valid_rules, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """المعالجة النهائية مع التأكد من فريدة النطاقات"""
    seen_domains = set()  # تخزين النطاقات الفريدة
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        results = []
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = []
            
            for rule in rules:
                # استخراج النطاق من القاعدة
                domain_match = re.search(r'\|\|([a-z0-9-]+\.[a-z0-9-\.]+)\^', rule, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1)  # النطاق بدون ||
                    
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        new_rules.append(rule)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: تمت إضافة {len(new_rules)} قاعدة فريدة")
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
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة AdGuard فريدة في {main_file}")
    print("📝 الصيغ المدعومة:")
    print("   - AdGuard: ||example.com^ أو @@||example.com^")
    print("   - HOSTS: 127.0.0.1 example.com أو 0.0.0.0 example.com")
    print("   - النطاقات البسيطة: example.com")
    print("📝 الصيغ المرفوضة:")
    print("   - التعليقات: ! أو #")
    print("   - التعبيرات العادية: /REGEX/")
    print("   - الرموز الخاصة: [ أو &")
    
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
        print("🚀 بدء عملية تحويل جميع القواعد لصيغة AdGuard...")
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تم تحويل جميع القواعد لصيغة AdGuard بنجاح!")
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
