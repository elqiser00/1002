import requests
import os
import time
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# إعدادات التكوين
MAX_LINES_PER_PART = 2_000_000
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "Pi-hole-Filter-Merger/1.0"
SOURCES_FILE = "list.txt"

# تجاوز تحقق SSL للشهادات المنتهية
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def create_session():
    """إنشاء جلسة مع تجاوز أخطاء SSL"""
    session = requests.Session()
    session.mount('https://', SSLAdapter())
    session.headers.update({'User-Agent': USER_AGENT})
    return session

def load_filter_sources():
    """تحميل روابط الفلاتر من ملف list.txt"""
    urls = []
    try:
        with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # تجاهل الأسطر الفارغة والتعليقات
                if line and not line.startswith('#'):
                    urls.append(line)
        
        if not urls:
            print(f"❌ ملف {SOURCES_FILE} لا يحتوي على أي روابط صالحة")
            return []
            
        print(f"✅ تم تحميل {len(urls)} مصدر من {SOURCES_FILE}")
        return urls
        
    except FileNotFoundError:
        print(f"❌ ملف {SOURCES_FILE} غير موجود")
        print("📋 يرجى إنشاء ملف list.txt يحتوي على روابط الفلاتر")
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
    # 1. نطاقات Pi-hole الأساسية (بدون قواعد AdGuard المعقدة)
    # 2. قواعد DNS (127.0.0.1 أو 0.0.0.0)
    # 3. النطاقات البسيطة (example.com)
    return (
        re.fullmatch(r'^([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE) or
        re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE) or
        re.fullmatch(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE) or
        re.fullmatch(r'^([a-z0-9-]+\.)+[a-z]{2,}\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE)
    )

def convert_rule(line):
    """تحويل القواعد إلى صيغة Pi-hole"""
    line = line.strip()
    if not is_valid_rule(line):
        return None
    
    # تحويل قواعد DNS إلى صيغة Pi-hole
    if re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        domain = line.split()[1]
        return domain
    
    # تحويل قواعد AdGuard (||example.com^) إلى صيغة Pi-hole
    if re.fullmatch(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE):
        domain = line[2:-1]  # إزالة || من البداية و ^ من النهاية
        return domain
    
    # معالجة قواعد HOSTS (نطاقين متجاورين)
    if re.fullmatch(r'^([a-z0-9-]+\.)+[a-z]{2,}\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        parts = line.split()
        if len(parts) >= 2:
            return parts[1]  # إرجاع النطاق الثاني
    
    # تجاهل قواعد الاستثناءات في Pi-hole
    if line.startswith('@@'):
        return None
    
    return line

def download_filter(url):
    """تحميل الفلتر مع التصفية الشاملة"""
    try:
        session = create_session()
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        
        valid_rules = []
        for line in response.text.splitlines():
            rule = convert_rule(line)
            if rule:
                valid_rules.append(rule)
                
        return valid_rules, url
        
    except requests.exceptions.SSLError:
        # إذا فشل HTTPS، جرب HTTP
        try:
            http_url = url.replace('https://', 'http://')
            response = requests.get(http_url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': USER_AGENT})
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
            
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """المعالجة النهائية مع التنظيف الكامل"""
    if not urls:
        return []
        
    seen_rules = set()
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        results = []
        for i, future in enumerate(as_completed(future_to_url), 1):
            rules, url = future.result()
            new_rules = [r for r in rules if r not in seen_rules]
            seen_rules.update(new_rules)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: تمت إضافة {len(new_rules)} قاعدة")
            results.extend(new_rules)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    # ترتيب النتائج أبجدياً
    return sorted(results, key=lambda x: x.lower())

def save_filters(rules, output_dir="pi-hole_filters"):
    """حفظ القواعد النظيفة - ملف واحد فقط"""
    os.makedirs(output_dir, exist_ok=True)
    
    # حفظ ملف النطاقات فقط (pi-hole_domains.txt)
    main_file = os.path.join(output_dir, "pi-hole_domains.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في {main_file}")
    
    # التقسيم التلقائي إذا لزم الأمر
    if len(rules) > MAX_LINES_PER_PART:
        parts = (len(rules) // MAX_LINES_PER_PART) + 1
        print(f"📦 تقسيم إلى {parts} أجزاء...")
        
        for i in range(parts):
            part_file = os.path.join(output_dir, f"pi-hole_domains_part_{i+1}.txt")
            with open(part_file, 'w', encoding='utf-8') as f:
                start = i * MAX_LINES_PER_PART
                end = start + MAX_LINES_PER_PART
                f.write("\n".join(rules[start:end]))
            
            print(f"✅ الجزء {i+1}: {len(rules[start:end])} قاعدة")

if __name__ == "__main__":
    # تحميل الروابط من ملف list.txt فقط
    FILTER_URLS = load_filter_sources()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط لمعالجتها")
        exit(1)
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية التنظيف والدمج لـ Pi-hole...")
        rules = process_filters(FILTER_URLS)
        
        if rules:
            save_filters(rules)
            print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
            print(f"📊 تم جمع {len(rules)} قاعدة فلترة")
            print("✨ تمت العملية بنجاح!")
            print("\n📋 كيفية الاستخدام في Pi-hole:")
            print("1. اذهب إلى Group Management > Adlists")
            print("2. أضف الرابط: https://raw.githubusercontent.com/elqiser00/1002/main/pi-hole_filters/pi-hole_domains.txt")
            print("3. اذهب إلى Tools > Update Gravity")
        else:
            print("❌ لم يتم العثور على أي قواعد صالحة")
            
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
