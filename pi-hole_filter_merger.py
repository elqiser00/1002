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
    """تحويل القواعد إلى صيغة Pi-hole وتحديد نوعها (blacklist/whitelist)"""
    line = line.strip()
    if not line:
        return None, None
    
    # معالجة قواعد الاستثناءات (Whitelist)
    if line.startswith('@@'):
        # استخراج النطاق من قاعدة الاستثناء
        domain = None
        if re.fullmatch(r'^@@\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE):
            domain = line[4:-1]  # إزالة @@|| من البداية و ^ من النهاية
        elif re.fullmatch(r'^@@([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
            domain = line[2:]  # إزالة @@ من البداية
        
        if domain and is_valid_rule(domain):
            return domain, 'whitelist'
        return None, None
    
    # تجاهل القواعد غير الصالحة للبلاك ليست
    if not is_valid_rule(line):
        return None, None
    
    # تحويل قواعد DNS إلى صيغة Pi-hole
    if re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        domain = line.split()[1]
        return domain, 'blacklist'
    
    # تحويل قواعد AdGuard (||example.com^) إلى صيغة Pi-hole
    if re.fullmatch(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', line, re.IGNORECASE):
        domain = line[2:-1]  # إزالة || من البداية و ^ من النهاية
        return domain, 'blacklist'
    
    # معالجة قواعد HOSTS (نطاقين متجاورين)
    if re.fullmatch(r'^([a-z0-9-]+\.)+[a-z]{2,}\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        parts = line.split()
        if len(parts) >= 2:
            return parts[1], 'blacklist'  # إرجاع النطاق الثاني
    
    # النطاقات البسيطة
    if re.fullmatch(r'^([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE):
        return line, 'blacklist'
    
    return None, None

def download_filter(url):
    """تحميل الفلتر مع التصفية الشاملة"""
    try:
        session = create_session()
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        
        blacklist_rules = []
        whitelist_rules = []
        
        for line in response.text.splitlines():
            rule, rule_type = convert_rule(line)
            if rule and rule_type == 'blacklist':
                blacklist_rules.append(rule)
            elif rule and rule_type == 'whitelist':
                whitelist_rules.append(rule)
                
        return blacklist_rules, whitelist_rules, url
        
    except requests.exceptions.SSLError as ssl_error:
        print(f"⚠️ خطأ SSL في {urlparse(url).netloc}: {ssl_error}")
        print(f"   ⚡ جرب التحويل إلى HTTP بدلاً من HTTPS...")
        try:
            # تحويل HTTPS إلى HTTP
            http_url = url.replace('https://', 'http://')
            session = requests.Session()
            session.headers.update({'User-Agent': USER_AGENT})
            response = session.get(http_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            blacklist_rules = []
            whitelist_rules = []
            
            for line in response.text.splitlines():
                rule, rule_type = convert_rule(line)
                if rule and rule_type == 'blacklist':
                    blacklist_rules.append(rule)
                elif rule and rule_type == 'whitelist':
                    whitelist_rules.append(rule)
                    
            print(f"   ✅ تم التحميل بنجاح عبر HTTP")
            return blacklist_rules, whitelist_rules, url
            
        except Exception as fallback_error:
            print(f"   ❌ فشل التحويل إلى HTTP أيضًا: {fallback_error}")
            return [], [], url
            
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], [], url

def process_filters(urls):
    """المعالجة النهائية مع التنظيف الكامل"""
    if not urls:
        return [], []
        
    seen_blacklist = set()
    seen_whitelist = set()
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        blacklist_results = []
        whitelist_results = []
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            black_rules, white_rules, url = future.result()
            
            # معالجة البلاك ليست
            new_black_rules = [r for r in black_rules if r not in seen_blacklist and r not in seen_whitelist]
            seen_blacklist.update(new_black_rules)
            blacklist_results.extend(new_black_rules)
            
            # معالجة الويت ليست (تأخذ الأولوية)
            new_white_rules = [r for r in white_rules if r not in seen_whitelist]
            seen_whitelist.update(new_white_rules)
            whitelist_results.extend(new_white_rules)
            
            # إزالة أي نطاقات من البلاك ليست إذا كانت في الويت ليست
            blacklist_results = [r for r in blacklist_results if r not in seen_whitelist]
            seen_blacklist = seen_blacklist - seen_whitelist
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: {len(new_black_rules)} بلاك ليست, {len(new_white_rules)} ويت ليست")
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    # ترتيب النتائج أبجدياً
    blacklist_sorted = sorted(blacklist_results, key=lambda x: x.lower())
    whitelist_sorted = sorted(whitelist_results, key=lambda x: x.lower())
    
    return blacklist_sorted, whitelist_sorted

def save_filters(blacklist_rules, whitelist_rules, output_dir="pi-hole_filters"):
    """حفظ القوائم المنفصلة"""
    os.makedirs(output_dir, exist_ok=True)
    
    # حفظ البلاك ليست
    if blacklist_rules:
        blacklist_file = os.path.join(output_dir, "blacklist.txt")
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(blacklist_rules))
        print(f"✅ تم حفظ {len(blacklist_rules)} قاعدة في {blacklist_file}")
    
    # حفظ الويت ليست
    if whitelist_rules:
        whitelist_file = os.path.join(output_dir, "whitelist.txt")
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(whitelist_rules))
        print(f"✅ تم حفظ {len(whitelist_rules)} قاعدة في {whitelist_file}")
    
    # حفظ ملف موحد للتوافق مع الإصدار السابق
    if blacklist_rules:
        main_file = os.path.join(output_dir, "pi-hole_domains.txt")
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(blacklist_rules))
        print(f"✅ تم حفظ {len(blacklist_rules)} قاعدة في {main_file} (للتوافق)")

if __name__ == "__main__":
    # تحميل الروابط من ملف list.txt فقط
    FILTER_URLS = load_filter_sources()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط لمعالجتها")
        exit(1)
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية التنظيف والدمج لـ Pi-hole...")
        blacklist, whitelist = process_filters(FILTER_URLS)
        
        if blacklist or whitelist:
            save_filters(blacklist, whitelist)
            print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
            print(f"📊 تم جمع {len(blacklist)} قاعدة بلاك ليست و {len(whitelist)} قاعدة ويت ليست")
            print("✨ تمت العملية بنجاح!")
            print("\n📋 كيفية الاستخدام في Pi-hole:")
            print("1. اذهب إلى Group Management > Adlists")
            print("2. أضف الرابط: https://raw.githubusercontent.com/elqiser00/1002/main/pi-hole_filters/blacklist.txt")
            print("3. اذهب إلى Group Management > Domainlist")
            print("4. أضف الرابط: https://raw.githubusercontent.com/elqiser00/1002/main/pi-hole_filters/whitelist.txt")
            print("5. اذهب إلى Tools > Update Gravity")
        else:
            print("❌ لم يتم العثور على أي قواعد صالحة")
            
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
