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

def is_valid_domain(domain):
    """التحقق من أن النطاق صالح لـ Pi-hole"""
    if not domain:
        return False
    
    # تجاهل القواعد المعقدة والمسارات
    if re.search(r'[/\\?&=:%]', domain):
        return False
    
    # قبول النطاقات العادية فقط
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', domain):
        return True
    
    return False

def extract_simple_domain(line):
    """استخراج نطاقات بسيطة فقط لـ Pi-hole"""
    line = line.strip()
    
    # تجاهل التعليقات والأسطر الفارغة
    if not line or line.startswith(('!', '#', '[', '&')):
        return None, None
    
    # قواعد الاستثناء (@@)
    if line.startswith('@@'):
        # من @@||domain.com^
        match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+)\^', line)
        if match and is_valid_domain(match.group(1)):
            return match.group(1), 'whitelist'
        
        # من @@domain.com
        match = re.match(r'^@@([a-zA-Z0-9.-]+)$', line)
        if match and is_valid_domain(match.group(1)):
            return match.group(1), 'whitelist'
    
    # قواعد الحظر العادية
    else:
        # من ||domain.com^
        match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^', line)
        if match and is_valid_domain(match.group(1)):
            return match.group(1), 'blacklist'
        
        # من domain.com
        match = re.match(r'^([a-zA-Z0-9.-]+)$', line)
        if match and is_valid_domain(match.group(1)):
            return match.group(1), 'blacklist'
        
        # من 127.0.0.1 domain.com
        match = re.match(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-zA-Z0-9.-]+)$', line)
        if match and is_valid_domain(match.group(2)):
            return match.group(2), 'blacklist'
    
    return None, None

def process_rule(line):
    """معالجة القاعدة لأخذ النطاقات البسيطة فقط"""
    line = line.strip()
    if not line:
        return None, None
    
    # تجاهل التعليقات
    if line.startswith(('!', '#', '[', '&')):
        return None, None
    
    # تجاهل قواعد RegEX (مثل /ads?/)
    if re.match(r'^/.*/$', line) or '*' in line:
        return None, None
    
    # تجاهل قواعد AdGuard المتقدمة ($removeparam, etc)
    if re.search(r'\$', line):
        domain, rule_type = extract_simple_domain(line)
        return domain, rule_type
    
    # القواعد البسيطة فقط
    domain, rule_type = extract_simple_domain(line)
    return domain, rule_type

def download_filter(url):
    """تحميل الفلتر وأخذ النطاقات البسيطة فقط"""
    try:
        session = create_session()
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        
        blacklist_rules = []
        whitelist_rules = []
        
        for line in response.text.splitlines():
            rule, rule_type = process_rule(line)
            if rule and rule_type == 'blacklist':
                blacklist_rules.append(rule)
            elif rule and rule_type == 'whitelist':
                whitelist_rules.append(rule)
                
        return blacklist_rules, whitelist_rules, url
        
    except requests.exceptions.SSLError:
        # تحويل HTTPS إلى HTTP بشكل صامت
        try:
            http_url = url.replace('https://', 'http://')
            session = requests.Session()
            session.headers.update({'User-Agent': USER_AGENT})
            response = session.get(http_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            blacklist_rules = []
            whitelist_rules = []
            
            for line in response.text.splitlines():
                rule, rule_type = process_rule(line)
                if rule and rule_type == 'blacklist':
                    blacklist_rules.append(rule)
                elif rule and rule_type == 'whitelist':
                    whitelist_rules.append(rule)
                    
            return blacklist_rules, whitelist_rules, url
            
        except Exception:
            return [], [], url
            
    except Exception:
        return [], [], url

def process_filters(urls):
    """المعالجة النهائية مع إزالة التكرار فقط"""
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
            
            # إزالة التكرار من البلاك ليست
            new_black_rules = [r for r in black_rules if r not in seen_blacklist]
            seen_blacklist.update(new_black_rules)
            blacklist_results.extend(new_black_rules)
            
            # إزالة التكرار من الويت ليست
            new_white_rules = [r for r in white_rules if r not in seen_whitelist]
            seen_whitelist.update(new_white_rules)
            whitelist_results.extend(new_white_rules)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: {len(new_black_rules)} بلاك ليست, {len(new_white_rules)} ويت ليست")
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    return blacklist_results, whitelist_results

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

if __name__ == "__main__":
    # تحميل الروابط من ملف list.txt فقط
    FILTER_URLS = load_filter_sources()
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط لمعالجتها")
        exit(1)
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية الدمج لـ Pi-hole...")
        print("📝 ملاحظة: يتم أخذ النطاقات البسيطة فقط (بدون RegEx)")
        blacklist, whitelist = process_filters(FILTER_URLS)
        
        if blacklist or whitelist:
            save_filters(blacklist, whitelist)
            print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
            print(f"📊 تم جمع {len(blacklist)} قاعدة بلاك ليست و {len(whitelist)} قاعدة ويت ليست")
            print("✨ تمت العملية بنجاح!")
            
            # عرض أمثلة من القواعد
            print("\n🔍 أمثلة من النطاقات المستخرجة:")
            if blacklist:
                print(f"بلاك ليست: {blacklist[:5]}...")
            if whitelist:
                print(f"ويت ليست: {whitelist[:5]}...")
                
        else:
            print("❌ لم يتم العثور على أي قواعد صالحة")
            
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
