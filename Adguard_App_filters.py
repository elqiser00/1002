import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات التكوين
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-App-Filter-Merger/4.0"

def load_filter_urls():
    """تحميل روابط الفلاتر من ملف list.txt"""
    try:
        with open("list.txt", "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file if line.strip() and not line.startswith("#")]
        return urls
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        return []

def extract_domain_from_rule(rule):
    """استخراج النطاق من أي صيغة قاعدة وتحويلها إلى صيغة موحدة"""
    rule = rule.strip()
    
    # تجاهل التعليقات
    if rule.startswith('!') or rule.startswith('#'):
        return None, None
    
    # التحقق إذا كانت القاعدة استثناء
    is_exception = rule.startswith('@@')
    
    # إزالة علامة الاستثناء إذا وجدت للمعالجة
    clean_rule = rule[2:] if is_exception else rule
    
    # قائمة بأنماط القواعد المدعومة
    patterns = [
        # صيغة AdGuard: ||example.com^
        (r'^\|\|([a-z0-9-\.]+)\^$', r'\1'),
        # صيغة AdGuard بدون ^: ||example.com
        (r'^\|\|([a-z0-9-\.]+)$', r'\1'),
        # صيغة hosts: 0.0.0.0 example.com أو 127.0.0.1 example.com
        (r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9-\.]+)$', r'\1'),
        # صيغة نطاق عادي: example.com
        (r'^([a-z0-9-\.]+\.[a-z]{2,})$', r'\1'),
        # صيغة مع *: *.example.com
        (r'^\*\.([a-z0-9-\.]+\.[a-z]{2,})$', r'\1'),
        # صيغة مع /: /example.com/
        (r'^/([a-z0-9-\.]+\.[a-z]{2,})/$', r'\1'),
    ]
    
    for pattern, replacement in patterns:
        match = re.match(pattern, clean_rule, re.IGNORECASE)
        if match:
            domain = match.group(1).lower()
            # تنظيف النطاق من أي نقاط إضافية
            domain = domain.strip('.')
            return domain, is_exception
    
    return None, None

def download_and_extract_domains(url):
    """تحميل الفلتر واستخراج النطاقات فقط"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        domains = []  # قائمة النطاقات العادية
        exceptions = []  # قائمة النطاقات المستثناة
        
        for line in response.text.splitlines():
            domain, is_exception = extract_domain_from_rule(line)
            if domain:
                if is_exception:
                    exceptions.append(domain)
                else:
                    domains.append(domain)
        
        # إزالة المكرر داخل المصدر نفسه
        domains = list(set(domains))
        exceptions = list(set(exceptions))
        
        # إزالة النطاقات المستثناة من قائمة الحظر
        domains = [d for d in domains if d not in exceptions]
        
        return domains, exceptions, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], [], url

def process_filters(urls):
    """معالجة جميع الفلاتر وتوحيد النطاقات"""
    all_domains = set()  # كل النطاقات المحظورة
    all_exceptions = set()  # كل النطاقات المستثناة
    
    total_urls = len(urls)
    total_domains_before = 0
    total_exceptions_before = 0
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    print("📝 سيتم استخراج النطاقات من جميع أنواع القواعد:")
    print("   - ||example.com^ (AdGuard)")
    print("   - 0.0.0.0 example.com (hosts)")
    print("   - example.com (نطاق عادي)")
    print("   - @@example.com (استثناءات)")
    print("🎯 الهدف: كل نطاق يظهر مرة واحدة فقط\n")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_and_extract_domains, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            domains, exceptions, url = future.result()
            
            total_domains_before += len(domains)
            total_exceptions_before += len(exceptions)
            
            # إضافة النطاقات الجديدة
            new_domains = [d for d in domains if d not in all_domains]
            new_exceptions = [e for e in exceptions if e not in all_exceptions]
            
            all_domains.update(domains)
            all_exceptions.update(exceptions)
            
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}:")
            print(f"   📍 حظر: {len(domains)} نطاق → {len(new_domains)} جديد")
            print(f"   📍 استثناء: {len(exceptions)} نطاق → {len(new_exceptions)} جديد")
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    # إزالة النطاقات المستثناة من قائمة الحظر
    final_domains = all_domains - all_exceptions
    
    print(f"\n📈 الإحصائيات النهائية:")
    print(f"   إجمالي النطاقات المحظورة (قبل إزالة الاستثناءات): {len(all_domains)}")
    print(f"   إجمالي النطاقات المستثناة: {len(all_exceptions)}")
    print(f"   النطاقات النهائية المحظورة: {len(final_domains)}")
    
    return sorted(final_domains), sorted(all_exceptions)

def save_filters(domains, exceptions, output_dir="merged_filters"):
    """حفظ الفلاتر بصيغة متوافقة مع تطبيق AdGuard"""
    os.makedirs(output_dir, exist_ok=True)
    
    # إضافة رأس الملف
    header = f"""! Title: AdGuard App Unified Filter
! Description: Merged and deduplicated domains from multiple sources
! Expires: 6 hours
! Version: {time.strftime("%Y.%m.%d")}
! Homepage: https://github.com/elqiser00/1002
! Total Blocked Domains: {len(domains)}
! Total Exceptions: {len(exceptions)}
!
! All domains have been normalized to simple format (domain.com)
! Exceptions are marked with @@ prefix
!
"""
    
    # الملف الرئيسي - كل النطاقات المحظورة بصيغة بسيطة
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(header)
        # إضافة النطاقات المحظورة
        for domain in domains:
            f.write(f"{domain}\n")
        # إضافة النطاقات المستثناة
        if exceptions:
            f.write(f"\n! Exceptions\n")
            for exception in exceptions:
                f.write(f"@@{exception}\n")
    
    print(f"\n✅ تم حفظ {len(domains)} نطاق محظور و {len(exceptions)} استثناء في {main_file}")
    
    # إنشاء ملف بصيغة hosts إضافية (اختياري)
    hosts_file = os.path.join(output_dir, "hosts_format.txt")
    with open(hosts_file, 'w', encoding='utf-8') as f:
        f.write("# Hosts format for AdGuard App\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total Blocked Domains: {len(domains)}\n\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")
    
    print(f"✅ تم إنشاء نسخة بصيغة hosts في {hosts_file}")

def create_metadata(domains, exceptions):
    """إنشاء ملف metadata.json"""
    import json
    
    metadata = {
        "name": "AdGuard App Unified Filter",
        "description": "Unified domains from multiple sources - all duplicates removed, normalized to simple format",
        "homepage": "https://github.com/elqiser00/1002",
        "version": time.strftime("%Y.%m.%d"),
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "blocked_domains": len(domains),
        "exceptions": len(exceptions),
        "total_rules": len(domains) + len(exceptions)
    }
    
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
        print("🚀 بدء عملية توحيد النطاقات...")
        print("=" * 60)
        
        domains, exceptions = process_filters(FILTER_URLS)
        save_filters(domains, exceptions)
        create_metadata(domains, exceptions)
        
        print("=" * 60)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تم توحيد النطاقات بنجاح!")
        print(f"📊 النتائج النهائية:")
        print(f"   🚫 نطاقات محظورة: {len(domains)}")
        print(f"   ⭐ نطاقات مستثناة: {len(exceptions)}")
        print(f"   📝 إجمالي القواعد: {len(domains) + len(exceptions)}")
        
        # عرض بعض الأمثلة
        if domains:
            print("\n🔍 أمثلة على النطاقات المحظورة:")
            for i, domain in enumerate(domains[:5]):
                print(f"   {i+1}. {domain}")
            if len(domains) > 5:
                print(f"   ... و{len(domains) - 5} نطاق آخر")
        
        if exceptions:
            print("\n🔍 أمثلة على النطاقات المستثناة:")
            for i, exception in enumerate(exceptions[:3]):
                print(f"   {i+1}. @@{exception}")
                
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
