import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# إعدادات التكوين
MAX_LINES_PER_PART = 2_000_000
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "Pi-hole-Filter-Merger/13.0"

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
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
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
    
    # ترتيب النتائج أبجدياً
    return sorted(results, key=lambda x: x.lower())

def save_filters(rules, output_dir="pi-hole_filters"):
    """حفظ القواعد النظيفة"""
    os.makedirs(output_dir, exist_ok=True)
    
    main_file = os.path.join(output_dir, "pi-hole_domains.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة نظيفة فقط في {main_file}")
    
    # حفظ إصدار مناسب لـ Pi-hole Gravity
    gravity_file = os.path.join(output_dir, "gravity.list")
    with open(gravity_file, 'w', encoding='utf-8') as f:
        for rule in rules:
            f.write(f"0.0.0.0 {rule}\n")
    
    print(f"✅ تم حفظ {len(rules)} قاعدة بصيغة Gravity في {gravity_file}")
    
    # التقسيم التلقائي
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
    FILTER_URLS = [
        # قوائم Pi-hole الموصى بها
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://mirror1.malwaredomains.com/files/justdomains",
        "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
        "https://hosts-file.net/ad_servers.txt",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KAD/master/annoyances.txt",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KAD/master/kad.txt",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
        "https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts",
        "https://winhelp2002.mvps.org/hosts.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.txt",
        "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
        "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
        "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
        "https://adaway.org/hosts.txt",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
        "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
        "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
        "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
        "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
        
        # قوائم AdGuard الأساسية (سيتم تحويلها)
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
        
        # قوائم EasyList (سيتم تحويلها)
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
        
        # قوائم إضافية
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    ]
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية التنظيف والدمج لـ Pi-hole...")
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تمت إزالة جميع التعليقات والمعلومات غير الضرورية بنجاح!")
        print("\n📋 تعليمات الاستخدام في Pi-hole:")
        print("1. انتقل إلى Admin Console -> Group Management -> Adlists")
        print("2. أضف ملف pi-hole_domains.txt كقائمة مخصصة")
        print("3. انتقل إلى Tools -> Update Gravity لتطبيق التغييرات")
        print("4. أو استخدم gravity.list كملف hosts مخصص")
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
