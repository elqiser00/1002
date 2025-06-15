import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# إعدادات التكوين
MAX_LINES_PER_PART = 2_000_000
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 45
REQUEST_DELAY = 0.3
MAX_WORKERS = 5
USER_AGENT = "AdGuardHome-Filter-Merger/5.0"

def convert_rule(line):
    """تحويل القواعد إلى صيغة AdGuard مع معالجة التكرار"""
    line = line.strip()
    if not line:
        return None

    # تجاهل التعليقات والبيانات الوصفية
    if line.startswith(('!', '#', '[', '&')):
        return None

    # 1. قواعد AdGuard (موجودة بالفعل)
    if line.startswith(('||', '@@||')) and line.endswith('^'):
        return line.lower()  # توحيد الحروف للتكرار

    # 2. قواعد DNS (127.0.0.1 أو 0.0.0.0)
    if re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+[a-z0-9-]+\.[a-z]{2,}$', line, re.IGNORECASE):
        domain = line.split()[1].lower()
        return f"||{domain}^"

    return None

def is_valid_filter(line):
    """التحقق من صحة السطر حسب الأنواع المدعومة"""
    line = line.strip()
    return (
        len(line) <= MAX_LINE_LENGTH and
        not line.startswith(('!', '#', '[', '&', '/')) and
        not any(patt in line for patt in ('##', '#@#', '!#', '##^')) and
        (
            (line.startswith(('||', '@@||')) and line.endswith('^')) or
            re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+[a-z0-9-]+\.[a-z]{2,}$', line, re.IGNORECASE)
        )
    )

def normalize_filter(line):
    """توحيد صيغة السطر للتكرار"""
    line = line.strip().lower()
    if line.startswith(('||', '@@||')) and line.endswith('^'):
        return line
    if re.match(r'^(?:127\.0\.0\.1|0\.0\.0\.0)\s+[a-z0-9-]+\.[a-z]{2,}$', line):
        return f"||{line.split()[1]}^"
    return line

def process_filters(urls):
    """معالجة الفلاتر مع إزالة التكرارات الشاملة"""
    global_seen = set()
    duplicate_count = 0
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر مع التحقق من التكرارات...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            lines, url = future.result()
            domain = urlparse(url).netloc
            new_lines = []
            
            for line in lines:
                normalized = normalize_filter(line)
                if normalized not in global_seen:
                    global_seen.add(normalized)
                    new_lines.append(line)
                else:
                    duplicate_count += 1
            
            print(f"📊 [{i}/{total_urls}] {domain}: {len(lines)} قاعدة | تمت إضافة {len(new_lines)} | التكرارات: {duplicate_count}")
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    print(f"\n⚠️ إجمالي التكرارات المكتشفة: {duplicate_count}")
    return list(global_seen)

def save_filters(rules, output_dir="merged_filters"):
    """حفظ القواعد مع التحقق النهائي من التكرار"""
    os.makedirs(output_dir, exist_ok=True)
    
    # التحقق النهائي من التكرار
    final_rules = []
    seen = set()
    duplicate_count = 0
    
    for rule in rules:
        normalized = normalize_filter(rule)
        if normalized not in seen:
            seen.add(normalized)
            final_rules.append(rule)
        else:
            duplicate_count += 1
    
    if duplicate_count > 0:
        print(f"⚠️ تم اكتشاف {duplicate_count} تكرار أثناء الحفظ النهائي")
    
    # فرز القواعد: استثناءات أولاً
    exceptions = [r for r in final_rules if r.startswith('@@')]
    blocks = [r for r in final_rules if not r.startswith('@@')]
    sorted_rules = exceptions + blocks
    
    # حفظ الملف الرئيسي
    main_file = os.path.join(output_dir, "adguard_rules.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted_rules))
    
    print(f"\n✅ تم حفظ {len(sorted_rules)} قاعدة فريدة في {main_file}")
    
    # التقسيم إذا لزم الأمر
    if len(sorted_rules) > MAX_LINES_PER_PART:
        parts = (len(sorted_rules) // MAX_LINES_PER_PART) + 1
        print(f"📦 تقسيم إلى {parts} أجزاء...")
        
        for i in range(parts):
            start = i * MAX_LINES_PER_PART
            end = start + MAX_LINES_PER_PART
            part_file = os.path.join(output_dir, f"adguard_rules_part_{i+1}.txt")
            
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(sorted_rules[start:end]))
            
            print(f"✅ تم حفظ الجزء {i+1}: {len(sorted_rules[start:end])} قاعدة")

if __name__ == "__main__":
    FILTER_URLS = [
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_1_Russian/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_6_German/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_16_French/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_7_Japanese/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_8_Dutch/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_9_Spanish/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_13_Turkish/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_23_Ukrainian/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
        "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt",
        "https://easylist.to/easylist/easylist.txt",
        "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
        "https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt",
        "https://abpvn.com/filter/abpvn-IPl6HE.txt",
        "http://stanev.org/abp/adblock_bg.txt",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersABP-Inclusion.txt",
        "https://easylist-downloads.adblockplus.org/easylistchina.txt",
        "https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt",
        "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
        "https://easylist.to/easylistgermany/easylistgermany.txt",
        "https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt",
        "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
        "https://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt",
        "https://easylist-downloads.adblockplus.org/easylistpolish.txt",
        "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",
        "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
        "https://easylist-downloads.adblockplus.org/indianlist.txt",
        "https://easylist-downloads.adblockplus.org/koreanlist.txt",
        "https://raw.githubusercontent.com/Latvian-List/adblock-latvian/master/lists/latvian-list.txt",
        "https://easylist-downloads.adblockplus.org/Liste_AR.txt",
        "https://easylist-downloads.adblockplus.org/liste_fr.txt",
        "https://www.zoso.ro/pages/rolist.txt",
        "https://easylist-downloads.adblockplus.org/advblock.txt",
        "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    ]
    
    start_time = time.perf_counter()
    try:
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        
        elapsed = time.perf_counter() - start_time
        print(f"\n⏱️ الوقت الإجمالي: {elapsed:.2f} ثانية")
        
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
