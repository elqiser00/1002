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
USER_AGENT = "AdGuardHome-Filter-Merger/4.0"

def convert_rule(line):
    """
    تحويل جميع أنواع القواعد إلى صيغة AdGuard الموحدة
    يدعم:
    - قواعد AdGuard (||example.org^، @@||example.org^)
    - قواعد DNS (127.0.0.1 example.org)
    - قواعد Regex (/regex/)
    """
    line = line.strip()
    
    # تجاهل التعليقات
    if line.startswith(('!', '#')):
        return None
    
    # 1. إذا كانت قاعدة AdGuard (موجودة بالفعل)
    if (line.startswith(('||', '@@||')) and line.endswith('^')):
        return line
    
    # 2. قواعد DNS (127.0.0.1 example.org)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+[a-z0-9-]+\.[a-z]{2,}$', line):
        domain = line.split()[1]
        return f"||{domain}^"  # تحويل إلى حظر كامل مع subdomains
    
    # 3. قواعد Regex
    if line.startswith('/') and line.endswith('/'):
        # تحويل Regex البسيط إلى دومين
        match = re.search(r'([a-z0-9-]+\.[a-z]{2,})', line[1:-1])
        if match:
            domain = match.group(1)
            if line.startswith('/@@/'):  # استثناء
                return f"@@||{domain}^"
            return f"||{domain}^"
    
    # 4. قواعد أخرى غير مدعومة
    return None

def is_valid_filter(line):
    """التحقق من صحة السطر مع تطبيق التحويلات"""
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return False
    
    # تجاهل التعليقات والبيانات الوصفية
    if line.startswith(('[', '&', '!', '#')):
        return False
    
    # تجاهل الأنماط غير المدعومة
    if any(patt in line for patt in ('##', '#@#', '!#', '##^')):
        return False
    
    return True

def normalize_filter(line):
    """توحيد صيغة السطر"""
    return line.strip().replace('\r', '').replace('\t', ' ').replace('  ', ' ')

def process_line(raw_line):
    """معالجة كل سطر وتطبيق التحويلات"""
    normalized = normalize_filter(raw_line)
    if not is_valid_filter(normalized):
        return None
    
    # تطبيق التحويلات
    converted = convert_rule(normalized)
    return converted if converted else normalized if is_valid_filter(normalized) else None

def download_filter(url):
    """تحميل الفلتر مع المعالجة الأولية"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        
        processed_lines = []
        for line in response.text.splitlines():
            processed = process_line(line)
            if processed:
                processed_lines.append(processed)
                
        return processed_lines, url
    except Exception as e:
        print(f"⚠️ خطأ في تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """معالجة جميع الفلاتر مع إزالة التكرارات"""
    seen_domains = set()
    unique_rules = []
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            lines, url = future.result()
            domain = urlparse(url).netloc
            print(f"📊 [{i}/{total_urls}] معالجة: {domain} ({len(lines)} قاعدة)")
            
            for line in lines:
                # استخراج الدومين الأساسي للتكرار
                domain_match = re.match(r'^(?:@@\|\|)?\|?\|?([a-z0-9-]+\.[a-z]{2,})\^', line)
                if domain_match:
                    domain_key = domain_match.group(1)
                    if domain_key in seen_domains:
                        continue
                    seen_domains.add(domain_key)
                
                unique_rules.append(line)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    return unique_rules

def save_filters(rules, output_dir="merged_filters"):
    """حفظ القواعد مع التقسيم والترتيب"""
    os.makedirs(output_dir, exist_ok=True)
    
    # فرز القواعد: استثناءات أولاً، ثم الحظر
    exceptions = [r for r in rules if r.startswith('@@')]
    blocks = [r for r in rules if not r.startswith('@@')]
    sorted_rules = exceptions + blocks
    
    # حفظ الملف الرئيسي
    main_file = os.path.join(output_dir, "adguard_rules.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted_rules))
    
    print(f"\n✅ تم حفظ {len(sorted_rules)} قاعدة في {main_file}")
    
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

def main(filter_urls):
    """الدالة الرئيسية"""
    start_time = time.perf_counter()
    
    try:
        print("🛠️ بدء عملية دمج الفلاتر...")
        rules = process_filters(filter_urls)
        save_filters(rules)
        
        elapsed = time.perf_counter() - start_time
        stats = {
            "إجمالي القواعد": len(rules),
            "قواعد الاستثناء": len([r for r in rules if r.startswith('@@')]),
            "قواعد الحظر": len([r for r in rules if not r.startswith('@@')]),
            "الوقت المستغرق": f"{elapsed:.2f} ثانية",
            "السرعة": f"{len(rules)/max(elapsed, 1):.1f} قاعدة/ثانية",
            "نطاقات فريدة": len(set(re.match(r'^(?:@@\|\|)?\|?\|?([a-z0-9-]+\.[a-z]{2,})\^', r).group(1) for r in rules if re.match(r'^(?:@@\|\|)?\|?\|?([a-z0-9-]+\.[a-z]{2,})\^', r)))
        }
        
        print("\n📊 الإحصائيات النهائية:")
        for k, v in stats.items():
            print(f"- {k}: {v}")
            
    except KeyboardInterrupt:
        print("\n⏹ تم إيقاف العملية بواسطة المستخدم")
    except Exception as e:
        print(f"❌ خطأ غير متوقع: {str(e)}")

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
    
    main(FILTER_URLS)
