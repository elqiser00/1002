import requests
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# إعدادات التكوين
MAX_LINES_PER_PART = 2_000_000  # الحد الأقصى للأسطر في كل جزء
MAX_LINE_LENGTH = 5000  # الحد الأقصى لطول السطر
REQUEST_TIMEOUT = 45  # وقت انتظار الطلب
REQUEST_DELAY = 0.3  # تأخير بين الطلبات
MAX_WORKERS = 5  # الحد الأقصى لعدد العمال
USER_AGENT = "AdGuardHome-Filter-Merger/3.0"  # وكيل المستخدم

def is_valid_filter(line):
    """تحقق من صحة سطر الفلتر مع تجاهل الترويسات والتعليقات"""
    line = line.strip()
    if not line:
        return False
    
    # تجاهل جميع أنواع الترويسات والتعليقات
    if line.startswith(('!', '#', '@@', '[', '&', '/')):
        return False
    
    # تجاهل بعض الأنماط غير المدعومة
    invalid_patterns = ('##', '#@#', '!#', '##^')
    if any(pattern in line for pattern in invalid_patterns):
        return False
    
    return len(line) <= MAX_LINE_LENGTH

def normalize_filter(line):
    """تنظيف بسيط للسطر مع الحفاظ على الهيكل الأصلي"""
    return line.strip().replace('\r', '').replace('\t', ' ').replace('  ', ' ')

def is_adguard_home_domain_rule(line):
    """تحقق إذا كان السطر قاعدة دومين لـ AdGuard Home"""
    return line.startswith('||') and line.endswith('^') and not any(c in line for c in ['/', '*', '?', '='])

def extract_domain_from_rule(line):
    """استخراج الدومين من قاعدة AdGuard Home"""
    if is_adguard_home_domain_rule(line):
        return line[2:-1].lower()
    return None

def download_filter(url):
    """تحميل الفلتر مع تصفية التعليقات"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        
        # تصفية السطور وإزالة التعليقات
        filtered_lines = []
        for line in response.text.splitlines():
            if is_valid_filter(line):
                filtered_lines.append(line)
                
        return filtered_lines, url
    except Exception as e:
        print(f"⚠️ فشل تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """معالجة الفلاتر مع إزالة التكرار الحرفي وتكرار دومينات AdGuard Home"""
    seen_filters = set()
    seen_domains = set()
    unique_filters = []
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            lines, url = future.result()
            domain = urlparse(url).netloc
            print(f"📊 [{i}/{total_urls}] معالجة: {domain} ({len(lines)} سطر بعد التصفية)")
            
            for line in lines:
                normalized = normalize_filter(line)
                
                # معالجة خاصة لقواعد دومينات AdGuard Home
                rule_domain = extract_domain_from_rule(normalized)
                if rule_domain:
                    if rule_domain in seen_domains:
                        continue  # تخطي إذا كان الدومين متكرراً
                    seen_domains.add(rule_domain)
                
                if normalized not in seen_filters:
                    seen_filters.add(normalized)
                    unique_filters.append(normalized)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    return unique_filters

def save_filters(filters, output_dir="merged_filters"):
    """حفظ الفلاتر مع تقسيمها إذا لزم الأمر"""
    os.makedirs(output_dir, exist_ok=True)
    
    # ملف واحد يحتوي على جميع الفلاتر (دائماً)
    all_filters_file = os.path.join(output_dir, "all_filters.txt")
    with open(all_filters_file, 'w', encoding='utf-8') as f:
        # ترويسة أساسية مختصرة
        f.write("! Title: All Merged Filters (Cleaned)\n")
        f.write("! Updated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("! Total filters: " + str(len(filters)) + "\n\n")
        f.write("\n".join(filters))
    
    print(f"\n✅ تم حفظ جميع الفلاتر ({len(filters)} سطر) في {all_filters_file}")
    
    # إذا تجاوز عدد الأسطر الحد الأقصى، نقوم بالتقسيم
    if len(filters) > MAX_LINES_PER_PART:
        parts = (len(filters) // MAX_LINES_PER_PART) + 1
        print(f"\n📦 سيتم تقسيم الفلاتر إلى {parts} أجزاء (كل جزء {MAX_LINES_PER_PART} سطر)")
        
        for i in range(parts):
            start = i * MAX_LINES_PER_PART
            end = start + MAX_LINES_PER_PART
            part_file = os.path.join(output_dir, f"filters_part_{i+1}.txt")
            
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write("! Title: Merged Filters Part {}\n".format(i+1))
                f.write("! Updated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                f.write("! Filters: {}-{}\n\n".format(start+1, min(end, len(filters))))
                f.write("\n".join(filters[start:end]))
            
            print(f"✅ تم حفظ الجزء {i+1}: {len(filters[start:end])} سطر ({part_file})")

def main(filter_urls):
    """الدالة الرئيسية"""
    start_time = time.perf_counter()
    
    try:
        filters = process_filters(filter_urls)
        save_filters(filters)
        
        elapsed = time.perf_counter() - start_time
        stats = {
            "total_filters": len(filters),
            "time_elapsed": f"{elapsed:.2f} ثانية",
            "avg_speed": f"{len(filters)/max(elapsed, 1):.1f} قاعدة/ثانية",
            "unique_domains": len({extract_domain_from_rule(f) for f in filters if extract_domain_from_rule(f)})
        }
        
        print("\n📊 إحصائيات الأداء النهائية:")
        for k, v in stats.items():
            print(f"- {k.replace('_', ' ').title()}: {v}")
            
    except KeyboardInterrupt:
        print("\n⏹ تم إيقاف العملية بواسطة المستخدم")
    except Exception as e:
        print(f"❌ خطأ غير متوقع: {str(e)}")

if __name__ == "__main__":
    # قائمة المصادر (يجب وضعها هنا كما هي)
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
