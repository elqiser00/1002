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
USER_AGENT = "AdGuardHome-Filter-Merger/14.0"

def extract_domain(rule):
    """استخراج النطاق الأساسي من أي نوع من القواعد"""
    # 1. قواعد AdGuard الأساسية: ||example.com^
    if re.match(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^', rule, re.IGNORECASE):
        return re.match(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^', rule).group(0)[2:-1]
    
    # 2. قواعد الاستثناء: @@||example.com^
    elif re.match(r'^@@\|\|([a-z0-9-]+\.)+[a-z]{2,}\^', rule, re.IGNORECASE):
        return re.match(r'^@@\|\|([a-z0-9-]+\.)+[a-z]{2,}\^', rule).group(0)[4:-1]
    
    # 3. قواعد HOSTS: 127.0.0.1 example.com
    elif re.match(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}', rule, re.IGNORECASE):
        return rule.split()[1]
    
    # 4. قواعد DOMAIN: ||example.com
    elif re.match(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}(/|$)', rule, re.IGNORECASE):
        return re.match(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}', rule).group(0)[2:]
    
    # 5. قواعد DOMAIN-SUFFIX: .example.com
    elif re.match(r'^\.([a-z0-9-]+\.)+[a-z]{2,}', rule, re.IGNORECASE):
        return rule[1:]
    
    # 6. قواعد بسيطة بدون رمز: example.com
    elif re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', rule, re.IGNORECASE):
        return rule
    
    return None

def convert_to_adguard_home(rule):
    """تحويل أي قاعدة إلى صيغة AdGuard Home"""
    rule = rule.strip()
    
    # تجاهل التعليقات والأسطر الفارغة
    if not rule or rule.startswith(('!', '#', '[', '/', '&', '$')):
        return None
    
    # إذا كانت القاعدة بالفعل بصيغة AdGuard Home، احتفظ بها كما هي
    if re.fullmatch(r'^(@@\|\|)?\|\|([a-z0-9-]+\.)+[a-z]{2,}\^$', rule, re.IGNORECASE) or \
       re.fullmatch(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9-]+\.)+[a-z]{2,}$', rule, re.IGNORECASE):
        return rule
    
    # استخراج النطاق من القاعدة
    domain = extract_domain(rule)
    if not domain:
        return None
    
    # تحديد نوع القاعدة الأصلية لمعرفة إذا كانت استثناء
    is_exception = rule.startswith('@@') or \
                  (rule.startswith('/') and '@@' in rule) or \
                  (not rule.startswith(('||', '|', '.', '127.0.0.1', '0.0.0.0')) and 'whitelist' in rule.lower())
    
    # التحويل إلى صيغة AdGuard Home
    if is_exception:
        return f"@@||{domain}^"
    else:
        # 50% تحويل إلى ||domain^ و 50% إلى 127.0.0.1 domain
        if hash(domain) % 2 == 0:
            return f"||{domain}^"
        else:
            return f"127.0.0.1 {domain}"

def download_filter(url):
    """تحميل الفلتر مع تحويل جميع قواعده"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        
        valid_rules = []
        for line in response.text.splitlines():
            rule = convert_to_adguard_home(line)
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
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر (سيتم تحويل جميع القواعد إلى صيغة AdGuard Home)...")
    
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
    
    # ترتيب النتائج: الاستثناءات أولاً
    return sorted(results, key=lambda x: (not x.startswith('@@'), x))

def save_filters(rules, output_dir="adguard_home_filters"):
    """حفظ القواعد بصيغة AdGuard Home"""
    os.makedirs(output_dir, exist_ok=True)
    
    main_file = os.path.join(output_dir, "adguard_home_rules.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! قواعد AdGuard Home المدمجة\n")
        f.write("! تم إنشاؤها تلقائياً من مصادر متعددة\n")
        f.write("! التاريخ: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
        f.write("\n".join(rules))
    
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في {main_file}")
    
    # التقسيم التلقائي إذا لزم الأمر
    if len(rules) > MAX_LINES_PER_PART:
        parts = (len(rules) // MAX_LINES_PER_PART) + 1
        print(f"📦 تقسيم إلى {parts} أجزاء...")
        
        for i in range(parts):
            part_file = os.path.join(output_dir, f"adguard_home_rules_part_{i+1}.txt")
            with open(part_file, 'w', encoding='utf-8') as f:
                start = i * MAX_LINES_PER_PART
                end = start + MAX_LINES_PER_PART
                f.write("\n".join(rules[start:end]))
            
            print(f"✅ الجزء {i+1}: {len(rules[start:end])} قاعدة")

if __name__ == "__main__":
    # يمكنك إضافة أي مصادر هنا، حتى لو كانت لإضافات المتصفح
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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_64.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
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
    "https://filters.adtidy.org/android/filters/1_optimized.txt",
    "https://filters.adtidy.org/android/filters/4_optimized.txt",
    "https://filters.adtidy.org/android/filters/6_optimized.txt",
    "https://filters.adtidy.org/android/filters/7_optimized.txt",
    "https://filters.adtidy.org/android/filters/8_optimized.txt",
    "https://filters.adtidy.org/android/filters/9_optimized.txt",
    "https://filters.adtidy.org/android/filters/11_optimized.txt",
    "https://filters.adtidy.org/android/filters/13_optimized.txt",
    "https://filters.adtidy.org/android/filters/14_optimized.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt",
    "https://filters.adtidy.org/android/filters/16_optimized.txt",
    "https://filters.adtidy.org/android/filters/17_optimized.txt",
    "https://filters.adtidy.org/android/filters/18_optimized.txt",
    "https://filters.adtidy.org/android/filters/19_optimized.txt",
    "https://filters.adtidy.org/android/filters/20_optimized.txt",
    "https://filters.adtidy.org/android/filters/21_optimized.txt",
    "https://filters.adtidy.org/android/filters/22_optimized.txt",
    "https://filters.adtidy.org/android/filters/23_optimized.txt",
    "https://filters.adtidy.org/android/filters/224_optimized.txt",
    "https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    "https://easylist.to/easylistgermany/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/liste_fr.txt",
    "https://adblock.gardar.net/is.abp.txt",
    "https://www.void.gr/kargig/void-gr-filters.txt",
    "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",
    "https://raw.githubusercontent.com/gioxx/xfiles/master/filtri.txt",
    "https://easylist-downloads.adblockplus.org/cntblock.txt",
    "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/cookies_filters/adblock_cookies.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",
    "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/adblock_social_filters/adblock_social_list.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://raw.githubusercontent.com/FiltersHeroes/KAD/master/KAD.txt",
    "https://www.zoso.ro/pages/rolist2.txt",
    "https://raw.githubusercontent.com/tcptomato/ROad-Block/master/road-block-filters-light.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/PolishAnnoyanceFilters/master/PPB.txt",
    "https://raw.githubusercontent.com/yous/YousList/master/youslist.txt",
    "https://easylist-downloads.adblockplus.org/easylistpolish.txt",
    "https://raw.githubusercontent.com/FiltersHeroes/PolishAntiAnnoyingSpecialSupplement/master/polish_rss_filters.txt",
    "https://stanev.org/abp/adblock_bg.txt",
    "https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt",
    "https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt",
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    "https://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt",
    "https://raw.githubusercontent.com/Latvian-List/adblock-latvian/master/lists/latvian-list.txt",
    "https://raw.githubusercontent.com/realodix/AdBlockID/main/dist/adblockid.adfl.txt",
    "https://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt",
    "https://cdn.jsdelivr.net/gh/hufilter/hufilter@gh-pages/hufilter-adguard.txt",
    "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_adguard.txt",
    "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt",
    "https://cdn.jsdelivr.net/gh/List-KR/List-KR@latest/filter-AdGuard.txt",
    "https://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/gh-pages/Finland_adb.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlocker.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/master/anti-adblock.txt",
    "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/SerboCroatianList.txt",
    "https://easylist-downloads.adblockplus.org/indianlist.txt",
    "https://raw.githubusercontent.com/RandomAdversary/Macedonian-adBlock-Filters/master/Filters",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersAdGuard.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://easylist.to/easylist/fanboy-social.txt",
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
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt",
    "https://dnsforge.de/blocklist.list",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "https://big.oisd.nl/",
    "https://blocklistproject.github.io/Lists/basic.txt",
    "https://blocklistproject.github.io/Lists/phishing.txt",
    "https://blocklistproject.github.io/Lists/ransomware.txt",
    "https://blocklistproject.github.io/Lists/tracking.txt",
    "https://hole.cert.pl/domains/v2/domains.txt",
    "https://o0.pages.dev/Lite/adblock.txt",
    "https://perflyst.github.io/PiHoleBlocklist/AmazonFireTV.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.amazon.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.apple.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.huawei.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.winoffice.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.lgwebos.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.xiaomi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.oppo-realme.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.vivo.txt",
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/quad9_blocklist.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
    "https://raw.githubusercontent.com/RealEnder/adblockbg/refs/heads/master/adblockbg.txt",
    "https://raw.githubusercontent.com/easylist/listear/refs/heads/master/Liste_AR.txt",
    "https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/refs/heads/master/filters.txt",
    "https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/refs/heads/master/filters_ublock.txt",
    "https://raw.githubusercontent.com/easylist/EasyListHebrew/refs/heads/master/EasyListHebrew.txt",
    "https://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/refs/heads/master/easylistlithuania.txt",
    "https://raw.githubusercontent.com/Latvian-List/adblock-latvian/refs/heads/master/lists/latvian-list.txt",
    "https://cdn.jsdelivr.net/gh/realodix/AdBlockID@master/dist/adblockid.adfl.txt",
    "https://cdn.jsdelivr.net/gh/realodix/AdBlockID@master/dist/adblockid_plus.adfl.txt",
    "https://abpvn.com/filter/abpvn-MKpIlo.txt",
    "https://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/refs/heads/master/Finland_adb.txt",
    "https://adblock.ee/list.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlocker-Deprecated.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlocker.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerAds-Domains.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerAds.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerAnnoyances-Domains.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerAnnoyances.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerCensor-Domains.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerCensor.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerHalfPrice.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerHosts.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerMobile.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerTrackers-Domains.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/refs/heads/main/PersianBlockerTrackers.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/refs/heads/master/adblock-suplement.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/refs/heads/master/adblock.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/refs/heads/master/anti-adblock-suplement-adguard.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/refs/heads/master/anti-adblock-suplement.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/refs/heads/master/anti-adblock.txt",
    "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/refs/heads/master/Frellwits-Swedish-Filter.txt",
    "https://raw.githubusercontent.com/DeepSpaceHarbor/Macedonian-adBlock-Filters/refs/heads/master/Filters",
    ]
    
    start_time = time.time()
    try:
        print("🚀 بدء عملية تحويل القواعد إلى صيغة AdGuard Home...")
        rules = process_filters(FILTER_URLS)
        save_filters(rules)
        print(f"\n⏱️ الوقت الإجمالي: {time.time() - start_time:.2f} ثانية")
        print("✨ تم تحويل جميع القواعد بنجاح إلى صيغة AdGuard Home!")
    except Exception as e:
        print(f"❌ خطأ: {str(e)}")
