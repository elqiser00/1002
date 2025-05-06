import requests
import os
import time
import re

# جميع الروابط
urls = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",
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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    "https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt",
    "https://abpvn.com/filter/abpvn-IPl6HE.txt",
    "https://easylist-downloads.adblockplus.org/Liste_AR.txt",
    "https://www.zoso.ro/pages/rolist.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance_ubo.txt",
    "https://www.fanboy.co.nz/fanboy-cookiemonster.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/AnnoyancesList",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://urlhaus-filter.pages.dev/urlhaus-filter-ag-online.txt",
    "https://fanboy.co.nz/fanboy-antifonts.txt",
    "https://www.fanboy.co.nz/fanboy-antifacebook.txt",
    "https://filters.adtidy.org/android/filters/1_optimized.txt",
    "https://filters.adtidy.org/android/filters/3_optimized.txt",
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
    "https://userscripts.adtidy.org/release/adguard-extra/1.0/adguard-extra.user.js",
    "https://userscripts.adtidy.org/release/adguard-extra/1.0/adguard-extra.meta.js",
    "https://userscripts.adtidy.org/release/disable-amp/1.0/disable-amp.user.js",
    "https://userscripts.adtidy.org/release/disable-amp/1.0/disable-amp.meta.js",
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
    "https://adblock.ee/list.txt",
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
    "https://raw.githubusercontent.com/elqiser00/1002/refs/heads/main/filters/merged-filters.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
]

# إعدادات
MAX_LINES_PER_FILE = 2_000_000  # أقصى عدد قواعد في كل ملف
MAX_LINE_LENGTH = 5000  # الحد الأقصى لطول السطر
REQUEST_DELAY = 0.2  # تأخير بين الطلبات (بالثواني)
OUTPUT_DIR = "merged_filters"  # مجلد الإخراج

def smart_split(line):
    """
    تقسيم ذكي للقواعد الطويلة مع الحفاظ على البنية
    """
    if len(line) <= MAX_LINE_LENGTH:
        return [line]
    
    # الحفاظ على تعليقات AdGuard الخاصة
    if line.startswith(('!', '#', '@@', '%%')):
        return [line]
    
    # معالجة أنواع القواعد المختلفة
    if line.startswith('||') and line.endswith('^'):
        domains = line[2:-1].split('|')
        return [f'||{"|".join(domains[i:i+50])}^' for i in range(0, len(domains), 50)]
    
    elif '##' in line or '#@#' in line:
        return [line]  # لا تقسم قواعد العناصر
    
    elif '$' in line:
        pattern, options = line.rsplit('$', 1)
        return [f'{pattern}${options}']
    
    elif ',' in line:
        parts = line.split(',')
        return [','.join(parts[i:i+100]) for i in range(0, len(parts), 100)]
    
    return [line[i:i+MAX_LINE_LENGTH] for i in range(0, len(line), MAX_LINE_LENGTH)]

def is_valid_rule(rule):
    """
    التحقق من صحة القاعدة الأساسية
    """
    if not rule.strip():
        return False
    if re.search(r'[\s\'"]', rule):
        return False
    return True

def process_filters():
    """
    العملية الرئيسية لمعالجة الفلاتر
    """
    all_rules = set()
    metadata = []
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    for url in urls:
        try:
            print(f"⏳ جاري تحميل: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                clean_line = line.strip()
                
                # الاحتفاظ بالتعليقات وبيانات الميتا
                if not clean_line or clean_line.startswith(('!', '#', '@@', '%%')):
                    metadata.append(clean_line)
                    continue
                
                # معالجة القواعد الفعلية
                if is_valid_rule(clean_line):
                    for split_rule in smart_split(clean_line):
                        all_rules.add(split_rule)
            
            time.sleep(REQUEST_DELAY)
        except Exception as e:
            print(f"❌ خطأ في تحميل {url}: {str(e)}")
    
    # تحويل إلى قائمة وترتيب
    all_rules = sorted(list(all_rules))
    total_rules = len(all_rules)
    print(f"✅ تم تجهيز {total_rules} قاعدة فريدة مع {len(metadata)} سطر وصفية.")
    
    # حفظ الملف الكامل مع البيانات الوصفية
    full_output_path = os.path.join(OUTPUT_DIR, "all_filters.txt")
    with open(full_output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(metadata + all_rules))
    print(f"💾 تم حفظ الملف الكامل في: {full_output_path}")
    
    # تقسيم إلى ملفات أصغر
    file_count = 1
    for i in range(0, total_rules, MAX_LINES_PER_FILE):
        chunk = all_rules[i:i + MAX_LINES_PER_FILE]
        part_path = os.path.join(OUTPUT_DIR, f"filters_part_{file_count}.txt")
        
        with open(part_path, "w", encoding="utf-8") as f:
            f.write("\n".join(metadata + chunk))
        
        print(f"📦 تم إنشاء ملف الجزء {file_count}: {part_path} ({len(chunk)} قاعدة)")
        file_count += 1
    
    print("🎉 اكتملت العملية بنجاح!")

if __name__ == "__main__":
    process_filters()
