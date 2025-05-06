import requests
import os
import time
import re

# جميع الروابط
urls = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
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
]

# إعدادات
MAX_LINES_PER_FILE = 2_000_000
REQUEST_DELAY = 0.2
OUTPUT_DIR = "adguard_clean_filters"

def is_real_rule(line):
    """
    تحديد إذا كان السطر قاعدة حقيقية لـ AdGuard Home وليس تعليقًا
    """
    line = line.strip()
    
    # تجاهل الخطوط الفارغة والتعليقات البسيطة
    if not line or line.startswith(('! ', '# ', '! Title:', '! Description:')):
        return False
    
    # قواعد النطاقات (تبدأ بـ || أو @@||)
    if re.match(r'^(@@)?\|\|[\w\-\.]+\^?', line):
        return True
    
    # قواعد عناصر الـ CSS/JS (تبدأ بـ ## أو #@# أو @@##)
    if re.match(r'^(@@)?#@?#[\w\-\.#]', line):
        return True
    
    # قواعد الـ Hosts (عنوان IP ثم نطاق)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+[\w\-\.]+', line):
        return True
    
    # القواعد المعتمدة على regex (بين //)
    if re.match(r'^/.*/', line):
        return True
    
    # القواعد الخاصة (تبدأ بـ %% أو $$$)
    if line.startswith(('%%', '$$$')):
        return True
    
    # قواعد الاستثناءات الخاصة
    if line.startswith('@@') and not line.startswith('@@ '):
        return True
    
    # قواعد التعديلات (تحتوي على $ ولكن ليس في البداية)
    if re.search(r'\$[a-z]+(=[^,\s]+)?(,|$)', line):
        return True
    
    return False

def clean_rule(rule):
    """
    تنظيف القاعدة من أي تعليقات جانبية
    """
    # إزالة التعليقات بعد علامة : أو ;
    rule = re.split(r'[:;]', rule)[0].strip()
    
    # إزالة المسافات الزائدة
    return ' '.join(rule.split())

def process_filters():
    """
    العملية الرئيسية لتنظيف الفلاتر
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    unique_rules = set()
    
    for url in urls:
        try:
            print(f"⏳ جاري تحميل: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                if is_real_rule(line):
                    cleaned = clean_rule(line)
                    if cleaned:
                        unique_rules.add(cleaned)
            
            time.sleep(REQUEST_DELAY)
        except Exception as e:
            print(f"❌ خطأ في تحميل {url}: {str(e)}")
    
    # حفظ النتائج
    sorted_rules = sorted(unique_rules)
    output_file = os.path.join(OUTPUT_DIR, "adguard_rules.txt")
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted_rules))
    
    print(f"✅ تم حفظ {len(sorted_rules)} قاعدة فلترة في {output_file}")
    print("🎉 تم الانتهاء بنجاح مع الحفاظ على جميع أنواع قواعد AdGuard Home!")

if __name__ == "__main__":
    process_filters()
