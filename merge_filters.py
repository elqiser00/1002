import requests
import os
import time
from urllib.parse import urlparse

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

# إعدادات التكوين
MAX_LINES_PER_FILE = 1_000_000  # تقليل الحد الأقصى لتحسين الأداء
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 30
REQUEST_DELAY = 0.5  # زيادة التأخير بين الطلبات
USER_AGENT = "AdGuardHome-Filter-Merger/1.0"

def is_valid_filter_line(line):
    """تحقق مما إذا كان السطر صالحًا للفلترة"""
    line = line.strip()
    return (
        line and
        not line.startswith(('!', '#', '@@', '/')) and
        not line.startswith(('[', '&', '~')) and
        not line.startswith(('www.', 'http://', 'https://')) and
        '##' not in line and
        '#@#' not in line and
        len(line) <= MAX_LINE_LENGTH
    )

def normalize_filter_line(line):
    """توحيد تنسيق سطر الفلتر"""
    return line.strip().replace('\r', '').replace('\t', ' ')

def download_filter(url):
    """تحميل فلتر من URL مع التعامل مع الأخطاء"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"❌ خطأ في تحميل {url}: {str(e)}")
        return []

def process_filters():
    """معالجة الفلاتر الرئيسية"""
    unique_lines = set()
    total_urls = len(FILTER_URLS)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    for index, url in enumerate(FILTER_URLS, 1):
        domain = urlparse(url).netloc
        print(f"⏳ [{index}/{total_urls}] جاري تحميل من {domain}...")
        
        lines = download_filter(url)
        for line in lines:
            if is_valid_filter_line(line):
                normalized = normalize_filter_line(line)
                unique_lines.add(normalized)
        
        if index < total_urls:  # لا تأخير بعد آخر طلب
            time.sleep(REQUEST_DELAY)
    
    return sorted(unique_lines, key=lambda x: (x.startswith('||'), reverse=True)

def save_filters(filters, output_dir="merged_filters"):
    """حفظ الفلاتر في ملفات"""
    os.makedirs(output_dir, exist_ok=True)
    
    # ملف شامل
    all_filters_path = os.path.join(output_dir, "all_filters.txt")
    with open(all_filters_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(filters))
    print(f"✅ تم حفظ {len(filters)} فلتر في {all_filters_path}")
    
    # تقسيم إلى ملفات أصغر إذا لزم الأمر
    if len(filters) > MAX_LINES_PER_FILE:
        file_count = (len(filters) // MAX_LINES_PER_FILE) + 1
        for i in range(file_count):
            start_idx = i * MAX_LINES_PER_FILE
            end_idx = start_idx + MAX_LINES_PER_FILE
            chunk = filters[start_idx:end_idx]
            
            part_path = os.path.join(output_dir, f"filters_part_{i+1}.txt")
            with open(part_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(chunk))
            print(f"📦 تم حفظ الجزء {i+1} ({len(chunk)} فلتر) في {part_path}")

def main():
    start_time = time.time()
    
    filters = process_filters()
    save_filters(filters)
    
    elapsed = time.time() - start_time
    print(f"🎉 تم الانتهاء في {elapsed:.2f} ثانية")
    print(f"📊 الإجمالي النهائي: {len(filters)} قاعدة فلترة فريدة")

if __name__ == "__main__":
    main()
