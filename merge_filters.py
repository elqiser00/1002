#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home Filter Merger
مزيل التكرار الحرفي للقواعد مع الحفاظ على جميع الأشكال المختلفة
"""

import requests
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# إعدادات التكوين
MAX_LINES_PER_FILE = 1_500_000
MAX_LINE_LENGTH = 5000
REQUEST_TIMEOUT = 45
REQUEST_DELAY = 0.3
MAX_WORKERS = 5
USER_AGENT = "AdGuardHome-Filter-Merger/2.0"

def is_valid_filter(line):
    """تحقق من صحة سطر الفلتر"""
    line = line.strip()
    if not line:
        return False
    
    ignore_prefixes = ('!', '#', '@@', '[', '&', '/')
    if line.startswith(ignore_prefixes):
        return False
    
    invalid_patterns = ('##', '#@#', '!#', '##^')
    if any(pattern in line for pattern in invalid_patterns):
        return False
    
    return len(line) <= MAX_LINE_LENGTH

def normalize_filter(line):
    """تنظيف بسيط للسطر دون تغيير هيكل القاعدة"""
    return line.strip().replace('\r', '').replace('\t', ' ').replace('  ', ' ')

def download_filter(url):
    """تحميل الفلتر"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        return response.text.splitlines(), url
    except Exception as e:
        print(f"⚠️ فشل تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """معالجة الفلاتر مع إزالة التكرار الحرفي فقط"""
    unique_filters = set()
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            lines, url = future.result()
            domain = urlparse(url).netloc
            print(f"📊 [{i}/{total_urls}] معالجة: {domain} ({len(lines)} سطر)")
            
            for line in lines:
                if is_valid_filter(line):
                    normalized = normalize_filter(line)
                    unique_filters.add(normalized)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    return sorted(unique_filters, key=lambda x: (
        not x.startswith('||'),
        not x.startswith('||*'),
        not x.startswith('|'),
        x.lower()
    ))

def save_filters(filters, output_dir="merged_filters"):
    """حفظ الفلاتر"""
    os.makedirs(output_dir, exist_ok=True)
    
    main_file = os.path.join(output_dir, "all_filters.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: Merged Filters (Optimized)\n")
        f.write("! Description: Combined filters for AdGuardHome\n")
        f.write("! Version: " + time.strftime("%Y%m%d") + "\n")
        f.write("! Last updated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
        f.write("\n".join(filters))
    
    print(f"✅ تم حفظ {len(filters)} فلتر في {main_file}")
    
    if len(filters) > MAX_LINES_PER_FILE:
        parts = (len(filters) // MAX_LINES_PER_FILE) + 1
        for i in range(parts):
            start = i * MAX_LINES_PER_FILE
            end = start + MAX_LINES_PER_FILE
            part_file = os.path.join(output_dir, f"filters_part_{i+1}.txt")
            
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(filters[start:end]))
            
            print(f"📦 الجزء {i+1}: {len(filters[start:end])} قاعدة ({part_file})")

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
            "avg_speed": f"{len(filters)/max(elapsed, 1):.1f} قاعدة/ثانية"
        }
        
        print("\n📊 إحصائيات الأداء:")
        for k, v in stats.items():
            print(f"- {k.replace('_', ' ').title()}: {v}")
            
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
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt",
        "https://raw.githubusercontent.com/elqiser00/1002/refs/heads/main/filters/BlackList.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
        "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
  ]
    
    main(FILTER_URLS)
