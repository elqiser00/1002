import requests
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# إعدادات التكوين
REQUEST_TIMEOUT = 45
REQUEST_DELAY = 0.3
MAX_WORKERS = 5
USER_AGENT = "AdGuardHome-Filter-Merger/3.0"

def is_valid_filter(line):
    """تحقق من صحة سطر الفلتر"""
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return False
    return True

def extract_domain(rule):
    """استخراج الدومين من القاعدة بشكل آمن"""
    try:
        rule = rule.strip()
        
        # معالجة قواعد الاستثناءات (@@)
        if rule.startswith('@@'):
            if rule.startswith('@@||') and '^' in rule:
                domain = rule[4:rule.index('^')].lower()
                return domain, 'allowed'
            elif rule.startswith('@@http://'):
                return rule[8:].split('/')[0].lower(), 'allowed'
            elif rule.startswith('@@https://'):
                return rule[9:].split('/')[0].lower(), 'allowed'
        
        # معالجة قواعد الحظر
        elif rule.startswith('||') and '^' in rule:
            domain = rule[2:rule.index('^')].lower()
            return domain, 'blocked'
        elif rule.startswith(('http://', 'https://')):
            domain = rule.split('/')[2].lower()
            return domain, 'blocked'
        elif '://' in rule:
            domain = rule.split('/')[2].lower()
            return domain, 'blocked'
            
    except Exception as e:
        print(f"⚠️ خطأ في معالجة القاعدة: {rule[:50]}...")
        return None, None
    
    return None, None

def download_filter(url):
    """تحميل الفلتر مع معالجة الأخطاء"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        return response.text.splitlines(), url
    except Exception as e:
        print(f"⚠️ فشل تحميل {urlparse(url).netloc}: {str(e)}")
        return [], url

def process_filters(urls):
    """معالجة الفلاتر وتصنيف الدومينات"""
    allowed_domains = set()
    blocked_domains = set()
    total_urls = len(urls)
    
    print(f"🔍 بدء معالجة {total_urls} مصدر فلتر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            lines, url = future.result()
            domain = urlparse(url).netloc
            print(f"📊 [{i}/{total_urls}] معالجة: {domain} ({len(lines)} سطر)")
            
            for line in lines:
                if not is_valid_filter(line):
                    continue
                
                domain_name, domain_type = extract_domain(line)
                if domain_name:
                    if domain_type == 'allowed':
                        allowed_domains.add(domain_name)
                        blocked_domains.discard(domain_name)
                    elif domain_type == 'blocked' and domain_name not in allowed_domains:
                        blocked_domains.add(domain_name)
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    return sorted(allowed_domains), sorted(blocked_domains)

def save_domains(allowed, blocked, output_dir="filtered_domains"):
    """حفظ الدومينات في ملفات منفصلة"""
    os.makedirs(output_dir, exist_ok=True)
    
    allowed_file = os.path.join(output_dir, "allowed_domains.txt")
    with open(allowed_file, 'w', encoding='utf-8') as f:
        f.write("# قائمة الدومينات المسموحة (الاستثناءات)\n")
        f.write(f"# تم الإنشاء: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("\n".join(allowed))
    
    blocked_file = os.path.join(output_dir, "blocked_domains.txt")
    with open(blocked_file, 'w', encoding='utf-8') as f:
        f.write("# قائمة الدومينات المحظورة\n")
        f.write(f"# تم الإنشاء: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("\n".join(blocked))
    
    print(f"\n✅ تم الحفظ بنجاح:\n- الدومينات المسموحة: {len(allowed)} دومين ({allowed_file})\n- الدومينات المحظورة: {len(blocked)} دومين ({blocked_file})")

def main(filter_urls):
    """الدالة الرئيسية"""
    start_time = time.time()
    
    try:
        allowed, blocked = process_filters(filter_urls)
        save_domains(allowed, blocked)
        
        elapsed = time.time() - start_time
        print(f"\n⏱ وقت التنفيذ: {elapsed:.2f} ثانية")
        print(f"📊 الإحصائيات النهائية:")
        print(f"- مجموع الدومينات المسموحة: {len(allowed)}")
        print(f"- مجموع الدومينات المحظورة: {len(blocked)}")
        print(f"- إجمالي الدومينات المعالجة: {len(allowed)+len(blocked)}")
        
    except Exception as e:
        print(f"\n❌ حدث خطأ: {str(e)}")

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
        "https://raw.githubusercontent.com/elqiser00/1002/refs/heads/main/filters/whitelist.txt",
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
