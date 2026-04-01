import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 60
REQUEST_DELAY = 0.5
MAX_WORKERS = 10
USER_AGENT = "AdGuard-Merger/14.0"

def clean_rule(line):
    """استخراج النطاق فقط وإزالة أي شروط أو أحرف غير مرغوب فيها"""
    original = line.strip()
    if not original or original.startswith(('!', '#')):
        return None, False

    is_exception = original.startswith('@@')
    # إزالة @@
    clean = original[2:] if is_exception else original

    # إزالة أي شيء بعد $ أو / (الشروط)
    # نقسم على $ ونأخذ الجزء الأول
    clean = clean.split('$')[0]
    # إذا كان هناك /، نأخذ الجزء الأول
    clean = clean.split('/')[0]

    # البحث عن نطاق صالح: يجب أن يحتوي على نقطة على الأقل وألا يبدأ برقم متبوع بشرطة
    # نمط النطاق: حرف (أو رقم) متبوعًا بنقاط وشرطات، وينتهي بـ TLD حروف
    match = re.search(r'([a-z0-9][a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]{2,}|[a-z0-9][a-z0-9\-]*\.[a-z]{2,})', clean, re.IGNORECASE)
    if not match:
        return None, False

    domain = match.group(1).lower()
    domain = domain.strip('-')
    # منع الشرطات المتتالية
    if '--' in domain:
        return None, False
    # منع النطاق القصير جداً
    if len(domain) < 4:
        return None, False
    # منع النطاق الذي يبدأ برقم ثم شرطة
    if re.match(r'^[0-9]+-', domain):
        return None, False
    # منع النطاق الذي لا يحتوي على نقطة (لن يحدث)
    if '.' not in domain:
        return None, False

    # بناء الصيغة النهائية
    if is_exception:
        return f"@@||{domain}^", True
    else:
        return f"||{domain}^", False

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        r.raise_for_status()
        rules = set()
        for line in r.text.splitlines():
            rule, _ = clean_rule(line)
            if rule:
                rules.add(rule)
        return rules, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return set(), url

def process_filters(urls):
    all_rules = set()
    total = len(urls)
    print(f"🔍 معالجة {total} مصدر (تنظيف كامل)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_filter, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            rules, url = future.result()
            new_count = len(rules - all_rules)
            all_rules.update(rules)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: +{new_count} قاعدة")
            if i < total:
                time.sleep(REQUEST_DELAY)
    return sorted(all_rules)

def save_filters(rules, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Filter (Strict DNS)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total rules: {len(rules)}\n\n")
        f.write("\n".join(rules))
    size_mb = os.path.getsize(main_file) / (1024 * 1024)
    print(f"\n✅ تم حفظ {len(rules)} قاعدة في {main_file} (حجم {size_mb:.2f} ميجابايت)")

    # عرض عينة من الأسطر للتأكد من خلوه من الشروط
    print("\n🔍 عينة من القواعد (يجب أن تكون كلها بصيغة ||domain^ أو @@||domain^):")
    for r in rules[:10]:
        print(f"   {r}")
    return main_file

if __name__ == "__main__":
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("❌ ملف list.txt غير موجود")
        exit(1)

    if not urls:
        print("❌ لا توجد روابط")
        exit(1)

    start = time.time()
    rules = process_filters(urls)
    save_filters(rules)
    print(f"\n⏱️ الوقت: {time.time() - start:.2f} ثانية")
