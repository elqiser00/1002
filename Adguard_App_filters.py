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
USER_AGENT = "AdGuard-App-Filter-Merger/6.0"

def is_valid_domain(domain):
    """التحقق من صحة النطاق - يجب أن يكون نطاقًا حقيقيًا صالحًا"""
    if not domain:
        return False
    
    domain = domain.strip().lower()
    
    # منع النطاقات التي تبدأ برقم أو شرطة
    if re.match(r'^[0-9\-]', domain):
        return False
    
    # منع النطاقات التي تحتوي على أكثر من شرطة متتالية
    if '--' in domain:
        return False
    
    # منع النطاقات التي تبدأ أو تنتهي بنقطة
    if domain.startswith('.') or domain.endswith('.'):
        return False
    
    # التحقق من وجود نقطة واحدة على الأقل
    if '.' not in domain:
        return False
    
    # التحقق من أن الجزء الأخير (TLD) مكون من حروف فقط
    parts = domain.split('.')
    tld = parts[-1]
    if not re.match(r'^[a-z]{2,}$', tld):
        return False
    
    # التحقق من أن جميع الأجزاء تحتوي على أحرف وأرقام وشرطات فقط (ولكن لا تبدأ برقم أو شرطة)
    for part in parts[:-1]:  # جميع الأجزاء ما عدا TLD
        if not part:
            return False
        if re.match(r'^[0-9\-]', part):  # يبدأ برقم أو شرطة
            return False
        if not re.match(r'^[a-z0-9\-]+$', part):
            return False
    
    return True

def extract_domain_from_rule(rule):
    """استخراج النطاق والتحقق من صحته"""
    rule = rule.strip()
    if rule.startswith('!') or rule.startswith('#'):
        return None, None
    
    is_exception = rule.startswith('@@')
    clean_rule = rule[2:] if is_exception else rule
    
    patterns = [
        (r'^\|\|([a-z0-9\-\.]+)\^$', r'\1'),
        (r'^\|\|([a-z0-9\-\.]+)$', r'\1'),
        (r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9\-\.]+)$', r'\1'),
        (r'^([a-z0-9\-\.]+\.[a-z]{2,})$', r'\1'),
        (r'^\*\.([a-z0-9\-\.]+\.[a-z]{2,})$', r'\1'),
        (r'^/([a-z0-9\-\.]+\.[a-z]{2,})/$', r'\1'),
    ]
    
    for pattern, _ in patterns:
        match = re.match(pattern, clean_rule, re.IGNORECASE)
        if match:
            domain = match.group(1).lower()
            if is_valid_domain(domain):
                return domain, is_exception
    
    return None, None

def download_filter(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        response.raise_for_status()
        
        domains = set()
        exceptions = set()
        
        for line in response.text.splitlines():
            domain, is_exception = extract_domain_from_rule(line)
            if domain:
                if is_exception:
                    exceptions.add(domain)
                else:
                    domains.add(domain)
        
        domains -= exceptions
        return list(domains), list(exceptions), url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return [], [], url

def process_filters(urls):
    all_domains = set()
    all_exceptions = set()
    total_urls = len(urls)
    
    print(f"🔍 معالجة {total_urls} مصدر...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(download_filter, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            domains, exceptions, url = future.result()
            all_domains.update(domains)
            all_exceptions.update(exceptions)
            print(f"📊 [{i}/{total_urls}] {urlparse(url).netloc}: {len(domains)} حظر, {len(exceptions)} استثناء")
            
            if i < total_urls:
                time.sleep(REQUEST_DELAY)
    
    final_domains = all_domains - all_exceptions
    print(f"\n📈 النتائج: {len(final_domains)} نطاق صالح, {len(all_exceptions)} استثناء")
    return sorted(final_domains), sorted(all_exceptions)

def save_filters(domains, exceptions, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)
    main_file = os.path.join(output_dir, "adguard_app_filter.txt")
    
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Custom Filter\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Total: {len(domains)} domains\n\n")
        for d in domains:
            f.write(f"{d}\n")
        for e in exceptions:
            f.write(f"@@{e}\n")
    
    print(f"\n✅ {len(domains)} نطاق صالح في {main_file}")
    return main_file

if __name__ == "__main__":
    with open("list.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    if not urls:
        print("❌ list.txt فارغ")
        exit(1)
    
    start = time.time()
    domains, exceptions = process_filters(urls)
    save_filters(domains, exceptions)
    print(f"⏱️ {time.time() - start:.2f} ثانية")
    
    if domains:
        print("\n🔍 أمثلة للنطاقات الصالحة:")
        for d in domains[:10]:
            print(f"   {d}")
