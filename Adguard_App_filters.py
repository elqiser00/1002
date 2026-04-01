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
USER_AGENT = "AdGuard-Cleaner/3.0"

def is_valid_domain(domain):
    """التحقق من صحة النطاق (لا يبدأ برقم/شرطة، لا يحتوي --، به نقطة)"""
    domain = domain.lower().strip('-')
    if not domain or len(domain) < 4:
        return False
    if '--' in domain:
        return False
    if domain.startswith(('.', '-')) or domain.endswith('.'):
        return False
    if re.match(r'^[0-9]+-', domain):
        return False
    if re.search(r'[^a-z0-9\.\-]', domain):
        return False
    if '.' not in domain:
        return False
    return True

def extract_domain(line):
    """استخراج النطاق من أي قاعدة وإرجاع (domain, is_exception)"""
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None, None

    is_exception = line.startswith('@@')
    content = line[2:] if is_exception else line

    # إزالة الشروط ($) والمسارات (/) والنجوم (*)
    content = content.split('$')[0]
    content = content.split('/')[0]
    content = content.replace('*', '')

    # البحث عن نطاق صالح: يجب أن يبدأ بحرف (a-z) ويحتوي على نقطة
    match = re.search(r'([a-z][a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]{2,}|[a-z][a-z0-9\-]*\.[a-z]{2,})', content, re.IGNORECASE)
    if not match:
        return None, None

    domain = match.group(1).lower().strip('-')
    if is_valid_domain(domain):
        return domain, is_exception
    return None, None

def download_source(url):
    try:
        headers = {'User-Agent': USER_AGENT}
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        r.raise_for_status()
        domains = set()
        exceptions = set()
        for line in r.text.splitlines():
            domain, is_exception = extract_domain(line)
            if domain:
                if is_exception:
                    exceptions.add(domain)
                else:
                    domains.add(domain)
        return domains, exceptions, url
    except Exception as e:
        print(f"⚠️ {urlparse(url).netloc}: {str(e)}")
        return set(), set(), url

def merge_filters(urls):
    all_domains = set()
    all_exceptions = set()
    total = len(urls)
    print(f"🔍 معالجة {total} مصدر (استخراج النطاقات الصالحة)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_source, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            domains, exceptions, url = future.result()
            new_domains = domains - all_domains
            new_exceptions = exceptions - all_exceptions
            all_domains.update(domains)
            all_exceptions.update(exceptions)
            print(f"📊 [{i}/{total}] {urlparse(url).netloc}: +{len(new_domains)} حظر, +{len(new_exceptions)} استثناء")
            if i < total:
                time.sleep(REQUEST_DELAY)

    # إزالة المستثناة من قائمة الحظر
    final_domains = all_domains - all_exceptions
    return sorted(final_domains), sorted(all_exceptions)

def save_single_file(domains, exceptions, out_dir="merged_filters"):
    os.makedirs(out_dir, exist_ok=True)
    file_path = os.path.join(out_dir, "adguard_app_filter.txt")
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("! Title: AdGuard App Filter (Strict DNS)\n")
        f.write(f"! Version: {time.strftime('%Y.%m.%d')}\n")
        f.write(f"! Blocked domains: {len(domains)}\n")
        f.write(f"! Exceptions: {len(exceptions)}\n\n")
        for d in domains:
            f.write(f"||{d}^\n")
        for e in exceptions:
            f.write(f"@@||{e}^\n")
    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"\n✅ تم حفظ {len(domains)} قاعدة حظر و {len(exceptions)} استثناء في {file_path}")
    print(f"📦 حجم الملف: {size_mb:.2f} ميجابايت")
    if size_mb > 95:
        print("⚠️  تحذير: الملف كبير جداً (أكثر من 95 ميجابايت). قد يواجه GitHub صعوبة في الدفع.")
    return file_path

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
    blocked, allowed = merge_filters(urls)
    save_single_file(blocked, allowed)
    print(f"\n⏱️ الوقت الإجمالي: {time.time() - start:.2f} ثانية")
