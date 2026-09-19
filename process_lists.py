import os
import re
import gzip
import shutil
import requests
from datetime import datetime

INPUT_FILE = "list.txt"
OUTPUT_FILE = "dnsmasq_blocklist.conf"
COMPRESSED_FILE = "dnsmasq_blocklist.conf.gz"


def read_filter_urls(filepath):
    """يقرأ قائمة روابط الفلاتر من ملف الإدخال."""
    with open(filepath, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    return urls


def download_content(url):
    """يحاول تنزيل محتوى الرابط، ويعيد None في حال الفشل."""
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"خطأ في تنزيل {url}: {e}")
        return None


def extract_domains_from_line(line):
    """يستخرج الدومين من سطر نصي (hosts أو دومين مباشر)."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    parts = line.split()
    if len(parts) >= 2 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
        domain_candidate = parts[1].lower()
        if '.' in domain_candidate:
            return domain_candidate

    domain = line.split()[0].lower() if line.split() else ""
    if re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', domain):
        return domain

    return None


def parse_filters(urls):
    """ينزّل ويحلل جميع ملفات الفلاتر، ويصنف الدومينات إلى قوائم بيضاء وسوداء."""
    blocklist = set()
    allowlist = set()

    ALLOW_KEYWORDS = ['allow', 'whitelist', 'white-list', 'white_list']

    for url in urls:
        print(f"معالجة: {url}")
        content = download_content(url)
        if not content:
            continue

        url_lower = url.lower()
        is_allowlist_url = any(keyword in url_lower for keyword in ALLOW_KEYWORDS)

        for line in content.splitlines():
            domain = extract_domains_from_line(line)
            if domain:
                if is_allowlist_url:
                    allowlist.add(domain)
                else:
                    blocklist.add(domain)

    return blocklist, allowlist


def apply_priority(blocklist, allowlist):
    """القائمة البيضاء تتغلب على السوداء."""
    print(f"\nعدد الدومينات في القائمة السوداء: {len(blocklist)}")
    print(f"عدد الدومينات في القائمة البيضاء: {len(allowlist)}")
    final_blocklist = blocklist - allowlist
    print(f"عدد الدومينات النهائية بعد التصفية: {len(final_blocklist)}")
    return final_blocklist


def format_dnsmasq(domains, output_path):
    """يكتب الدومينات بتنسيق dnsmasq."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# قائمة الحظر - تنسيق dnsmasq\n")
        f.write(f"# تاريخ الإنشاء: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# عدد الدومينات: {len(domains)}\n\n")
        for domain in sorted(domains):
            f.write(f"address=/{domain}/0.0.0.0\n")
    print(f"تم إنشاء {output_path}")


def compress_file(input_path, output_path):
    """يضغط الملف بصيغة gzip لتقليل حجمه."""
    with open(input_path, 'rb') as f_in:
        with gzip.open(output_path, 'wb', compresslevel=9) as f_out:
            shutil.copyfileobj(f_in, f_out)
    original_size = os.path.getsize(input_path) / (1024 * 1024)
    compressed_size = os.path.getsize(output_path) / (1024 * 1024)
    print(f"حجم الملف الأصلي: {original_size:.2f} MB")
    print(f"حجم الملف المضغوط: {compressed_size:.2f} MB")


def main():
    print("بدء عملية معالجة قوائم الفلاتر...")

    filter_urls = read_filter_urls(INPUT_FILE)
    if not filter_urls:
        print(f"لا توجد روابط في {INPUT_FILE}. إنهاء.")
        return

    blocklist, allowlist = parse_filters(filter_urls)
    final_blocklist = apply_priority(blocklist, allowlist)
    format_dnsmasq(final_blocklist, OUTPUT_FILE)
    compress_file(OUTPUT_FILE, COMPRESSED_FILE)

    print("اكتملت العملية بنجاح.")


if __name__ == "__main__":
    main()
