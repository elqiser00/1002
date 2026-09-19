import os
import re
import gzip
import shutil
import requests
from datetime import datetime

INPUT_FILE = "list.txt"
OUTPUT_DIR = "dnsmasq_filters"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dnsmasq_blocklist.conf")
COMPRESSED_FILE = os.path.join(OUTPUT_DIR, "dnsmasq_blocklist.conf.gz")


def read_filter_urls(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]


def download_content(url):
    try:
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        return r.text
    except requests.exceptions.RequestException as e:
        print(f"خطأ في تنزيل {url}: {e}")
        return None


def extract_domains_from_line(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    parts = line.split()
    if len(parts) >= 2 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
        d = parts[1].lower()
        if '.' in d:
            return d
    domain = line.split()[0].lower() if line.split() else ""
    if re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', domain):
        return domain
    return None


def parse_filters(urls):
    blocklist, allowlist = set(), set()
    ALLOW_KEYWORDS = ['allow', 'whitelist', 'white-list', 'white_list']
    for url in urls:
        print(f"معالجة: {url}")
        content = download_content(url)
        if not content:
            continue
        is_allow = any(k in url.lower() for k in ALLOW_KEYWORDS)
        for line in content.splitlines():
            d = extract_domains_from_line(line)
            if d:
                (allowlist if is_allow else blocklist).add(d)
    return blocklist, allowlist


def apply_priority(blocklist, allowlist):
    print(f"سوداء: {len(blocklist)} | بيضاء: {len(allowlist)}")
    final = blocklist - allowlist
    print(f"النهائية: {len(final)}")
    return final


def format_dnsmasq(domains, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# قائمة الحظر - تنسيق dnsmasq\n")
        f.write(f"# تاريخ الإنشاء: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# عدد الدومينات: {len(domains)}\n\n")
        for d in sorted(domains):
            f.write(f"address=/{d}/0.0.0.0\n")
    print(f"تم إنشاء: {output_path}")


def compress_file(src, dst):
    with open(src, 'rb') as fi, gzip.open(dst, 'wb', compresslevel=9) as fo:
        shutil.copyfileobj(fi, fo)
    print(f"الأصلي: {os.path.getsize(src)/(1024*1024):.2f} MB")
    print(f"المضغوط: {os.path.getsize(dst)/(1024*1024):.2f} MB")


def main():
    print("بدء المعالجة...")
    urls = read_filter_urls(INPUT_FILE)
    if not urls:
        print("لا توجد روابط.")
        return
    block, allow = parse_filters(urls)
    final = apply_priority(block, allow)
    format_dnsmasq(final, OUTPUT_FILE)
    compress_file(OUTPUT_FILE, COMPRESSED_FILE)
    # احذف الملف الأصلي لتقليل الفوضى (النسخة المضغوطة كافية)
    os.remove(OUTPUT_FILE)
    print("اكتمل ✅")


if __name__ == "__main__":
    main()
