import os
import re
import gzip
import shutil
import time
import random
import unicodedata
from datetime import datetime
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

import warnings
warnings.simplefilter('ignore', InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import brotli  # noqa: F401
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False


# ============ الإعدادات ============
INPUT_FILE = "list.txt"
OUTPUT_DIR = "dnsmasq_filters"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dnsmasq_blocklist.conf")
COMPRESSED_FILE = os.path.join(OUTPUT_DIR, "dnsmasq_blocklist.conf.gz")
SKIPPED_LOG = os.path.join(OUTPUT_DIR, "skipped_lines.log")
STATS_LOG = os.path.join(OUTPUT_DIR, "stats.txt")

# إزالة الدومينات الفرعية (موصى به بشدة لتقليل الحجم)
REMOVE_SUBDOMAIN_DUPS = True

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "curl/8.4.0",
    "Wget/1.21.3",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
    "Connection": "keep-alive",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
}

ALLOW_KEYWORDS = ['allow', 'whitelist', 'white-list', 'white_list']

INVALID_WORDS = {
    'localhost', 'broadcasthost', 'ip6-localhost', 'ip6-loopback',
    'ip6-allnodes', 'ip6-allrouters', 'ip6-localnet', 'ip6-mcastprefix',
    'local', 'localdomain', 'localhost.localdomain',
}


# ============ الجلسة ============
def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    session.verify = False
    return session


# ============ قراءة list.txt ============
def read_filter_urls(filepath):
    entries = []
    if not os.path.exists(filepath):
        print(f"⚠️ ملف {filepath} غير موجود.")
        return entries
    with open(filepath, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            entries.append(parse_entry(line))
    return entries


def parse_entry(line):
    parts = [p.strip() for p in line.split('|')]
    entry = {"url": parts[0], "cookies": {}, "headers": {}, "user_agent": None, "auth": None}
    for opt in parts[1:]:
        low = opt.lower()
        if low.startswith(("cookie=", "cookies=")):
            for c in opt.split("=", 1)[1].split(";"):
                if "=" in c:
                    k, v = c.split("=", 1)
                    entry["cookies"][k.strip()] = v.strip()
        elif low.startswith("header="):
            h = opt.split("=", 1)[1]
            if ":" in h:
                k, v = h.split(":", 1)
                entry["headers"][k.strip()] = v.strip()
        elif low.startswith("ua="):
            entry["user_agent"] = opt.split("=", 1)[1].strip()
        elif low.startswith("auth="):
            entry["auth"] = tuple(opt.split("=", 1)[1].split(":", 1))
    return entry


# ============ كشف الهيدرز ============
def is_header_or_comment(line):
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith(('#', '!', '//', ';', '[', ']')):
        return True
    if re.match(r'^[\s#*=\-_~`+=|<>/\\.,;:!"\']+$', stripped):
        return True
    if re.match(r'^[=\-#*_~]{3,}.*[=\-#*_~]{3,}$', stripped):
        return True
    if stripped.startswith('<!--') or stripped.endswith('-->'):
        return True
    return False


# ============ تنظيف الدومين ============
def clean_domain(d):
    if not d:
        return None
    d = d.strip().lower().rstrip('.')
    d = d.replace("*.", "")
    d = d.strip('^$|')

    # تحويل unicode إلى ASCII (punycode-like)
    try:
        d = unicodedata.normalize('NFKC', d)
    except Exception:
        pass

    # رفض الطول الزائد (أقصى 253 حرف حسب RFC)
    if len(d) > 253:
        return None

    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', d):
        return None
    if '.' not in d:
        return None
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', d):
        return None
    if d in INVALID_WORDS:
        return None

    tld = d.rsplit('.', 1)[-1]
    if len(tld) < 2 or not tld.isalpha():
        return None

    return d


# ============ استخراج الدومينات ============
def extract_domains_from_line(line):
    if is_header_or_comment(line):
        return []

    line = line.strip()
    line = re.split(r'\s[#!]', line, maxsplit=1)[0].strip()
    if not line:
        return []

    domains_found = []

    if '::' in line:
        for part in line.split('::'):
            part = part.strip()
            if not part:
                continue
            for token in part.split():
                d = clean_domain(token)
                if d:
                    domains_found.append(d)
        return domains_found

    parts = line.split()

    if parts and (re.match(r'^(\d{1,3}\.){3}\d{1,3}$', parts[0]) or
                  parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::')):
        for token in parts[1:]:
            d = clean_domain(token)
            if d:
                domains_found.append(d)
        return domains_found

    m = re.match(r'^address=/([^/]+)/', line)
    if m:
        d = clean_domain(m.group(1))
        if d:
            domains_found.append(d)
        return domains_found

    m = re.match(r'^\|\|([a-z0-9.-]+)\^?', line, re.IGNORECASE)
    if m:
        d = clean_domain(m.group(1))
        if d:
            domains_found.append(d)
        return domains_found

    if line.startswith(("http://", "https://")):
        parsed = urlparse(line)
        d = clean_domain(parsed.hostname or "")
        if d:
            domains_found.append(d)
        return domains_found

    for token in parts:
        d = clean_domain(token)
        if d:
            domains_found.append(d)

    return domains_found


# ============ التنزيل ============
def download_content(entry, max_attempts=3):
    url = entry["url"]

    if url.lower().startswith("ftp://"):
        return download_ftp(url)

    if url.lower().startswith("file://"):
        try:
            with open(url[7:], 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"  ❌ file:// فشل: {e}")
            return None

    auth = entry.get("auth")
    if not auth and "@" in urlparse(url).netloc:
        parsed = urlparse(url)
        if ":" in parsed.netloc.split("@")[0]:
            user, pwd = parsed.netloc.split("@")[0].split(":", 1)
            auth = (user, pwd)
            new_netloc = parsed.netloc.split("@", 1)[1]
            url = urlunparse(parsed._replace(netloc=new_netloc))

    for attempt in range(1, max_attempts + 1):
        ua = entry.get("user_agent") or random.choice(USER_AGENTS)
        headers = dict(entry.get("headers", {}))
        headers["User-Agent"] = ua

        try:
            session = create_session()
            if entry.get("cookies"):
                session.cookies.update(entry["cookies"])

            resp = session.get(
                url, headers=headers, auth=auth,
                timeout=(10, 60), allow_redirects=True, verify=False,
            )

            if resp.status_code == 200:
                try:
                    return resp.text
                except Exception:
                    return resp.content.decode("utf-8", errors="ignore")
            else:
                print(f"  ⚠️ محاولة {attempt}: HTTP {resp.status_code}")

        except requests.exceptions.SSLError as e:
            print(f"  ⚠️ SSL (محاولة {attempt}): {str(e)[:60]}")
        except requests.exceptions.Timeout:
            print(f"  ⚠️ Timeout (محاولة {attempt})")
        except requests.exceptions.ConnectionError as e:
            print(f"  ⚠️ اتصال (محاولة {attempt}): {str(e)[:60]}")
        except Exception as e:
            print(f"  ⚠️ خطأ (محاولة {attempt}): {str(e)[:80]}")

        time.sleep(1.5 * attempt)

    if HTTPX_AVAILABLE:
        print("  🔄 httpx...")
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=60) as client:
                r = client.get(url, headers=entry.get("headers", {}), auth=auth)
                if r.status_code == 200:
                    return r.text
        except Exception as e:
            print(f"  ❌ httpx: {str(e)[:80]}")

    print("  🔄 curl...")
    return download_with_curl(url, entry)


def download_ftp(url):
    from ftplib import FTP
    try:
        p = urlparse(url)
        ftp = FTP(p.hostname, timeout=30)
        ftp.login(p.username or "anonymous", p.password or "")
        ftp.set_pasv(True)
        lines = []
        ftp.retrlines(f"RETR {p.path}", lines.append)
        ftp.quit()
        return "\n".join(lines)
    except Exception as e:
        print(f"  ❌ FTP: {e}")
        return None


def download_with_curl(url, entry):
    import subprocess
    try:
        cmd = ["curl", "-sSL", "--insecure", "--compressed",
               "--max-time", "90", "--retry", "3", "--retry-delay", "2",
               "-A", entry.get("user_agent") or random.choice(USER_AGENTS)]
        for k, v in entry.get("headers", {}).items():
            cmd += ["-H", f"{k}: {v}"]
        cmd.append(url)
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  ❌ curl: {e}")
    return None


# ============ إزالة الدومينات الفرعية ============
def remove_subdomain_duplicates(domains):
    """
    يحذف الدومين الفرعي إذا كان أبوه موجودًا.
    مثال: إذا كان example.com موجودًا، نحذف ads.example.com و tracker.example.com.
    السبب: dnsmasq يحجب كل الفروع تلقائيًا مع address=/example.com/0.0.0.0.
    """
    sorted_domains = sorted(domains, key=lambda d: d.count('.'))
    result = set()
    removed = 0
    for d in sorted_domains:
        parts = d.split('.')
        has_parent = False
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in result:
                has_parent = True
                break
        if has_parent:
            removed += 1
        else:
            result.add(d)
    print(f"  🗑️ إزالة {removed} دومين فرعي مكرر")
    return result


# ============ المعالجة ============
def parse_filters(entries):
    blocklist, allowlist = set(), set()
    skipped_samples = []
    stats = []

    for entry in entries:
        url = entry["url"]
        print(f"🌐 معالجة: {url}")
        content = download_content(entry)
        if not content:
            print(f"  ❌ فشل نهائي")
            stats.append((url, 0, "FAILED"))
            continue

        is_allow = any(k in url.lower() for k in ALLOW_KEYWORDS)
        count = 0
        before = len(blocklist) + len(allowlist)
        for line in content.splitlines():
            if is_header_or_comment(line):
                if len(skipped_samples) < 100 and line.strip():
                    skipped_samples.append(line)
                continue
            domains = extract_domains_from_line(line)
            for d in domains:
                (allowlist if is_allow else blocklist).add(d)
                count += 1
        after = len(blocklist) + len(allowlist)
        added = after - before
        print(f"  ✅ {count} دومين مقروء، {added} جديد")
        stats.append((url, count, "OK"))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(SKIPPED_LOG, 'w', encoding='utf-8') as f:
        f.write(f"# عينة من الأسطر المتجاهلة (أول 100)\n")
        f.write(f"# التاريخ: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
        for s in skipped_samples:
            f.write(s + "\n")

    with open(STATS_LOG, 'w', encoding='utf-8') as f:
        f.write("URL\tعدد الدومينات\tالحالة\n")
        for url, cnt, st in stats:
            f.write(f"{url}\t{cnt}\t{st}\n")

    return blocklist, allowlist


def apply_priority(blocklist, allowlist):
    print(f"\n📊 سوداء (بدون إزالة فرعية): {len(blocklist):,}")
    print(f"📊 بيضاء: {len(allowlist):,}")
    final = blocklist - allowlist
    print(f"📊 بعد إزالة البيضاء: {len(final):,}")
    return final


def format_dnsmasq(domains, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# قائمة الحظر - تنسيق dnsmasq\n")
        f.write(f"# تاريخ الإنشاء: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# عدد الدومينات: {len(domains):,}\n\n")
        for d in sorted(domains):
            f.write(f"address=/{d}/0.0.0.0\n")
    print(f"✅ تم إنشاء {output_path}")


def compress_file(src, dst):
    with open(src, 'rb') as fi, gzip.open(dst, 'wb', compresslevel=9) as fo:
        shutil.copyfileobj(fi, fo)
    print(f"📦 الأصلي: {os.path.getsize(src)/(1024*1024):.2f} MB")
    print(f"📦 المضغوط: {os.path.getsize(dst)/(1024*1024):.2f} MB")


def main():
    print("🚀 بدء المعالجة...\n")
    entries = read_filter_urls(INPUT_FILE)
    if not entries:
        print("لا توجد روابط.")
        return

    block, allow = parse_filters(entries)
    final = apply_priority(block, allow)

    if REMOVE_SUBDOMAIN_DUPS:
        print(f"\n🔍 إزالة الدومينات الفرعية المكررة...")
        before = len(final)
        final = remove_subdomain_duplicates(final)
        print(f"📊 قبل: {before:,} → بعد: {len(final):,}")

    format_dnsmasq(final, OUTPUT_FILE)
    compress_file(OUTPUT_FILE, COMPRESSED_FILE)
    os.remove(OUTPUT_FILE)
    print("\n🎉 اكتمل بنجاح.")


if __name__ == "__main__":
    main()
