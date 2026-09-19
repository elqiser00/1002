import os
import re
import gzip
import shutil
import time
import random
from datetime import datetime
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

# كتم تحذيرات SSL
import warnings
warnings.simplefilter('ignore', InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# محاولة استيراد httpx و brotli (اختياريان)
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False


# ============ الإعدادات ============
INPUT_FILE = "list.txt"
OUTPUT_DIR = "dnsmasq_filters"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dnsmasq_blocklist.conf")
COMPRESSED_FILE = os.path.join(OUTPUT_DIR, "dnsmasq_blocklist.conf.gz")
SKIPPED_LOG = os.path.join(OUTPUT_DIR, "skipped_lines.log")

# User-Agents للتدوير
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
    "Accept-Encoding": "gzip, deflate, br" if BROTLI_AVAILABLE else "gzip, deflate",
    "Connection": "keep-alive",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
}

# كلمات مفتاحية للقوائم البيضاء
ALLOW_KEYWORDS = ['allow', 'whitelist', 'white-list', 'white_list']

# كلمات محجوزة (ليست دومينات)
INVALID_WORDS = {
    'localhost', 'broadcasthost', 'ip6-localhost', 'ip6-loopback',
    'ip6-allnodes', 'ip6-allrouters', 'ip6-localnet', 'ip6-mcastprefix',
    'local', 'localdomain', 'localhost.localdomain',
}


# ============ إعداد الجلسة ============
def create_session():
    """ينشئ جلسة requests مع Retry و SSL مطفأ."""
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
    """يقرأ الروابط مع دعم صيغ متعددة (cookie، header، ua، auth)."""
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
    """يفهم: URL | cookie=... | header=X:Y | ua=... | auth=user:pass"""
    parts = [p.strip() for p in line.split('|')]
    entry = {"url": parts[0], "cookies": {}, "headers": {}, "user_agent": None, "auth": None}

    for opt in parts[1:]:
        low = opt.lower()
        if low.startswith(("cookie=", "cookies=")):
            cookie_str = opt.split("=", 1)[1]
            for c in cookie_str.split(";"):
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


# ============ كشف الهيدرز والتعليقات ============
def is_header_or_comment(line):
    """يتعرف على أسطر الهيدرز والتعليقات بكل أنواعها."""
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
    """ينظف الدومين ويتحقق من صحته بشكل صارم."""
    if not d:
        return None
    d = d.strip().lower().rstrip('.')
    d = d.replace("*.", "")
    d = d.strip('^$|')

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


# ============ استخراج الدومينات من سطر ============
def extract_domains_from_line(line):
    """يستخرج كل الدومينات من سطر واحد، ويتجاهل الهيدرز."""
    if is_header_or_comment(line):
        return []

    line = line.strip()
    line = re.split(r'\s[#!]', line, maxsplit=1)[0].strip()
    if not line:
        return []

    domains_found = []

    # الحالة 1: مفصولة بـ ::
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

    # الحالة 2: hosts (IP DOMAIN)
    if parts and (re.match(r'^(\d{1,3}\.){3}\d{1,3}$', parts[0]) or
                  parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::')):
        for token in parts[1:]:
            d = clean_domain(token)
            if d:
                domains_found.append(d)
        return domains_found

    # الحالة 3: dnsmasq
    m = re.match(r'^address=/([^/]+)/', line)
    if m:
        d = clean_domain(m.group(1))
        if d:
            domains_found.append(d)
        return domains_found

    # الحالة 4: Adblock
    m = re.match(r'^\|\|([a-z0-9.-]+)\^?', line, re.IGNORECASE)
    if m:
        d = clean_domain(m.group(1))
        if d:
            domains_found.append(d)
        return domains_found

    # الحالة 5: URL
    if line.startswith(("http://", "https://")):
        parsed = urlparse(line)
        d = clean_domain(parsed.hostname or "")
        if d:
            domains_found.append(d)
        return domains_found

    # الحالة 6: دومين مباشر
    for token in parts:
        d = clean_domain(token)
        if d:
            domains_found.append(d)

    return domains_found


# ============ التنزيل ============
def download_content(entry, max_attempts=3):
    """ينزّل المحتوى بكل الاحتياطات."""
    url = entry["url"]

    # FTP
    if url.lower().startswith("ftp://"):
        return download_ftp(url)

    # file://
    if url.lower().startswith("file://"):
        try:
            with open(url[7:], 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"  ❌ file:// فشل: {e}")
            return None

    # Basic Auth في الرابط
    auth = entry.get("auth")
    if not auth and "@" in urlparse(url).netloc:
        parsed = urlparse(url)
        if ":" in parsed.netloc.split("@")[0]:
            user, pwd = parsed.netloc.split("@")[0].split(":", 1)
            auth = (user, pwd)
            new_netloc = parsed.netloc.split("@", 1)[1]
            url = urlunparse(parsed._replace(netloc=new_netloc))

    # محاولات requests
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
                content = resp.content
                encoding = resp.headers.get("Content-Encoding", "").lower()
                if "br" in encoding and BROTLI_AVAILABLE:
                    content = brotli.decompress(content)
                elif "gzip" in encoding:
                    try:
                        content = gzip.decompress(content)
                    except Exception:
                        pass
                try:
                    return content.decode(resp.encoding or "utf-8", errors="ignore")
                except Exception:
                    return content.decode("utf-8", errors="ignore")
            else:
                print(f"  ⚠️ محاولة {attempt}: HTTP {resp.status_code}")

        except requests.exceptions.SSLError as e:
            print(f"  ⚠️ SSL خطأ (محاولة {attempt}): {str(e)[:80]}")
        except requests.exceptions.Timeout:
            print(f"  ⚠️ Timeout (محاولة {attempt})")
        except requests.exceptions.ConnectionError as e:
            print(f"  ⚠️ اتصال فشل (محاولة {attempt}): {str(e)[:80]}")
        except Exception as e:
            print(f"  ⚠️ خطأ (محاولة {attempt}): {str(e)[:100]}")

        time.sleep(1.5 * attempt)

    # بديل httpx
    if HTTPX_AVAILABLE:
        print("  🔄 تجربة httpx...")
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=60) as client:
                r = client.get(url, headers=entry.get("headers", {}), auth=auth)
                if r.status_code == 200:
                    return r.text
        except Exception as e:
            print(f"  ❌ httpx فشل: {str(e)[:100]}")

    # ملاذ أخير: curl
    print("  🔄 تجربة curl...")
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
        print(f"  ❌ FTP فشل: {e}")
        return None


def download_with_curl(url, entry):
    import subprocess
    try:
        cmd = ["curl", "-sSL", "--insecure", "--max-time", "90",
               "--retry", "3", "--retry-delay", "2",
               "-A", entry.get("user_agent") or random.choice(USER_AGENTS)]
        for k, v in entry.get("headers", {}).items():
            cmd += ["-H", f"{k}: {v}"]
        cmd.append(url)
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  ❌ curl فشل: {e}")
    return None


# ============ المعالجة الرئيسية ============
def parse_filters(entries):
    blocklist, allowlist = set(), set()
    skipped_samples = []

    for entry in entries:
        url = entry["url"]
        print(f"🌐 معالجة: {url}")
        content = download_content(entry)
        if not content:
            print(f"  ❌ فشل نهائي: {url}")
            continue

        is_allow = any(k in url.lower() for k in ALLOW_KEYWORDS)
        count = 0
        for line in content.splitlines():
            if is_header_or_comment(line):
                if len(skipped_samples) < 100 and line.strip():
                    skipped_samples.append(line)
                continue
            domains = extract_domains_from_line(line)
            for d in domains:
                (allowlist if is_allow else blocklist).add(d)
                count += 1
        print(f"  ✅ {count} دومين")

    # حفظ عينة من الأسطر المتجاهلة
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(SKIPPED_LOG, 'w', encoding='utf-8') as f:
        f.write(f"# عينة من الأسطر المتجاهلة (أول 100)\n")
        f.write(f"# التاريخ: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
        for s in skipped_samples:
            f.write(s + "\n")

    return blocklist, allowlist


def apply_priority(blocklist, allowlist):
    print(f"\n📊 سوداء: {len(blocklist)} | بيضاء: {len(allowlist)}")
    final = blocklist - allowlist
    print(f"📊 النهائية: {len(final)}")
    return final


def format_dnsmasq(domains, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# قائمة الحظر - تنسيق dnsmasq\n")
        f.write(f"# تاريخ الإنشاء: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# عدد الدومينات: {len(domains)}\n\n")
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
    format_dnsmasq(final, OUTPUT_FILE)
    compress_file(OUTPUT_FILE, COMPRESSED_FILE)
    os.remove(OUTPUT_FILE)
    print("\n🎉 اكتمل بنجاح.")


if __name__ == "__main__":
    main()
