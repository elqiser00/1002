import os
import re
import gzip
import shutil
import time
import ssl
import socket
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

# محاولة استيراد httpx كبديل احتياطي (لو مثبت)
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# محاولة استيراد brotli (اختياري لفك ضغط br)
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

# قائمة User-Agents حقيقية للتدوير
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "curl/8.4.0",
    "Wget/1.21.3",
]

# Headers افتراضية
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
    "Accept-Encoding": "gzip, deflate",   # br يحتاج brotli، بنضيفه لو متاح
    "Connection": "keep-alive",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
}

if BROTLI_AVAILABLE:
    DEFAULT_HEADERS["Accept-Encoding"] = "gzip, deflate, br"


# ============ إعداد الجلسة مع Retry ============
def create_session():
    """ينشئ جلسة requests مع Retry و SSL مطفأ."""
    session = requests.Session()

    retry_strategy = Retry(
        total=5,
        backoff_factor=1.5,       # 1.5s, 3s, 6s, 12s, 24s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(DEFAULT_HEADERS)
    session.verify = False  # تعطيل التحقق من SSL
    return session


# ============ قراءة قائمة الروابط ============
def read_filter_urls(filepath):
    """يقرأ الروابط، ويدعم صيغ متعددة:
    - رابط مباشر
    - URL|COOKIE=...|HEADER=X:Y|UA=...
    """
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
    """
    يفهم صيغ متعددة:
      https://example.com/list.txt
      https://example.com/list.txt | cookie=abc=1; def=2 | header=X-Token: 123 | ua=Mozilla/5.0
      https://example.com/list.txt | headers=Referer:https://google.com
    """
    parts = [p.strip() for p in line.split('|')]
    entry = {
        "url": parts[0],
        "cookies": {},
        "headers": {},
        "user_agent": None,
        "auth": None,
    }

    for opt in parts[1:]:
        low = opt.lower()
        if low.startswith("cookie=") or low.startswith("cookies="):
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
            # auth=user:pass
            entry["auth"] = tuple(opt.split("=", 1)[1].split(":", 1))

    return entry


# ============ التنزيل مع كل الحمايات ============
def download_content(entry, max_attempts=3):
    """
    ينزّل محتوى الرابط مع كل الاحتياطات:
    - SSL مطفأ
    - Retries
    - تدوير User-Agents
    - دعم Cookies و Headers
    - بديل httpx لو requests فشل
    - دعم FTP
    """
    url = entry["url"]

    # --- 1. دعم FTP ---
    if url.lower().startswith("ftp://"):
        return download_ftp(url)

    # --- 2. دعم file:// ---
    if url.lower().startswith("file://"):
        path = url[7:]
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"  ❌ file:// فشل: {e}")
            return None

    # --- 3. التعامل مع Basic Auth في الرابط ---
    auth = entry.get("auth")
    if not auth and "@" in urlparse(url).netloc:
        parsed = urlparse(url)
        if ":" in parsed.netloc.split("@")[0]:
            user, pwd = parsed.netloc.split("@")[0].split(":", 1)
            auth = (user, pwd)
            # نظف الرابط من الـ auth
            new_netloc = parsed.netloc.split("@", 1)[1]
            url = urlunparse(parsed._replace(netloc=new_netloc))

    # --- 4. المحاولة بـ requests ---
    for attempt in range(1, max_attempts + 1):
        ua = entry.get("user_agent") or random.choice(USER_AGENTS)
        headers = dict(entry.get("headers", {}))
        headers["User-Agent"] = ua

        try:
            session = create_session()
            if entry.get("cookies"):
                session.cookies.update(entry["cookies"])

            resp = session.get(
                url,
                headers=headers,
                auth=auth,
                timeout=(10, 60),       # (اتصال، قراءة)
                allow_redirects=True,
                verify=False,
                stream=False,
            )

            if resp.status_code == 200:
                # فك الضغط يدويًا لو brotli
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

    # --- 5. المحاولة بـ httpx كبديل ---
    if HTTPX_AVAILABLE:
        print("  🔄 تجربة httpx كبديل...")
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=60) as client:
                r = client.get(url, headers=entry.get("headers", {}), auth=auth)
                if r.status_code == 200:
                    return r.text
        except Exception as e:
            print(f"  ❌ httpx فشل: {str(e)[:100]}")

    # --- 6. المحاولة بـ curl كملاذ أخير ---
    print("  🔄 تجربة curl كملاذ أخير...")
    return download_with_curl(url, entry)


def download_ftp(url):
    """ينزّل ملف FTP."""
    from ftplib import FTP
    from urllib.parse import urlparse
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
    """يستخدم curl الخارجي كحل أخير."""
    import subprocess
    try:
        cmd = [
            "curl", "-sSL", "--insecure",
            "--max-time", "90",
            "--retry", "3",
            "--retry-delay", "2",
            "-A", entry.get("user_agent") or random.choice(USER_AGENTS),
        ]
        for k, v in entry.get("headers", {}).items():
            cmd += ["-H", f"{k}: {v}"]
        cmd.append(url)
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  ❌ curl فشل: {e}")
    return None


# ============ استخراج الدومينات ============
def extract_domains_from_line(line):
    """يستخرج الدومين من سطر (hosts / دومين / URL / HTML)."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # إزالة تعليقات في نهاية السطر
    line = line.split('#')[0].strip()
    if not line:
        return None

    parts = line.split()

    # صيغة hosts: IP DOMAIN [DOMAIN...]
    if parts and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
        domains = []
        for p in parts[1:]:
            d = clean_domain(p)
            if d:
                domains.append(d)
        if domains:
            return domains[0]  # السطر الأول
        return None

    # صيغة dnsmasq: address=/domain/0.0.0.0
    m = re.match(r'^address=/([^/]+)/', line)
    if m:
        return clean_domain(m.group(1))

    # صيغة Adblock: ||domain^
    m = re.match(r'^\|\|([a-z0-9.-]+)\^', line, re.IGNORECASE)
    if m:
        return clean_domain(m.group(1))

    # رابط URL كامل
    if line.startswith(("http://", "https://")):
        parsed = urlparse(line)
        return clean_domain(parsed.hostname or "")

    # دومين مباشر
    return clean_domain(parts[0])


def clean_domain(d):
    """ينظف الدومين ويتحقق من صحته."""
    if not d:
        return None
    d = d.strip().lower().rstrip('.')
    d = d.replace("*.", "")           # إزالة wildcard
    if d.startswith("www.") and d.count(".") > 2:
        pass  # نحتفظ بـ www لو الدومين له subdomain
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', d):
        return None
    if '.' not in d:
        return None
    return d


# ============ المعالجة ============
def parse_filters(entries):
    blocklist, allowlist = set(), set()
    ALLOW_KEYWORDS = ['allow', 'whitelist', 'white-list', 'white_list']

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
            d = extract_domains_from_line(line)
            if d:
                (allowlist if is_allow else blocklist).add(d)
                count += 1
        print(f"  ✅ {count} دومين")

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
