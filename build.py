#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adguard-Adblock-only Builder
- يجمع الدومينات من كل المصادر + قائمتك المخصصة (BlackList.txt)
- يشيل التكرار الحرفي فقط (Literal Duplicates)
- لا يحذف أي تعارض (لو دومين محظور ومسموح، يكتب الاتنين)
- الصيغة النهائية: ||domain^$important و @@||domain^$important
"""

import os
import re
import io
import gzip
import time
import zipfile
import tarfile
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LIST_FILE   = "list2.txt"
OUT_DIR     = "Adguard-Adblock-only"
MAX_BYTES   = 90 * 1024 * 1024
TIMEOUT     = 300
MAX_RETRIES = 3
CHUNK_SIZE  = 1024 * 1024

# رابط قائمتك المخصصة
FORCED_BLOCKLIST_URL = "https://raw.githubusercontent.com/elqiser00/1002/refs/heads/main/filters/BlackList.txt"

DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.I,
)

SKIP_HOSTS = {
    "localhost", "localhost.localdomain", "localdomain", "broadcasthost",
    "local", "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
    "0.0.0.0", "127.0.0.1", "::1", "255.255.255.255",
}

REGEX_PATTERNS = [
    re.compile(r"^/.*/$"),
    re.compile(r"/\*.*\*/"),
    re.compile(r"\\[dwsbSWD]"),
    re.compile(r"\\\."),
    re.compile(r"\^[a-z0-9]", re.I),
    re.compile(r"[a-z0-9]\$$", re.I),
    re.compile(r"\.\*"),
    re.compile(r"\.\+"),
    re.compile(r"\(\?[:=!]"),
    re.compile(r"\[[a-z0-9\-\^]+\]", re.I),
    re.compile(r"\\\$"),
]

def looks_like_regex(s: str) -> bool:
    if not s:
        return False
    if s.startswith("/") or s.endswith("/"):
        return True
    for pat in REGEX_PATTERNS:
        if pat.search(s):
            return True
    return False

def clean_url(raw: str) -> str:
    u = raw.strip().strip('"\'').strip()
    u = re.sub(r"[:;,\.\s]+$", "", u)
    return u

def read_urls(path):
    urls, seen = [], set()
    if not os.path.isfile(path):
        print(f"[!] {path} غير موجود")
        return urls
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = clean_url(line)
            if not u.lower().startswith(("http://", "https://")):
                continue
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls

def build_session():
    s = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/122.0.0.0 Safari/537.36"),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate",
    })
    return s

def decode_bytes(data):
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="ignore")

def try_decompress(data, url, content_type):
    ct = (content_type or "").lower()
    low_url = url.lower()

    if low_url.endswith(".gz") or "gzip" in ct or data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data)
        except Exception:
            try:
                return gzip.decompress(data[data.find(b"\x1f\x8b"):])
            except Exception:
                pass

    if low_url.endswith((".tgz", ".tar.gz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                chunks = []
                for m in tar.getmembers():
                    if m.isfile():
                        f = tar.extractfile(m)
                        if f:
                            chunks.append(f.read())
                if chunks:
                    return b"\n".join(chunks)
        except Exception:
            pass

    if low_url.endswith(".zip") or "zip" in ct or data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                chunks = []
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    try:
                        chunks.append(z.read(name))
                    except Exception:
                        pass
                if chunks:
                    return b"\n".join(chunks)
        except Exception:
            pass

    return data

def fetch_full(session, url):
    r = None
    for verify in (True, False):
        try:
            r = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=verify,
                stream=True,
            )
            r.raise_for_status()
            break
        except requests.exceptions.SSLError:
            print("    [!] SSL error، إعادة المحاولة بدون تحقق...")
            continue
        except Exception as exc:
            print(f"    [!] {exc}")
            return None, 0, False

    if r is None:
        return None, 0, False

    chunks = []
    try:
        for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                chunks.append(chunk)
    except Exception as exc:
        print(f"    [!] خطأ أثناء التحميل: {exc}")
        pass

    body = b"".join(chunks)
    if not body:
        return None, 0, False

    body = try_decompress(body, url, r.headers.get("Content-Type", ""))
    text = decode_bytes(body)

    head = text[:400].lstrip().lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        if "||" not in text and "0.0.0.0" not in text:
            print("    [!] محتوى HTML مش ليست، تجاهل")
            return None, 0, False

    return text, len(body), True

HOSTS_IP_RE    = re.compile(r"^([0-9a-fA-F:.]+)\s+([^\s#]+)")
ADBLOCK_DOM_RE = re.compile(r"^([a-z0-9][a-z0-9.\-]*[a-z0-9])", re.I)

def clean_domain(d: str) -> str:
    if not d:
        return ""
    d = re.split(r"[/:?#&|]", d)[0]
    d = d.strip(".").lower()
    return d

def extract_domain(s):
    if not s:
        return None, None
    if len(s) > 1024:
        return None, None
    if s.startswith("!"):
        return None, None
    if "#" in s:
        return None, None
    if s.startswith("[") and s.endswith("]"):
        return None, None
    if looks_like_regex(s):
        return None, None

    m = HOSTS_IP_RE.match(s)
    if m:
        raw_host = m.group(2)
        host = clean_domain(raw_host)
        if not host or host in SKIP_HOSTS:
            return None, None
        if not DOMAIN_RE.match(host):
            return None, None
        return host, False

    allowed_flag = False
    if s.startswith("@@"):
        allowed_flag = True
        s = s[2:]

    domain = None

    if s.startswith("||"):
        rest = s[2:]
        m = ADBLOCK_DOM_RE.match(rest)
        if m:
            domain = m.group(1)
    elif s.startswith("|"):
        rest = re.sub(r"^https?://", "", s[1:], flags=re.I)
        m = ADBLOCK_DOM_RE.match(rest)
        if m:
            domain = m.group(1)
    else:
        tmp = re.sub(r"^https?://", "", s, flags=re.I)
        tmp = re.split(r"[/:?#&\s]", tmp)[0]
        if DOMAIN_RE.match(tmp):
            domain = tmp

    if not domain:
        return None, None

    domain = clean_domain(domain)

    if not domain or domain in SKIP_HOSTS:
        return None, None
    if not DOMAIN_RE.match(domain):
        return None, None

    return domain, allowed_flag

def write_output(blocked_domains, allowed_domains, out_dir, max_bytes):
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.endswith(".txt"):
            try:
                os.remove(os.path.join(out_dir, f))
            except OSError:
                pass

    total = len(blocked_domains) + len(allowed_domains)
    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Adguard Adblock only\n"
        "! Description: Literal De-duplication Only (Keep conflicts)\n"
        f"! Blocked domains: {len(blocked_domains)}\n"
        f"! Allowed domains: {len(allowed_domains)}\n"
        f"! Total domains:   {total}\n"
        "! Generated: "
        + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + "\n"
        "!\n"
    )
    header_bytes = len(header.encode("utf-8"))

    files, idx, cur_lines, cur_size = [], 1, [], header_bytes

    def flush():
        nonlocal idx, cur_lines, cur_size
        if not cur_lines:
            return
        name = "blacklist.txt" if idx == 1 else f"blacklist_{idx}.txt"
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(header)
            fh.writelines(cur_lines)
        files.append(path)
        idx += 1
        cur_lines, cur_size = [], header_bytes

    def add_line(line):
        nonlocal cur_lines, cur_size
        b = len(line.encode("utf-8"))
        if cur_size + b > max_bytes and cur_lines:
            flush()
        cur_lines.append(line)
        cur_size += b

    # كتابة كل الحظر بـ $important
    for d in blocked_domains:
        add_line(f"||{d}^$important\n")

    # كتابة كل السماح بـ $important
    for d in allowed_domains:
        add_line(f"@@||{d}^$important\n")

    flush()
    return files

def main():
    print("=" * 60)
    print("  Adguard-Adblock-only  |  Literal De-duplication Only")
    print("=" * 60)

    session = build_session()
    blocked, allowed = set(), set()

    # 1. تحميل القائمة المخصصة
    print(f"[*] تحميل القائمة المخصصة: {FORCED_BLOCKLIST_URL}")
    text, _, _ = fetch_full(session, FORCED_BLOCKLIST_URL)
    if text:
        for line in text.splitlines():
            for part in re.split(r'\s+', line.strip()):
                if not part:
                    continue
                domain, allowed_flag = extract_domain(part)
                if domain:
                    if allowed_flag:
                        allowed.add(domain)
                    else:
                        blocked.add(domain)
        print(f"    [✓] تم قراءة قائمتك المخصصة.")
    
    # 2. تحميل الروابط العادية
    urls = read_urls(LIST_FILE)
    print(f"\n[+] عدد الروابط في list2.txt: {len(urls)}\n")

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {url}")
        text, _, is_complete = fetch_full(session, url)

        if not text:
            continue

        for line in text.splitlines():
            s = line.strip()
            if not s or len(s) > 1024:
                continue

            if s.startswith("!") or (s.startswith("[") and s.endswith("]")):
                continue
            if "#" in s:
                continue
            if looks_like_regex(s):
                continue

            domain, allowed_flag = extract_domain(s)
            if not domain:
                continue

            if allowed_flag:
                allowed.add(domain)
            else:
                blocked.add(domain)

    # ═══════════════════════════════════════════════════════
    # لا يوجد أي فلترة متعارضة هنا، السيت (set) شال التكرار بس
    # ═══════════════════════════════════════════════════════
    final_blocked = sorted(blocked)
    final_allowed = sorted(allowed)

    print("\n" + "=" * 60)
    print("  📊 إحصائيات الفلترة الحرفية")
    print("=" * 60)
    print(f"  🚫 الدومينات المحظورة الفريدة: {len(final_blocked):,}")
    print(f"  ✅ الدومينات المسموحة الفريدة: {len(final_allowed):,}")
    
    # حساب عدد المتعارضين للمعلومة فقط
    conflicts = set(final_blocked) & set(final_allowed)
    print(f"  ⚠️  دومينات موجودة في القائمتين (تم الاحتفاظ بها): {len(conflicts):,}")
    print("=" * 60)

    print("\n[+] كتابة الملفات...")
    files = write_output(final_blocked, final_allowed, OUT_DIR, MAX_BYTES)
    for f in files:
        size = os.path.getsize(f)
        print(f"    ✅ {f}  ({size/1024/1024:.2f} MB)")
        print("    🔍 معاينة (أول 5 أسطر):")
        with open(f, "r", encoding="utf-8") as preview:
            for _ in range(5):
                print(f"       {preview.readline().strip()}")

    print("\n[✓] خلص بنجاح")

if __name__ == "__main__":
    main()
