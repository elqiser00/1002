#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adguard-Adblock-only Builder
- Deep Scan لكل الملفات
- يستخرج الدومين فقط (بدون /path ولا :port ولا ?query)
- قواعد الأولوية:
    * محظور بس         -> ||domain^
    * مسموح بس         -> whitelist.txt
    * محظور + مسموح     -> يحذف من البلاك ويفضل في الوايت (الوايت تغلب)
- يشيل: ! تعليقات، # كوزمتك، $options، regex
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
TIMEOUT     = 120
MAX_RETRIES = 3

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


# ═══════════════════════════════════════════════
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


# ═══════════════════════════════════════════════
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

    if low_url.endswith(".gz") or "gzip" in ct:
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

    if low_url.endswith(".zip") or "zip" in ct:
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


def fetch(session, url):
    r = None
    for verify in (True, False):
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=verify)
            r.raise_for_status()
            break
        except requests.exceptions.SSLError:
            print("    [!] SSL error، إعادة المحاولة بدون تحقق...")
            continue
        except Exception as exc:
            print(f"    [!] {exc}")
            return None, 0

    if r is None:
        return None, 0

    body = r.content
    if not body:
        return None, 0

    original_size = len(body)
    body = try_decompress(body, url, r.headers.get("Content-Type", ""))
    text = decode_bytes(body)

    head = text[:400].lstrip().lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        if "||" not in text and "0.0.0.0" not in text:
            print("    [!] محتوى HTML مش ليست، تجاهل")
            return None, original_size

    return text, original_size


# ═══════════════════════════════════════════════
HOSTS_IP_RE    = re.compile(r"^([0-9a-fA-F:.]+)\s+([^\s#]+)")
ADBLOCK_DOM_RE = re.compile(r"^([a-z0-9][a-z0-9.\-]*[a-z0-9])", re.I)


def clean_domain(d: str) -> str:
    if not d:
        return ""
    d = re.split(r"[/:?#&]", d)[0]
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
    if len(domain) > 253:
        return None, None

    return domain, allowed_flag


# ═══════════════════════════════════════════════
def write_blocked(domains, out_dir, max_bytes):
    """يكتب ملفات البلاك ليست: ||domain^"""
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.startswith("blacklist") and f.endswith(".txt"):
            try:
                os.remove(os.path.join(out_dir, f))
            except OSError:
                pass

    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Adguard Adblock only\n"
        "! Description: Pure blocked domains (whitelist has priority)\n"
        f"! Total domains: {len(domains)}\n"
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

    for d in domains:
        line = f"||{d}^\n"
        b = len(line.encode("utf-8"))
        if cur_size + b > max_bytes and cur_lines:
            flush()
        cur_lines.append(line)
        cur_size += b

    flush()
    return files


def write_whitelist(domains, out_dir):
    """يكتب ملف الوايت ليست: @@||domain^"""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "whitelist.txt")

    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Adguard Adblock only - Whitelist\n"
        "! Description: Allowed domains (conflicts go here)\n"
        f"! Total domains: {len(domains)}\n"
        "! Generated: "
        + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + "\n"
        "!\n"
    )

    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)
        for d in sorted(domains):
            fh.write(f"@@||{d}^\n")
    return path


# ═══════════════════════════════════════════════
def main():
    print("=" * 60)
    print("  Adguard-Adblock-only  |  Deep Full-File Scan")
    print("  Rule: WHITELIST has priority over BLACKLIST")
    print("=" * 60)

    urls = read_urls(LIST_FILE)
    print(f"[+] عدد الروابط في list2.txt: {len(urls)}\n")

    session = build_session()
    blocked, allowed = set(), set()

    total_lines_scanned    = 0
    total_bytes_downloaded = 0
    total_blocked_lines    = 0
    total_allowed_lines    = 0
    total_regex_skipped    = 0
    total_hash_skipped     = 0
    failed_urls = []

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {url}")
        text, size = fetch(session, url)

        if not text:
            failed_urls.append(url)
            continue

        total_bytes_downloaded += size
        lines = text.splitlines()
        file_lines = len(lines)
        total_lines_scanned += file_lines

        file_blocked_lines = 0
        file_allowed_lines = 0
        file_blocked_new   = 0
        file_allowed_new   = 0
        file_regex_skipped = 0
        file_hash_skipped  = 0

        for line in lines:
            s = line.strip()
            if not s or len(s) > 1024:
                continue

            if s.startswith("!") or (s.startswith("[") and s.endswith("]")):
                continue
            if "#" in s:
                file_hash_skipped += 1
                continue
            if looks_like_regex(s):
                file_regex_skipped += 1
                continue

            domain, allowed_flag = extract_domain(s)
            if not domain:
                continue

            if allowed_flag:
                file_allowed_lines += 1
                before = len(allowed)
                allowed.add(domain)
                if len(allowed) > before:
                    file_allowed_new += 1
            else:
                file_blocked_lines += 1
                before = len(blocked)
                blocked.add(domain)
                if len(blocked) > before:
                    file_blocked_new += 1

        total_blocked_lines += file_blocked_lines
        total_allowed_lines += file_allowed_lines
        total_regex_skipped += file_regex_skipped
        total_hash_skipped  += file_hash_skipped

        print(f"    ├─ الحجم: {size/1024:.1f} KB")
        print(f"    ├─ الأسطر المفحوصة: {file_lines:,}")
        print(f"    ├─ أسطر حظر: {file_blocked_lines:,}  (جديد: +{file_blocked_new:,})")
        print(f"    ├─ أسطر سماح: {file_allowed_lines:,}  (جديد: +{file_allowed_new:,})")
        print(f"    ├─ Regex اتشال: {file_regex_skipped:,}")
        print(f"    └─ # اتشال: {file_hash_skipped:,}")

    # ═══════════════════════════════════════════════
    # 🔑 منطق الأولوية: الوايت تغلب البلاك
    # ═══════════════════════════════════════════════
    conflicts    = blocked & allowed        # في الاتنين -> يروح للوايت
    allowed_only = allowed - blocked        # وايت بس
    pure_blocked = blocked - allowed        # بلاك بس (يفضل)

    # الوايت النهائي = كل اللي كان مسموح (سواء مسموح بس أو متعارض)
    final_whitelist = allowed_only | conflicts   # = allowed
    final_blacklist = sorted(pure_blocked)

    duplicates_removed = total_blocked_lines - len(blocked)

    print("\n" + "=" * 60)
    print("  📊 إحصائيات الديب سيرش الكامل")
    print("=" * 60)
    print(f"  عدد الروابط الإجمالي:        {len(urls)}")
    print(f"  عدد الروابط اللي فشلت:       {len(failed_urls)}")
    print(f"  إجمالي البايتات المحمّلة:    {total_bytes_downloaded:,} "
          f"({total_bytes_downloaded/1024/1024:.2f} MB)")
    print(f"  إجمالي الأسطر المفحوصة:      {total_lines_scanned:,}")
    print()
    print(f"  🚫 إجمالي أسطر الحظر:          {total_blocked_lines:,}")
    print(f"  ✅ إجمالي أسطر السماح:          {total_allowed_lines:,}")
    print(f"  🔴 Regex اللي اتشال:           {total_regex_skipped:,}")
    print(f"  🟡 # اللي اتشال:               {total_hash_skipped:,}")
    print()
    print(f"  الدومينات المحظورة الفريدة:   {len(blocked):,}")
    print(f"  الدومينات المسموحة الفريدة:   {len(allowed):,}")
    print()
    print("  " + "-" * 50)
    print("  🔑 تطبيق قاعدة: الوايت تغلب البلاك")
    print(f"     ├─ مسموح بس → whitelist:    {len(allowed_only):,}")
    print(f"     ├─ متعارض → يتشال من بلاك:  {len(conflicts):,}")
    print(f"     └─ محظور بس → blacklist:    {len(pure_blocked):,}")
    print()
    print(f"  📦 المكرر اللي اتشال:          {duplicates_removed:,}")
    print()
    print(f"  ✨ البلاك ليست النهائي:         {len(final_blacklist):,}")
    print(f"  ✨ الوايت ليست النهائي:         {len(final_whitelist):,}")
    print("=" * 60)

    if failed_urls:
        print("\n⚠️  روابط فشلت:")
        for u in failed_urls:
            print(f"   - {u}")

    # ═══ كتابة الملفات ═══
    print("\n[+] كتابة الملفات...")
    files = write_blocked(final_blacklist, OUT_DIR, MAX_BYTES)
    for f in files:
        size = os.path.getsize(f)
        print(f"    ✅ {f}  ({size/1024/1024:.2f} MB)")

    wl = write_whitelist(final_whitelist, OUT_DIR)
    wl_size = os.path.getsize(wl)
    print(f"    ✅ {wl}  ({wl_size/1024:.1f} KB)")

    print("\n[✓] خلص بنجاح")


if __name__ == "__main__":
    main()
