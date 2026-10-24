#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adguard-Adblock-only Builder
- Zero Tolerance for Regex
- Strict Global Rule: If ANY domain is blocked, REMOVE it and ALL its parents from ALLOW list.
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

def is_complex_or_regex(s: str) -> bool:
    if not s: return True
    if s.startswith("/") or s.endswith("/"): return True
    core = s
    if core.startswith("@@"): core = core[2:]
    if core.startswith("||"): core = core[2:]
    elif core.startswith("|"): core = core[1:]
    core = re.sub(r'\$.*$', '', core)
    core = core.rstrip("^|")
    if "/" in core: return True
    for char in ["*", "\\", "[", "]", "(", ")", "{", "}", "?", "+", "|", "^", "$"]:
        if char in core: return True
    return False

def clean_url(raw: str) -> str:
    u = raw.strip().strip('"\'').strip()
    u = re.sub(r"[:;,\.\s]+$", "", u)
    return u

def read_urls(path):
    urls, seen = [], set()
    if not os.path.isfile(path): return urls
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"): continue
            u = clean_url(line)
            if not u.lower().startswith(("http://", "https://")): continue
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls

def build_session():
    s = requests.Session()
    retry = Retry(total=MAX_RETRIES, backoff_factor=1.5, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset(["GET", "HEAD"]))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*", "Accept-Encoding": "gzip, deflate",
    })
    return s

def decode_bytes(data):
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try: return data.decode(enc)
        except Exception: continue
    return data.decode("utf-8", errors="ignore")

def try_decompress(data, url, content_type):
    ct = (content_type or "").lower()
    low_url = url.lower()
    if low_url.endswith(".gz") or "gzip" in ct or data[:2] == b"\x1f\x8b":
        try: return gzip.decompress(data)
        except Exception:
            try: return gzip.decompress(data[data.find(b"\x1f\x8b"):])
            except Exception: pass
    if low_url.endswith((".tgz", ".tar.gz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                chunks = [tar.extractfile(m).read() for m in tar.getmembers() if m.isfile() and tar.extractfile(m)]
                if chunks: return b"\n".join(chunks)
        except Exception: pass
    if low_url.endswith(".zip") or "zip" in ct or data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                chunks = [z.read(name) for name in z.namelist() if not name.endswith("/")]
                if chunks: return b"\n".join(chunks)
        except Exception: pass
    return data

def fetch_full(session, url):
    r = None
    for verify in (True, False):
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=verify, stream=True)
            r.raise_for_status()
            break
        except requests.exceptions.SSLError: continue
        except Exception: return None, 0
    if not r: return None, 0
    chunks = []
    try:
        for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
            if chunk: chunks.append(chunk)
    except Exception: pass
    body = b"".join(chunks)
    if not body: return None, 0
    body = try_decompress(body, url, r.headers.get("Content-Type", ""))
    text = decode_bytes(body)
    head = text[:400].lstrip().lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        if "||" not in text and "0.0.0.0" not in text: return None, 0
    return text, len(body)

HOSTS_IP_RE    = re.compile(r"^([0-9a-fA-F:.]+)\s+([^\s#]+)")
ADBLOCK_DOM_RE = re.compile(r"^([a-z0-9][a-z0-9.\-]*[a-z0-9])", re.I)

def clean_domain(d: str) -> str:
    if not d: return ""
    d = re.split(r"[/:?#&|]", d)[0]
    return d.strip(".").lower()

def extract_domain(s):
    if not s or len(s) > 1024: return None, None
    if s.startswith("!") or (s.startswith("[") and s.endswith("]")): return None, None
    if "#" in s: return None, None
    if is_complex_or_regex(s): return None, None

    m = HOSTS_IP_RE.match(s)
    if m:
        host = clean_domain(m.group(2))
        if not host or host in SKIP_HOSTS or not DOMAIN_RE.match(host): return None, None
        return host, False

    allowed_flag = False
    if s.startswith("@@"):
        allowed_flag = True
        s = s[2:]

    domain = None
    if s.startswith("||"):
        m = ADBLOCK_DOM_RE.match(s[2:])
        if m: domain = m.group(1)
    elif s.startswith("|"):
        rest = re.sub(r"^https?://", "", s[1:], flags=re.I)
        m = ADBLOCK_DOM_RE.match(rest)
        if m: domain = m.group(1)
    else:
        tmp = re.sub(r"^https?://", "", s, flags=re.I)
        tmp = re.split(r"[/:?#&\s]", tmp)[0]
        if DOMAIN_RE.match(tmp): domain = tmp

    if not domain: return None, None
    domain = clean_domain(domain)
    if not domain or domain in SKIP_HOSTS or not DOMAIN_RE.match(domain): return None, None
    return domain, allowed_flag

def write_output(blocked, allowed, out_dir, max_bytes):
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.endswith(".txt"):
            try: os.remove(os.path.join(out_dir, f))
            except OSError: pass

    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Adguard Adblock only\n"
        "! Description: Global Strict Override (Block destroys Allow)\n"
        f"! Blocked: {len(blocked)} | Allowed: {len(allowed)}\n"
        "! Generated: " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + "\n!\n"
    )
    header_bytes = len(header.encode("utf-8"))

    files, idx, cur_lines, cur_size = [], 1, [], header_bytes

    def flush():
        nonlocal idx, cur_lines, cur_size
        if not cur_lines: return
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
        if cur_size + b > max_bytes and cur_lines: flush()
        cur_lines.append(line)
        cur_size += b

    for d in blocked: add_line(f"||{d}^$important\n")
    for d in allowed: add_line(f"@@||{d}^$important\n")
    flush()
    return files

def main():
    print("=" * 60)
    print("  Adguard-Adblock-only  |  Global Strict Override")
    print("=" * 60)

    session = build_session()
    blocked, allowed = set(), set()
    
    # 1. تحميل القائمة المخصصة
    print(f"[*] تحميل القائمة المخصصة: {FORCED_BLOCKLIST_URL}")
    text, _ = fetch_full(session, FORCED_BLOCKLIST_URL)
    if text:
        for line in text.splitlines():
            for part in re.split(r'\s+', line.strip()):
                if not part or is_complex_or_regex(part) or "#" in part:
                    continue
                domain, allowed_flag = extract_domain(part)
                if domain:
                    if allowed_flag: allowed.add(domain)
                    else: blocked.add(domain)
    
    # 2. تحميل الروابط العادية
    urls = read_urls(LIST_FILE)
    print(f"\n[+] عدد الروابط في list2.txt: {len(urls)}\n")

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {url}")
        text, _ = fetch_full(session, url)
        if not text: continue
        for line in text.splitlines():
            s = line.strip()
            if not s or len(s) > 1024: continue
            if s.startswith("!") or (s.startswith("[") and s.endswith("]")): continue
            if is_complex_or_regex(s) or "#" in s: continue
            
            domain, allowed_flag = extract_domain(s)
            if not domain: continue
            if allowed_flag: allowed.add(domain)
            else: blocked.add(domain)

    # ═══════════════════════════════════════════════════════
    # 🔥 القانون العالمي الصارم (تصحيح الخطأ):
    # أي دومين محظور -> نشيل الدومين نفسه + كل آباءه من قائمة السماح
    # ═══════════════════════════════════════════════════════
    
    final_allowed = set(allowed)
    
    for d in blocked:
        # 1. نشيل الدومين نفسه من السماح فوراً
        if d in final_allowed:
            final_allowed.remove(d)
            
        # 2. نشيل كل آباءه من السماح
        parts = d.split('.')
        # i=1 عشان نجيب الأب (مثلاً: ads.tiktok.com -> tiktok.com)
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in final_allowed:
                final_allowed.remove(parent)
    
    final_blocked = set(blocked)
    final_blocked_list = sorted(final_blocked)
    final_allowed_list = sorted(final_allowed)

    print("\n" + "=" * 60)
    print(f"  🚫 محظور نهائي: {len(final_blocked_list):,}")
    print(f"  ✅ مسموح نهائي: {len(final_allowed_list):,}")
    print("=" * 60)

    print("\n[+] كتابة الملفات...")
    files = write_output(final_blocked_list, final_allowed_list, OUT_DIR, MAX_BYTES)
    for f in files:
        size = os.path.getsize(f)
        print(f"    ✅ {f}  ({size/1024/1024:.2f} MB)")

if __name__ == "__main__":
    main()
