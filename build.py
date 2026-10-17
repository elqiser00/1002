#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adguard-Adblock-only Builder
- فلترة أوتوماتيكية 100% (بدون أي قوائم يدوية أو مراجع خارجية)
- الوايت ليست (الموجودة في روابطك) هي الكلمة العليا
- أي دومين أو نطاق فرعي منه مسموح، يتم حذفه من البلاك ليست فوراً
- بدون $important عشان نضمن إن التطبيقات متقفلش
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

    declared_size = 0
    if "Content-Length" in r.headers:
        try:
            declared_size = int(r.headers["Content-Length"])
        except (ValueError, TypeError):
            declared_size = 0

    chunks = []
    total_received = 0
    try:
        for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                chunks.append(chunk)
                total_received += len(chunk)
    except Exception as exc:
        print(f"    [!] خطأ أثناء التحميل: {exc}")
        pass

    body = b"".join(chunks)
    actual_size = len(body)

    if actual_size == 0:
        return None, 0, False

    is_complete = True
    if declared_size > 0 and actual_size < declared_size:
        is_complete = False
        print(f"    ⚠️  تحذير: الملف ناقص! "
              f"(المتوقع {declared_size:,} / استلمنا {actual_size:,})")

    body = try_decompress(body, url, r.headers.get("Content-Type", ""))
    text = decode_bytes(body)

    head = text[:400].lstrip().lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        if "||" not in text and "0.0.0.0" not in text:
            print("    [!] محتوى HTML مش ليست، تجاهل")
            return None, actual_size, is_complete

    return text, actual_size, is_complete


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
        "! Description: Automatic Natural Filtering (Pure Data)\n"
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

    for d in blocked_domains:
        add_line(f"||{d}^\n")

    for d in allowed_domains:
        add_line(f"@@||{d}^\n")

    flush()
    return files


def main():
    print("=" * 60)
    print("  Adguard-Adblock-only  |  Auto Pure Filtering")
    print("  No manual lists, No references. Data from list2.txt only.")
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
    incomplete_files       = []
    failed_urls            = []

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {url}")
        text, size, is_complete = fetch_full(session, url)

        if not text:
            failed_urls.append(url)
            continue

        if not is_complete:
            incomplete_files.append(url)

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

        complete_flag = "✅" if is_complete else "⚠️  ناقص"
        print(f"    ├─ الحجم: {size/1024:.1f} KB  {complete_flag}")
        print(f"    ├─ الأسطر المفحوصة: {file_lines:,}")
        print(f"    ├─ أسطر حظر: {file_blocked_lines:,}  (جديد: +{file_blocked_new:,})")
        print(f"    ├─ أسطر سماح: {file_allowed_lines:,}  (جديد: +{file_allowed_new:,})")
        print(f"    ├─ Regex اتشال: {file_regex_skipped:,}")
        print(f"    └─ # اتشال: {file_hash_skipped:,}")

    # ═══ الفلترة النهائية (الاعتماد على بيانات الروابط فقط) ═══
    final_blocked = set()
    final_allowed = allowed.copy()
    removed_by_parent = 0

    for d in blocked:
        # 1. لو الدومين نفسه مسموح -> يتشال
        if d in allowed:
            continue
        
        # 2. لو فيه أب للدومين مسموح -> يتشال (عشان نحمي التطبيقات)
        is_parent_allowed = False
        parts = d.split('.')
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in allowed:
                is_parent_allowed = True
                break
                
        if is_parent_allowed:
            removed_by_parent += 1
            continue
            
        # 3. لو مش مسموح بأي شكل، يتحظر عادي (بدون $important عشان منكسرش حاجة)
        final_blocked.add(d)

    final_blocked_list = sorted(final_blocked)
    final_allowed_list = sorted(final_allowed)

    duplicates_removed = total_blocked_lines - len(blocked)

    print("\n" + "=" * 60)
    print("  📊 إحصائيات الديب سيرش الكامل")
    print("=" * 60)
    print(f"  عدد الروابط الإجمالي:        {len(urls)}")
    print(f"  عدد الروابط اللي فشلت:       {len(failed_urls)}")
    print(f"  عدد الملفات الناقصة:          {len(incomplete_files)}")
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
    print("  🧹 الفلترة النهائية (أوتوماتيكية 100%):")
    print(f"     ├─ محظور خالص (يفضل):       {len(final_blocked):,}  ✅")
    print(f"     ├─ مسموح صريح (يفضل):       {len(final_allowed):,}  ✅")
    print(f"     └─ مسموح بسبب الأب (اتشال): {removed_by_parent:,}  🛡️")
    print()
    print(f"  📦 المكرر اللي اتشال:          {duplicates_removed:,}")
    print()
    print(f"  ✨ إجمالي الدومينات في الملف:   {len(final_blocked_list) + len(final_allowed_list):,}")
    print("=" * 60)

    print("\n[+] كتابة الملفات...")
    files = write_output(final_blocked_list, final_allowed_list, OUT_DIR, MAX_BYTES)
    for f in files:
        size = os.path.getsize(f)
        print(f"    ✅ {f}  ({size/1024/1024:.2f} MB)")

    print("\n[✓] خلص بنجاح")


if __name__ == "__main__":
    main()
