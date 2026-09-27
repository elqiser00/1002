#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero Blacklist Builder
- يقرأ الروابط من list2.txt
- يحمّل كل مصدر (يدعم gzip / zip / tar / tar.gz + redirects + cookies + headers + SSL fallback)
- يستخرج الدومينات من adblock / hosts / plain
- يحوّلها إلى: ||domain^$important
- لو دومين مسموح وفي نفس الوقت محظور -> يتحذف الاتنين
- الفاينل = المحظور فقط بدون تكرار
- يكتب في مجلد zero/ ويقسّم على 90 ميجا
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

LIST_FILE     = "list2.txt"
OUT_DIR       = "zero"
MAX_BYTES     = 90 * 1024 * 1024
TIMEOUT       = 90
MAX_RETRIES   = 3

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

COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#", "#@$#")


# ---------- قراءة الروابط ----------
def clean_url(raw: str) -> str:
    u = raw.strip().strip('"\'').strip()
    # 🔴 الحل لمشكلة النقطتين والأخطاء اللي بتتلزق في آخر الرابط
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


# ---------- HTTP ----------
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
                chunks = [tar.extractfile(m).read()
                          for m in tar.getmembers()
                          if m.isfile() and tar.extractfile(m)]
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
    for verify in (True, False):  # SSL fallback
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=verify)
            r.raise_for_status()
            break
        except requests.exceptions.SSLError:
            print("    [!] SSL error، إعادة المحاولة بدون تحقق...")
            continue
        except Exception as exc:
            print(f"    [!] {exc}")
            return None
    if r is None:
        return None

    body = r.content
    if not body:
        return None

    body = try_decompress(body, url, r.headers.get("Content-Type", ""))
    text = decode_bytes(body)

    # لو الصفحة HTML خطأ -> تجاهل
    head = text[:400].lstrip().lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        if "||" not in text and "0.0.0.0" not in text:
            print("    [!] محتوى HTML مش ليست، تجاهل")
            return None

    return text


# ---------- تحليل الأسطر ----------
HOSTS_IP_RE      = re.compile(r"^([0-9a-fA-F:.]+)\s+([^\s#]+)")
ADBLOCK_DOM_RE   = re.compile(r"^([a-z0-9][a-z0-9.\-]*[a-z0-9])", re.I)


def is_comment_or_header(s: str) -> bool:
    if not s:
        return True
    if s.startswith("!") or s.startswith("#"):
        return True
    if s.startswith("[") and s.endswith("]"):
        return True
    return False


def parse_line(line, blocked, allowed):
    s = line.strip()
    if is_comment_or_header(s):
        return
    if len(s) > 1024:
        return

    # -------- hosts format --------
    m = HOSTS_IP_RE.match(s)
    if m:
        host = m.group(2).lower().rstrip(".")
        if host in SKIP_HOSTS:
            return
        if not DOMAIN_RE.match(host):
            return
        blocked.add(host)
        return

    # -------- كوزمتك --------
    for marker in COSMETIC_MARKERS:
        if marker in s:
            return

    # -------- Allowed --------
    allowed_flag = False
    if s.startswith("@@"):
        allowed_flag = True
        s = s[2:]

    # -------- regex --------
    if s.startswith("/") or s.endswith("/"):
        return

    domain = None

    if s.startswith("||"):
        m = ADBLOCK_DOM_RE.match(s[2:])
        if m:
            domain = m.group(1).lower()
    elif s.startswith("|"):
        rest = re.sub(r"^https?://", "", s[1:], flags=re.I)
        m = ADBLOCK_DOM_RE.match(rest)
        if m:
            domain = m.group(1).lower()
    else:
        m = re.match(r"^([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})(?:[\^/$*?\s]|$)", s, re.I)
        if m:
            domain = m.group(1).lower()
        else:
            m = re.match(r"^https?://([a-z0-9][a-z0-9.\-]*)", s, re.I)
            if m:
                domain = m.group(1).lower()

    if not domain:
        return

    domain = domain.strip(".").lower()
    if not domain or domain in SKIP_HOSTS:
        return
    if not DOMAIN_RE.match(domain):
        return
    if len(domain) > 253:
        return

    if allowed_flag:
        allowed.add(domain)
    else:
        blocked.add(domain)


# ---------- كتابة المخرجات ----------
def write_output(domains, out_dir, max_bytes):
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.endswith(".txt"):
            try:
                os.remove(os.path.join(out_dir, f))
            except OSError:
                pass

    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Zero Blacklist\n"
        "! Description: Auto-generated unique blocked domains\n"
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
        line = f"||{d}^$important\n"
        b = len(line.encode("utf-8"))
        if cur_size + b > max_bytes and cur_lines:
            flush()
        cur_lines.append(line)
        cur_size += b

    flush()
    return files


# ---------- main ----------
def main():
    urls = read_urls(LIST_FILE)
    print(f"[+] عدد الروابط: {len(urls)}")

    session = build_session()
    blocked, allowed = set(), set()

    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {url}")
        text = fetch(session, url)
        if not text:
            continue
        before = len(blocked)
        for line in text.splitlines():
            parse_line(line, blocked, allowed)
        print(f"    -> +{len(blocked) - before} (إجمالي {len(blocked)})")

    print(f"[+] محظور={len(blocked)}  مسموح={len(allowed)}")
    conflicts = blocked & allowed
    print(f"[+] متعارض (محظور+مسموح) = {len(conflicts)}  -> يُحذف")

    final = sorted(blocked - allowed)
    print(f"[+] الدومينات النهائية الفريدة = {len(final)}")

    files = write_output(final, OUT_DIR, MAX_BYTES)
    for f in files:
        size = os.path.getsize(f)
        print(f"[+] {f}  ({size/1024/1024:.2f} MB)")


if __name__ == "__main__":
    main()
