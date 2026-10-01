#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adguard-Adblock Builder

- Deep Scan لكل الملفات
- استخراج دومينات الحظر والـ Whitelist
- الاحتفاظ بالـ Whitelist وعدم استخدامها لحذف الحظر
- إذا كان الدومين محظور + مسموح:
    يتم إخراج القاعدتين معًا
- إزالة التكرارات
- إخراج ملف AdGuard/Adblock صالح
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


# ═══════════════════════════════════════════════
# الإعدادات
# ═══════════════════════════════════════════════

LIST_FILE   = "list2.txt"
OUT_DIR     = "Adguard-Adblock-only"

MAX_BYTES   = 90 * 1024 * 1024
TIMEOUT     = 120
MAX_RETRIES = 3


# ═══════════════════════════════════════════════
# Regex
# ═══════════════════════════════════════════════

DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.I,
)

SKIP_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "localdomain",
    "broadcasthost",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "255.255.255.255",
}

COSMETIC_MARKERS = (
    "##",
    "#@#",
    "#?#",
    "#$#",
    "#%#",
    "#@$#",
)

HOSTS_IP_RE = re.compile(
    r"^([0-9a-fA-F:.]+)\s+([^\s#]+)"
)

ADBLOCK_DOM_RE = re.compile(
    r"^([a-z0-9][a-z0-9.\-]*[a-z0-9])",
    re.I,
)


# ═══════════════════════════════════════════════
# قراءة الروابط
# ═══════════════════════════════════════════════

def clean_url(raw: str) -> str:
    u = raw.strip().strip('"\'').strip()
    u = re.sub(r"[:;,\.\s]+$", "", u)
    return u


def read_urls(path):
    urls = []
    seen = set()

    if not os.path.isfile(path):
        print(f"[!] {path} غير موجود")
        return urls

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as fh:

        for line in fh:

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            u = clean_url(line)

            if not u.lower().startswith(
                ("http://", "https://")
            ):
                continue

            if u not in seen:

                seen.add(u)
                urls.append(u)

    return urls


# ═══════════════════════════════════════════════
# HTTP Session
# ═══════════════════════════════════════════════

def build_session():

    session = requests.Session()

    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=1.5,
        status_forcelist=(
            429,
            500,
            502,
            503,
            504,
        ),
        allowed_methods=frozenset([
            "GET",
            "HEAD",
        ]),
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=20,
    )

    session.mount(
        "http://",
        adapter
    )

    session.mount(
        "https://",
        adapter
    )

    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })

    return session


# ═══════════════════════════════════════════════
# Decode
# ═══════════════════════════════════════════════

def decode_bytes(data):

    for encoding in (
        "utf-8",
        "utf-8-sig",
        "latin-1",
    ):

        try:
            return data.decode(encoding)

        except Exception:
            continue

    return data.decode(
        "utf-8",
        errors="ignore"
    )


# ═══════════════════════════════════════════════
# فك الضغط
# ═══════════════════════════════════════════════

def try_decompress(
    data,
    url,
    content_type
):

    ct = (
        content_type or ""
    ).lower()

    low_url = url.lower()

    # GZIP
    if (
        low_url.endswith(".gz")
        or "gzip" in ct
    ):

        try:
            return gzip.decompress(data)

        except Exception:

            try:

                pos = data.find(
                    b"\x1f\x8b"
                )

                if pos >= 0:
                    return gzip.decompress(
                        data[pos:]
                    )

            except Exception:
                pass

    # TAR.GZ / TGZ
    if low_url.endswith(
        (".tgz", ".tar.gz")
    ):

        try:

            with tarfile.open(
                fileobj=io.BytesIO(data),
                mode="r:gz"
            ) as tar:

                chunks = []

                for member in tar.getmembers():

                    if not member.isfile():
                        continue

                    file_obj = tar.extractfile(
                        member
                    )

                    if file_obj:
                        chunks.append(
                            file_obj.read()
                        )

                if chunks:
                    return b"\n".join(
                        chunks
                    )

        except Exception:
            pass

    # ZIP
    if (
        low_url.endswith(".zip")
        or "zip" in ct
    ):

        try:

            with zipfile.ZipFile(
                io.BytesIO(data)
            ) as archive:

                chunks = []

                for name in archive.namelist():

                    if name.endswith("/"):
                        continue

                    try:
                        chunks.append(
                            archive.read(name)
                        )

                    except Exception:
                        pass

                if chunks:
                    return b"\n".join(
                        chunks
                    )

        except Exception:
            pass

    return data


# ═══════════════════════════════════════════════
# تحميل القائمة
# ═══════════════════════════════════════════════

def fetch(session, url):

    response = None

    for verify in (
        True,
        False,
    ):

        try:

            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=verify,
            )

            response.raise_for_status()

            break

        except requests.exceptions.SSLError:

            print(
                "    [!] SSL error، "
                "إعادة المحاولة بدون تحقق..."
            )

            continue

        except Exception as exc:

            print(
                f"    [!] {exc}"
            )

            return None, 0

    if response is None:
        return None, 0

    body = response.content

    if not body:
        return None, 0

    original_size = len(body)

    body = try_decompress(
        body,
        url,
        response.headers.get(
            "Content-Type",
            ""
        ),
    )

    text = decode_bytes(body)

    head = (
        text[:400]
        .lstrip()
        .lower()
    )

    if (
        head.startswith(
            "<!doctype html"
        )
        or
        head.startswith("<html")
    ):

        if (
            "||" not in text
            and "0.0.0.0" not in text
        ):

            print(
                "    [!] محتوى HTML "
                "مش ليست، تجاهل"
            )

            return None, original_size

    return text, original_size


# ═══════════════════════════════════════════════
# هل السطر تعليق؟
# ═══════════════════════════════════════════════

def is_comment_or_header(s: str) -> bool:

    if not s:
        return True

    if s.startswith("!"):
        return True

    if s.startswith("#"):
        return True

    if (
        s.startswith("[")
        and s.endswith("]")
    ):
        return True

    return False


# ═══════════════════════════════════════════════
# استخراج الدومين
# ═══════════════════════════════════════════════

def extract_domain(s):

    """
    يرجع:

        (domain, False)
            = Block

        (domain, True)
            = Whitelist

        (None, None)
            = غير صالح
    """

    if is_comment_or_header(s):
        return None, None

    if len(s) > 1024:
        return None, None

    # ═════════════════════════════════════════════
    # Hosts
    # ═════════════════════════════════════════════

    match = HOSTS_IP_RE.match(s)

    if match:

        host = (
            match.group(2)
            .lower()
            .rstrip(".")
        )

        if host in SKIP_HOSTS:
            return None, None

        if not DOMAIN_RE.match(host):
            return None, None

        return host, False

    # ═════════════════════════════════════════════
    # Cosmetic filters
    # ═════════════════════════════════════════════

    for marker in COSMETIC_MARKERS:

        if marker in s:
            return None, None

    # ═════════════════════════════════════════════
    # Whitelist
    # ═════════════════════════════════════════════

    allowed_flag = False

    if s.startswith("@@"):

        allowed_flag = True
        s = s[2:]

    # ═════════════════════════════════════════════
    # Regex rules
    # ═════════════════════════════════════════════

    if (
        s.startswith("/")
        or s.endswith("/")
    ):
        return None, None

    domain = None

    # ||example.com^
    if s.startswith("||"):

        match = ADBLOCK_DOM_RE.match(
            s[2:]
        )

        if match:
            domain = (
                match.group(1)
                .lower()
            )

    # |https://example.com
    elif s.startswith("|"):

        rest = re.sub(
            r"^https?://",
            "",
            s[1:],
            flags=re.I,
        )

        match = ADBLOCK_DOM_RE.match(
            rest
        )

        if match:
            domain = (
                match.group(1)
                .lower()
            )

    else:

        # plain domain
        match = re.match(
            r"^([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})"
            r"(?:[\^/$*?\s]|$)",
            s,
            re.I,
        )

        if match:

            domain = (
                match.group(1)
                .lower()
            )

        else:

            # URL
            match = re.match(
                r"^https?://"
                r"([a-z0-9][a-z0-9.\-]*)",
                s,
                re.I,
            )

            if match:

                domain = (
                    match.group(1)
                    .lower()
                )

    if not domain:
        return None, None

    domain = (
        domain
        .strip(".")
        .lower()
    )

    if not domain:
        return None, None

    if domain in SKIP_HOSTS:
        return None, None

    if not DOMAIN_RE.match(domain):
        return None, None

    if len(domain) > 253:
        return None, None

    return domain, allowed_flag


# ═══════════════════════════════════════════════
# كتابة الناتج
# ═══════════════════════════════════════════════

def write_output(
    blocked,
    allowed,
    out_dir,
    max_bytes
):

    os.makedirs(
        out_dir,
        exist_ok=True
    )

    # حذف ملفات txt القديمة
    for filename in os.listdir(out_dir):

        if filename.endswith(".txt"):

            try:

                os.remove(
                    os.path.join(
                        out_dir,
                        filename
                    )
                )

            except OSError:
                pass

    # ═══════════════════════════════════════════
    # Header
    # ═══════════════════════════════════════════

    total_domains = (
        len(blocked)
        + len(allowed)
    )

    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Adguard Adblock only\n"
        "! Description: "
        "Blocked domains + Whitelist domains\n"
        f"! Total unique blocked domains: "
        f"{len(blocked)}\n"
        f"! Total unique whitelist domains: "
        f"{len(allowed)}\n"
        f"! Total unique domains: "
        f"{total_domains}\n"
        "! Generated: "
        + time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime()
        )
        + "\n"
        "!\n"
    )

    header_bytes = len(
        header.encode("utf-8")
    )

    files = []

    index = 1

    current_lines = []

    current_size = header_bytes

    # ═══════════════════════════════════════════
    # تقسيم الملفات
    # ═══════════════════════════════════════════

    def flush():

        nonlocal index
        nonlocal current_lines
        nonlocal current_size

        if not current_lines:
            return

        if index == 1:
            filename = "blacklist.txt"
        else:
            filename = (
                f"blacklist_{index}.txt"
            )

        filepath = os.path.join(
            out_dir,
            filename
        )

        with open(
            filepath,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as fh:

            fh.write(header)
            fh.writelines(
                current_lines
            )

        files.append(filepath)

        index += 1

        current_lines = []

        current_size = header_bytes

    # ═══════════════════════════════════════════
    # أولًا: Block
    # ═══════════════════════════════════════════

    for domain in sorted(blocked):

        line = (
            f"||{domain}^$important\n"
        )

        line_size = len(
            line.encode("utf-8")
        )

        if (
            current_size + line_size > max_bytes
            and current_lines
        ):
            flush()

        current_lines.append(line)

        current_size += line_size

    # ═══════════════════════════════════════════
    # ثانيًا: Whitelist
    # ═══════════════════════════════════════════

    for domain in sorted(allowed):

        line = (
            f"@@||{domain}^\n"
        )

        line_size = len(
            line.encode("utf-8")
        )

        if (
            current_size + line_size > max_bytes
            and current_lines
        ):
            flush()

        current_lines.append(line)

        current_size += line_size

    # آخر ملف
    flush()

    return files


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════

def main():

    print("=" * 60)
    print(
        "  Adguard-Adblock Builder"
    )
    print(
        "  Deep Full-File Scan"
    )
    print("=" * 60)

    # ═══════════════════════════════════════════
    # قراءة الروابط
    # ═══════════════════════════════════════════

    urls = read_urls(
        LIST_FILE
    )

    print(
        f"[+] عدد الروابط في "
        f"{LIST_FILE}: {len(urls)}\n"
    )

    session = build_session()

    # ═══════════════════════════════════════════
    # Sets
    # ═══════════════════════════════════════════

    blocked = set()
    allowed = set()

    # ═══════════════════════════════════════════
    # Statistics
    # ═══════════════════════════════════════════

    total_lines_scanned = 0
    total_bytes_downloaded = 0

    total_blocked_lines = 0
    total_allowed_lines = 0

    failed_urls = []

    # ═══════════════════════════════════════════
    # Scan
    # ═══════════════════════════════════════════

    for index, url in enumerate(
        urls,
        1
    ):

        print(
            f"[{index}/{len(urls)}] {url}"
        )

        text, size = fetch(
            session,
            url
        )

        if not text:

            failed_urls.append(url)

            continue

        total_bytes_downloaded += size

        lines = text.splitlines()

        file_lines = len(lines)

        total_lines_scanned += (
            file_lines
        )

        file_blocked_lines = 0
        file_allowed_lines = 0

        file_blocked_new = 0
        file_allowed_new = 0

        # ═══════════════════════════════════════
        # Full Scan
        # ═══════════════════════════════════════

        for line in lines:

            s = line.strip()

            if not s:
                continue

            if len(s) > 1024:
                continue

            domain, allowed_flag = (
                extract_domain(s)
            )

            if not domain:
                continue

            # ═══════════════════════════════
            # Whitelist
            # ═══════════════════════════════

            if allowed_flag:

                file_allowed_lines += 1

                before = len(
                    allowed
                )

                allowed.add(
                    domain
                )

                if len(allowed) > before:
                    file_allowed_new += 1

            # ═══════════════════════════════
            # Block
            # ═══════════════════════════════

            else:

                file_blocked_lines += 1

                before = len(
                    blocked
                )

                blocked.add(
                    domain
                )

                if len(blocked) > before:
                    file_blocked_new += 1

        total_blocked_lines += (
            file_blocked_lines
        )

        total_allowed_lines += (
            file_allowed_lines
        )

        print(
            f"    ├─ الحجم: "
            f"{size / 1024:.1f} KB"
        )

        print(
            f"    ├─ الأسطر المفحوصة: "
            f"{file_lines:,}"
        )

        print(
            f"    ├─ أسطر حظر: "
            f"{file_blocked_lines:,} "
            f"(جديد: +{file_blocked_new:,})"
        )

        print(
            f"    └─ أسطر سماح: "
            f"{file_allowed_lines:,} "
            f"(جديد: +{file_allowed_new:,})"
        )

    # ═══════════════════════════════════════════
    # الإحصائيات النهائية
    # ═══════════════════════════════════════════

    conflicts = (
        blocked & allowed
    )

    blocked_only = (
        blocked - allowed
    )

    allowed_only = (
        allowed - blocked
    )

    duplicates_blocked = (
        total_blocked_lines
        - len(blocked)
    )

    duplicates_allowed = (
        total_allowed_lines
        - len(allowed)
    )

    total_duplicates = (
        duplicates_blocked
        + duplicates_allowed
    )

    # ═══════════════════════════════════════════
    # عرض الإحصائيات
    # ═══════════════════════════════════════════

    print(
        "\n"
        + "=" * 60
    )

    print(
        "  إحصائيات الديب سيرش الكامل"
    )

    print(
        "=" * 60
    )

    print(
        f"  عدد الروابط الإجمالي: "
        f"{len(urls)}"
    )

    print(
        f"  عدد الروابط اللي فشلت: "
        f"{len(failed_urls)}"
    )

    print(
        f"  إجمالي البايتات المحمّلة: "
        f"{total_bytes_downloaded:,} "
        f"({total_bytes_downloaded / 1024 / 1024:.2f} MB)"
    )

    print(
        f"  إجمالي الأسطر المفحوصة: "
        f"{total_lines_scanned:,}"
    )

    print()

    print(
        f"  إجمالي أسطر الحظر: "
        f"{total_blocked_lines:,}"
    )

    print(
        f"  إجمالي أسطر السماح: "
        f"{total_allowed_lines:,}"
    )

    print()

    print(
        f"  الدومينات المحظورة الفريدة: "
        f"{len(blocked):,}"
    )

    print(
        f"  الدومينات المسموحة الفريدة: "
        f"{len(allowed):,}"
    )

    print()

    print(
        "  " + "-" * 50
    )

    print(
        f"  محظور فقط: "
        f"{len(blocked_only):,}"
    )

    print(
        f"  مسموح فقط: "
        f"{len(allowed_only):,}"
    )

    print(
        f"  محظور + مسموح معًا: "
        f"{len(conflicts):,}"
    )

    print()

    print(
        f"  تكرارات الحظر التي تم حذفها: "
        f"{duplicates_blocked:,}"
    )

    print(
        f"  تكرارات الـ Whitelist التي تم حذفها: "
        f"{duplicates_allowed:,}"
    )

    print(
        f"  إجمالي التكرارات المحذوفة: "
        f"{total_duplicates:,}"
    )

    print()

    print(
        f"  إجمالي الدومينات النهائية: "
        f"{len(blocked) + len(allowed):,}"
    )

    print(
        "=" * 60
    )

    # ═══════════════════════════════════════════
    # روابط فشلت
    # ═══════════════════════════════════════════

    if failed_urls:

        print(
            "\n[!] روابط فشلت:"
        )

        for failed_url in failed_urls:

            print(
                f"   - {failed_url}"
            )

    # ═══════════════════════════════════════════
    # كتابة الملفات
    # ═══════════════════════════════════════════

    print(
        "\n[+] كتابة الملفات..."
    )

    files = write_output(
        blocked,
        allowed,
        OUT_DIR,
        MAX_BYTES
    )

    for filepath in files:

        size = os.path.getsize(
            filepath
        )

        print(
            f"    [OK] {filepath} "
            f"({size / 1024 / 1024:.2f} MB)"
        )

    print(
        "\n[✓] خلص بنجاح"
    )


# ═══════════════════════════════════════════════
# تشغيل
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    main()
