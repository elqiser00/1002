#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adguard-Adblock-only Builder v3

- Downloads source lists from list2.txt.
- Extracts literal host/domain rules only (no regex or conditional modifiers).
- Canonicalizes domains (lowercase, IDNA, trailing-dot removal).
- Exact duplicate handling: an exact blocked domain wins over an exact allow rule.
- Safe hierarchy cleanup:
    * A blocked parent makes its blocked children redundant, so children are removed.
    * An allowed parent makes its allowed children redundant, so children are removed.
    * An allowed parent is removed when a blocked child exists beneath it, so the
      broad allow rule cannot undermine the more specific block.
    * An explicitly allowed child beneath a blocked parent is retained as a
      more-specific exception.
- Skips private/local names, IP addresses, malformed domains, regex rules,
  wildcard rules, URL paths, and rules with modifiers such as $third-party.
- Downloads only with normal TLS certificate verification.
- Supports plain text, Hosts format, gzip, ZIP, TAR.GZ and TGZ sources.
- Hard-protects TikTok, Instagram, Facebook/Messenger and Threads roots.
- Emits $important exception rules for protected roots.
- Allows extra protected roots through protected_domains.txt.
- Splits generated output files at MAX_BYTES.
"""

import gzip
import io
import ipaddress
import os
import re
import tarfile
import time
import zipfile
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LIST_FILE = "list2.txt"
OUT_DIR = "Adguard-Adblock-only"
PROTECTED_DOMAINS_FILE = "protected_domains.txt"
MAX_BYTES = 90 * 1024 * 1024       # Maximum size of each generated TXT file
TIMEOUT = (20, 90)                 # (connection timeout, read timeout)
MAX_RETRIES = 3
CHUNK_SIZE = 1024 * 1024
MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024
MAX_UNPACKED_BYTES = 300 * 1024 * 1024
MAX_LINE_LENGTH = 2048

# Hard protection roots: blocking rules for these domains and every subdomain
# are discarded, then high-priority AdGuard exception rules are emitted.
# This list focuses on TikTok, Instagram, Facebook/Messenger, and Threads.
DEFAULT_PROTECTED_DOMAINS = {
    # TikTok / ByteDance delivery and media domains
    "tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com",
    "tiktokstatic.com", "byteoversea.com", "bytefcdn-oversea.com",
    "ibytedtos.com", "ibyteimg.com", "byteimg.com", "ipstatp.com",
    "pstatp.com", "muscdn.com",
    # Instagram
    "instagram.com", "cdninstagram.com", "instagramstatic.com",
    # Facebook / Meta messaging and content delivery
    "facebook.com", "facebook.net", "fb.com", "fb.me", "fbcdn.net",
    "fbsbx.com", "messenger.com", "m.me", "fb.watch",
    # Threads
    "threads.net",
}

SKIP_HOSTS = {
    "localhost", "localhost.localdomain", "localdomain", "broadcasthost",
    "local", "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
    "0.0.0.0", "127.0.0.1", "::1", "255.255.255.255",
}

# These suffixes are reserved for local use or documentation, not public blocking.
SKIP_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home",
    ".home.arpa", ".test", ".invalid", ".example",
)

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


# ---------------------------------------------------------------------------
# Domain normalization and validation
# ---------------------------------------------------------------------------
def canonical_domain(raw_domain: str) -> str | None:
    """Return a normalized ASCII/IDNA domain, or None if it is not a public host."""
    if not raw_domain:
        return None

    domain = raw_domain.strip().lower()
    # A final DNS root dot is equivalent to no final dot. Leading/multiple dots
    # are not silently repaired because that could turn malformed input valid.
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain or domain.startswith(".") or ".." in domain:
        return None

    # Do not accept URL components, ports, wildcards, IP literals or rule syntax.
    if any(ch in domain for ch in "/\\:*?[]{}()|^$@#%\t\r\n"):
        return None

    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass

    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None

    if len(domain) > 253 or domain in SKIP_HOSTS:
        return None
    if any(domain == suffix.lstrip(".") or domain.endswith(suffix) for suffix in SKIP_SUFFIXES):
        return None

    labels = domain.split(".")
    # At least two labels are required; this also excludes single-label hosts.
    if len(labels) < 2:
        return None
    if any(not label or len(label) > 63 or not LABEL_RE.fullmatch(label) for label in labels):
        return None

    # Avoid obvious pseudo-TLDs and numeric-only final labels.
    tld = labels[-1]
    if len(tld) < 2 or not any(ch.isalpha() for ch in tld):
        return None

    return domain


# ---------------------------------------------------------------------------
# Input URL list and HTTP session
# ---------------------------------------------------------------------------
def clean_url(raw: str) -> str:
    return raw.strip().strip("\"'").strip()


def read_urls(path: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    if not os.path.isfile(path):
        print(f"[!] ملف الروابط غير موجود: {path}")
        return urls

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith(("#", "!")):
                continue
            url = clean_url(line)
            if not url.lower().startswith(("http://", "https://")):
                continue
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
        status=MAX_RETRIES,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(("GET", "HEAD")),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; AdguardDomainBuilder/2.0)",
        "Accept": "*/*",
    })
    # requests verifies TLS certificates by default. Do not disable verification.
    return session


# ---------------------------------------------------------------------------
# Safe download and archive handling
# ---------------------------------------------------------------------------
def _read_limited(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("unpacked source exceeds configured size limit")
    return data


def unpack_payload(data: bytes, url: str) -> bytes:
    """Unpack supported archives with a total uncompressed-size limit."""
    low_url = url.lower().split("?", 1)[0]
    is_zip = low_url.endswith(".zip") or data.startswith(b"PK\x03\x04")
    is_tar_gz = low_url.endswith((".tar.gz", ".tgz"))
    is_gzip = low_url.endswith(".gz") or data.startswith(b"\x1f\x8b")

    if is_zip:
        chunks: list[bytes] = []
        total = 0
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise ValueError("ZIP content exceeds configured size limit")
                with archive.open(info, "r") as member:
                    chunk = _read_limited(member, MAX_UNPACKED_BYTES - (total - info.file_size))
                chunks.append(chunk)
        return b"\n".join(chunks) if chunks else data

    if is_tar_gz:
        chunks = []
        total = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                # Only regular files; never extract paths, links, devices or folders.
                if not member.isfile():
                    continue
                total += member.size
                if total > MAX_UNPACKED_BYTES:
                    raise ValueError("TAR content exceeds configured size limit")
                member_stream = archive.extractfile(member)
                if member_stream is None:
                    continue
                with member_stream:
                    chunks.append(_read_limited(member_stream, MAX_UNPACKED_BYTES - (total - member.size)))
        return b"\n".join(chunks) if chunks else data

    if is_gzip:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
            return _read_limited(gz, MAX_UNPACKED_BYTES)

    return data


def decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def fetch_full(session: requests.Session, url: str) -> tuple[str | None, int, bool]:
    try:
        with session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            downloaded = 0
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > MAX_DOWNLOAD_BYTES:
                    raise ValueError("download exceeds configured size limit")
                chunks.append(chunk)

            if not chunks:
                return None, 0, False

            body = unpack_payload(b"".join(chunks), url)
            text = decode_bytes(body)
            head = text[:1000].lstrip().lower()
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" in content_type or head.startswith(("<!doctype html", "<html", "<head")):
                return None, len(body), False
            return text, len(body), True

    except (requests.RequestException, OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        print(f"    [!] فشل التحميل/الفك: {exc}")
        return None, 0, False


# ---------------------------------------------------------------------------
# Literal rule parser
# ---------------------------------------------------------------------------
def parse_domain_token(token: str) -> tuple[str, bool] | None:
    """Parse only an unambiguous domain rule. Return (domain, is_allowed)."""
    token = token.strip().strip("\"'").strip().rstrip(",;")
    if not token or token.startswith(("!", "#", "[")):
        return None

    allowed = False
    if token.startswith("@@"):
        allowed = True
        token = token[2:]

    # Do not broaden conditional rules into full-domain rules. This rejects
    # modifiers such as $script, $third-party, $domain=..., $important, etc.
    if "$" in token:
        return None

    # Exact Adblock/AdGuard domain anchor: ||example.com^
    if token.startswith("||"):
        if not token.endswith("^"):
            return None
        candidate = token[2:-1]
        domain = canonical_domain(candidate)
        return (domain, allowed) if domain else None

    # Only an origin URL is accepted. A URL with a path/query would be broadened
    # if converted to a domain-only rule, so it is intentionally discarded.
    if token.lower().startswith(("http://", "https://")):
        try:
            parsed = urlsplit(token)
            if parsed.scheme.lower() not in ("http", "https"):
                return None
            if parsed.username or parsed.password or parsed.port is not None:
                return None
            if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                return None
            domain = canonical_domain(parsed.hostname or "")
            return (domain, allowed) if domain else None
        except ValueError:
            return None

    # Anchored URL-style rule: |https://example.com^
    if token.startswith("|"):
        rest = token[1:]
        if not rest.lower().startswith(("http://", "https://")) or not rest.endswith("^"):
            return None
        try:
            parsed = urlsplit(rest[:-1])
            if parsed.username or parsed.password or parsed.port is not None:
                return None
            if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                return None
            domain = canonical_domain(parsed.hostname or "")
            return (domain, allowed) if domain else None
        except ValueError:
            return None

    # Plain host/domain line. Anything containing rule syntax is rejected by
    # canonical_domain instead of being partially interpreted.
    domain = canonical_domain(token)
    return (domain, allowed) if domain else None


def extract_lists(source_text: str, blocked: set[str], allowed: set[str], stats: dict[str, int]) -> None:
    for raw_line in source_text.splitlines():
        line = raw_line.strip()
        if not line or len(line) > MAX_LINE_LENGTH:
            stats["ignored_lines"] += 1
            continue
        if line.startswith(("!", "#")) or (line.startswith("[") and line.endswith("]")):
            continue

        # Hosts files: IP address followed by one or more hostnames.
        # Remove inline comments before token processing.
        without_comment = line.split("#", 1)[0].strip()
        if not without_comment:
            continue
        parts = without_comment.split()
        if not parts:
            continue

        try:
            ipaddress.ip_address(parts[0])
            host_tokens = parts[1:]
        except ValueError:
            host_tokens = parts

        for token in host_tokens:
            stats["tokens_seen"] += 1
            parsed = parse_domain_token(token)
            if parsed is None:
                stats["tokens_rejected"] += 1
                continue
            domain, is_allowed = parsed
            if is_allowed:
                allowed.add(domain)
            else:
                blocked.add(domain)
            stats["tokens_accepted"] += 1


# ---------------------------------------------------------------------------
# Exact-match and hierarchy filtering
# ---------------------------------------------------------------------------
def has_parent_in(domain: str, domains: set[str]) -> bool:
    labels = domain.split(".")
    # Never test a bare public suffix/TLD as a parent candidate.
    for index in range(1, len(labels) - 1):
        if ".".join(labels[index:]) in domains:
            return True
    return False


def parent_domains_of(domain: str) -> set[str]:
    labels = domain.split(".")
    return {".".join(labels[index:]) for index in range(1, len(labels) - 1)}


def is_under_protected_domain(domain: str, protected_domains: set[str]) -> bool:
    """True for a protected root and any of its subdomains."""
    return any(domain == root or domain.endswith("." + root) for root in protected_domains)


def load_protected_domains(path: str) -> set[str]:
    """Load built-in protected domains plus user-added roots from a text file."""
    protected = set(DEFAULT_PROTECTED_DOMAINS)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "# Add extra trusted domains here, one domain per line.\n"
                "# Built-in protection for TikTok, Instagram, Facebook, Messenger and Threads\n"
                "# is always enabled in the script and cannot be removed from this file.\n"
                "# Example: example-social.net\n"
            )
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                # Permit plain domains only. Do not silently parse rules or URLs here.
                domain = canonical_domain(line)
                if domain:
                    protected.add(domain)
                else:
                    print(f"[!] نطاق حماية إضافي غير صالح وتم تجاهله: {line[:100]}")
    except OSError as exc:
        print(f"[!] تعذر قراءة {path}: {exc}")
    return protected


def filter_domains(
    blocked: set[str],
    allowed: set[str],
    protected_domains: set[str],
) -> tuple[list[str], list[str], dict[str, int]]:
    blocked = set(blocked)
    allowed = set(allowed)
    counts = {
        "protected_blocked_removed": 0,
        "protected_allow_duplicates_removed": 0,
        "exact_allow_removed": 0,
        "redundant_block_children_removed": 0,
        "redundant_allow_children_removed": 0,
        "broad_allow_parents_removed": 0,
    }

    # 0) Hard social-media safety policy. This runs BEFORE exact-match priority:
    # a source list is never allowed to block a protected social-media domain.
    protected_blocked = {
        domain for domain in blocked
        if is_under_protected_domain(domain, protected_domains)
    }
    blocked.difference_update(protected_blocked)
    counts["protected_blocked_removed"] = len(protected_blocked)

    # Any source allow rules inside a protected tree are redundant because the
    # protected root exception covers the root and all subdomains.
    protected_allow_duplicates = {
        domain for domain in allowed
        if is_under_protected_domain(domain, protected_domains)
    }
    allowed.difference_update(protected_allow_duplicates)
    counts["protected_allow_duplicates_removed"] = len(protected_allow_duplicates)

    # 1) Exact literal match for all NON-protected domains: a domain present in
    # both sets stays blocked. Protected domains are the explicit safety override.
    exact_conflicts = blocked & allowed
    allowed.difference_update(exact_conflicts)
    counts["exact_allow_removed"] = len(exact_conflicts)

    # 2) If a blocked parent exists, a blocked child adds no coverage.
    redundant_block_children = {
        domain for domain in blocked if has_parent_in(domain, blocked)
    }
    blocked.difference_update(redundant_block_children)
    counts["redundant_block_children_removed"] = len(redundant_block_children)

    # 3) Remove an allowed parent when a blocked child exists beneath it.
    broad_allow_parents = set()
    for blocked_domain in blocked:
        broad_allow_parents.update(parent_domains_of(blocked_domain) & allowed)
    allowed.difference_update(broad_allow_parents)
    counts["broad_allow_parents_removed"] = len(broad_allow_parents)

    # 4) If an allowed parent remains, allowed children are redundant.
    redundant_allow_children = {
        domain for domain in allowed if has_parent_in(domain, allowed)
    }
    allowed.difference_update(redundant_allow_children)
    counts["redundant_allow_children_removed"] = len(redundant_allow_children)

    # 5) Re-add every protected root as a mandatory allow exception.
    # The writer emits these with $important to override ordinary and important
    # blocking rules, where the installed AdGuard product supports that modifier.
    allowed.update(protected_domains)

    return sorted(blocked), sorted(allowed), counts


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------
def write_output(blocked_domains: list[str], allowed_domains: list[str], protected_domains: set[str], out_dir: str, max_bytes: int) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)

    # Remove only files generated by this script, not every TXT file in the folder.
    for filename in os.listdir(out_dir):
        if re.fullmatch(r"blacklist(?:_\d+)?\.txt", filename, flags=re.I):
            try:
                os.remove(os.path.join(out_dir, filename))
            except OSError as exc:
                print(f"[!] تعذر حذف الملف القديم {filename}: {exc}")

    total = len(blocked_domains) + len(allowed_domains)
    header = (
        "[Adblock Plus 2.0]\n"
        "! Title: Adguard Adblock only\n"
        "! Description: Literal Domains + Mandatory Social Media Protection\n"
        f"! Blocked domains: {len(blocked_domains)}\n"
        f"! Allowed domains: {len(allowed_domains)}\n"
        f"! Protected social roots: {len(protected_domains)}\n"
        f"! Total domains: {total}\n"
        "! Generated: " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + "\n!\n"
    )
    header_size = len(header.encode("utf-8"))
    files: list[str] = []
    index = 1
    current_lines: list[str] = []
    current_size = header_size

    def flush() -> None:
        nonlocal index, current_lines, current_size
        if not current_lines:
            return
        filename = "blacklist.txt" if index == 1 else f"blacklist_{index}.txt"
        path = os.path.join(out_dir, filename)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(header)
            handle.writelines(current_lines)
        files.append(path)
        index += 1
        current_lines = []
        current_size = header_size

    def add_line(line: str) -> None:
        nonlocal current_size
        line_size = len(line.encode("utf-8"))
        if current_lines and current_size + line_size > max_bytes:
            flush()
        current_lines.append(line)
        current_size += line_size

    # Put mandatory protection rules at the beginning of the first output file.
    # This makes them easy to verify and ensures they are not separated into a
    # later chunk when the generated list is split by size.
    for domain in sorted(protected_domains):
        # Important exception wins over ordinary and important blocking rules
        # in AdGuard products that support the $important modifier.
        add_line(f"@@||{domain}^$important\n")
        # Plain exception is retained as a compatibility fallback on clients
        # that do not support $important (it cannot defeat important blocks).
        add_line(f"@@||{domain}^\n")
    for domain in blocked_domains:
        add_line(f"||{domain}^\n")
    for domain in allowed_domains:
        if domain not in protected_domains:
            add_line(f"@@||{domain}^\n")

    flush()
    # Write an informative header even when there are no domains.
    if not files:
        path = os.path.join(out_dir, "blacklist.txt")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(header)
        files.append(path)
    return files


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 66)
    print(" Adguard-Adblock-only Builder v3 | Mandatory Social Media Protection")
    print("=" * 66)

    urls = read_urls(LIST_FILE)
    print(f"\n[+] عدد الروابط الفريدة في {LIST_FILE}: {len(urls)}")
    if not urls:
        print("[!] لا توجد روابط صالحة. لم يتم إنشاء قائمة جديدة.")
        return

    protected_domains = load_protected_domains(PROTECTED_DOMAINS_FILE)
    print(f"[+] نطاقات الحماية الإجبارية (الجذور): {len(protected_domains):,}")

    session = build_session()
    blocked: set[str] = set()
    allowed: set[str] = set()
    stats = {
        "sources_ok": 0,
        "sources_failed": 0,
        "tokens_seen": 0,
        "tokens_accepted": 0,
        "tokens_rejected": 0,
        "ignored_lines": 0,
    }

    try:
        for index, url in enumerate(urls, 1):
            print(f"\n[{index}/{len(urls)}] {url}")
            source_text, source_size, ok = fetch_full(session, url)
            if not ok or source_text is None:
                stats["sources_failed"] += 1
                continue

            before_blocked = len(blocked)
            before_allowed = len(allowed)
            extract_lists(source_text, blocked, allowed, stats)
            stats["sources_ok"] += 1
            added = (len(blocked) - before_blocked) + (len(allowed) - before_allowed)
            print(f"    تم التحميل: {source_size / 1024 / 1024:.2f} MB | دومينات جديدة: {added:,}")

    finally:
        session.close()

    if stats["sources_ok"] == 0 or stats["tokens_accepted"] == 0:
        print("\n[!] لم يتم استخراج أي دومين صالح من المصادر.")
        print("[!] تم إيقاف العملية للحفاظ على ملفات النتائج القديمة دون حذفها.")
        return

    raw_blocked_count = len(blocked)
    raw_allowed_count = len(allowed)
    final_blocked, final_allowed, filter_counts = filter_domains(blocked, allowed, protected_domains)

    print("\n" + "=" * 66)
    print(f"  المصادر الناجحة: {stats['sources_ok']:,}")
    print(f"  المصادر الفاشلة: {stats['sources_failed']:,}")
    print(f"  Tokens المفحوصة: {stats['tokens_seen']:,}")
    print(f"  Tokens المقبولة: {stats['tokens_accepted']:,}")
    print(f"  Tokens المرفوضة: {stats['tokens_rejected']:,}")
    print(f"  الدومينات المحظورة قبل التصفيه: {raw_blocked_count:,}")
    print(f"  الدومينات المسموحة قبل التصفيه: {raw_allowed_count:,}")
    print("-" * 66)
    print(f"  حظر دومينات محمية تم منعه: {filter_counts['protected_blocked_removed']:,}")
    print(f"  سماحات داخل دومينات محمية تم دمجها: {filter_counts['protected_allow_duplicates_removed']:,}")
    print(f"  تطابق حرفي: سماح اتشال لصالح الحظر: {filter_counts['exact_allow_removed']:,}")
    print(f"  دومينات حظر فرعية زائدة اتشالت: {filter_counts['redundant_block_children_removed']:,}")
    print(f"  دومينات سماح فرعية زائدة اتشالت: {filter_counts['redundant_allow_children_removed']:,}")
    print(f"  سماح أب اتشال لوجود حظر فرعي: {filter_counts['broad_allow_parents_removed']:,}")
    print("-" * 66)
    print(f"  النتيجة النهائية - محظور: {len(final_blocked):,}")
    print(f"  النتيجة النهائية - مسموح: {len(final_allowed):,}")
    print("=" * 66)

    print("\n[+] كتابة ملفات النتائج...")
    output_files = write_output(final_blocked, final_allowed, protected_domains, OUT_DIR, MAX_BYTES)
    for path in output_files:
        size = os.path.getsize(path)
        print(f"    [OK] {path} ({size / 1024 / 1024:.2f} MB)")
        print("    معاينة أول 5 أسطر:")
        with open(path, "r", encoding="utf-8") as preview:
            for _ in range(5):
                line = preview.readline()
                if not line:
                    break
                print(f"       {line.rstrip()}")

    print("\n[✓] انتهى إنشاء القائمة.")
    print("[i] تحقق من ظهور قواعد @@||...^$important في بداية blacklist.txt.")
    print("[i] هذه الحماية تخص القوائم الناتجة من هذا السكربت فقط؛ لا تتحكم في DNS خارجي أو قوائم أخرى مستقلة.")


if __name__ == "__main__":
    main()
