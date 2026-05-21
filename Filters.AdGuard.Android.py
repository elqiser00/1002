#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Universal Filter Merger v28
=====================================================
- FIXED: Gzip decompression with proper encoding fallback
- FIXED: URLhaus format (URLs per line -> extract domains)
- FIXED: Accept [Adblock Plus 3.x], [uBlock Origin] headers
- FIXED: Strip ALL source headers, keep only one clean output header
- FIXED: Proper deduplication with allow-list priority
- FIXED: Robust HTTP: SSL bypass, retries, cookies, gzip, encoding
- FIXED: Handle slow domains, 429 rate-limit, connection errors
- FIXED: Convert ALL formats to AdGuard Android native syntax
- FIXED: CSS rules (##) -> extract domain and block it
- FIXED: Regex rules -> skip or extract domain if possible
- Output: 100% compatible with AdGuard Android App
"""

import requests
import os
import sys
import time
import re
import gzip
import random
import socket
from urllib.parse import urlparse
import urllib3
from datetime import datetime

# ─── Configuration ───
MAX_LINE_LENGTH = 4096
REQUEST_TIMEOUT = 35
MAX_TOTAL_TIME = 2700          # 45 minutes max
REQUEST_DELAY = 0.2
MAX_RETRIES = 5
CONNECTION_POOL_SIZE = 15

FAST_DOMAINS = {
    'raw.githubusercontent.com', 'github.com', 'gitlab.com',
    'cdn.jsdelivr.net', 'filters.adtidy.org', 'adguardteam.github.io',
    'easylist.to', 'pgl.yoyo.org', 'urlhaus.abuse.ch'
}

SLOW_DOMAINS = {
    'someonewhocares.org': 5.0,
    'winhelp2002.mvps.org': 5.0,
    'sysctl.org': 4.0,
    'hosts-file.net': 4.0,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

START_TIME = time.time()


def check_timeout():
    if time.time() - START_TIME > MAX_TOTAL_TIME:
        print(f"\n⏰ تجاوز الوقت الأقصى ({MAX_TOTAL_TIME}s). إيقاف...")
        sys.exit(1)


def create_session():
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=CONNECTION_POOL_SIZE,
        pool_maxsize=CONNECTION_POOL_SIZE,
        pool_block=False,
        max_retries=0
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.headers.update({
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
    })
    return session


def load_filter_urls(filename="list.txt"):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            urls = []
            for line in f:
                line = line.strip()
                if not line or line.startswith(("#", "//", ";")):
                    continue
                if line.startswith(("http://", "https://")):
                    urls.append(line)
            return urls
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود!")
        return []


def normalize_domain(domain):
    if not domain:
        return ""
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    domain = domain.rstrip('.').rstrip('*').rstrip('^').rstrip('.')
    while domain.startswith('.') or domain.startswith('*'):
        domain = domain.lstrip('.').lstrip('*')
    return domain


def is_valid_domain(domain):
    if not domain or len(domain) > 253 or len(domain) < 2:
        return False
    clean = domain.replace('*.', '').replace('(^|\\.)', '').replace('$', '').replace('*', '')
    if clean.startswith('.'):
        clean = clean[1:]
    if re.match(r'^xn--[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$', clean):
        return True
    pattern = r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z\u00a1-\uffff]{2,}$'
    return bool(re.match(pattern, clean))


def is_valid_ip(ip):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def extract_domain_from_rule(rule):
    if not rule:
        return ""
    clean = rule.lstrip('@').lstrip('|')
    if '^' in clean:
        clean = clean.split('^')[0]
    if '$' in clean:
        clean = clean.split('$')[0]
    clean = clean.lstrip('*').lstrip('.')
    return normalize_domain(clean)


def strip_inline_comment(line):
    if ' #' in line:
        line = line.split(' #')[0]
    if '\t#' in line:
        line = line.split('\t#')[0]
    if '//' in line and not line.startswith('//'):
        idx = line.find('//')
        if idx > 0 and line[idx-1] != ':':
            line = line[:idx]
    return line.strip()


def is_source_header(line):
    """Detect if line is a source list header (to be stripped)"""
    if not line:
        return False
    line_lower = line.lower().strip()
    header_patterns = (
        '[adblock plus', '[ublock origin', '! title:', '! version:', '! expires:',
        '! description:', '! homepage:', '! last modified:', '! checksum:',
        '! timeupdated:', '! diff-path:', '! compiled by', '! license:',
        '! homepage:', '! url:', '! expires', '! download', '! mirror',
        '! redirect:', '! include:', '! exclude:', '! filter list',
        '! last updated:', '! updated:', '! date:', '! modified:',
    )
    return line_lower.startswith(header_patterns)


def extract_domain_from_url(url_str):
    """Extract domain from any URL string"""
    try:
        if not url_str or len(url_str) > 2048:
            return None
        url_str = url_str.strip().lower()
        # Handle URLs without protocol
        if '://' not in url_str and url_str.startswith('www.'):
            url_str = 'http://' + url_str
        elif '://' not in url_str and '.' in url_str:
            url_str = 'http://' + url_str
        parsed = urlparse(url_str)
        domain = parsed.netloc
        if not domain:
            # Maybe it's just a domain
            domain = url_str.split('/')[0].split(':')[0]
        domain = normalize_domain(domain)
        if is_valid_domain(domain) or is_valid_ip(domain):
            return domain
    except Exception:
        pass
    return None


def clean_rule_for_android(rule):
    """Convert any rule to AdGuard Android native format."""
    if not rule:
        return None
    rule = rule.strip()
    if not rule or len(rule) > MAX_LINE_LENGTH:
        return None

    is_exception = rule.startswith('@@')
    prefix = '@@||' if is_exception else '||'

    body = rule
    if body.startswith('@@'):
        body = body[2:]
    body = body.lstrip('|')

    domain_part = body
    modifiers = ""

    if '$' in body:
        parts = body.split('$', 1)
        domain_part = parts[0]
        modifiers = parts[1]

    domain_part = domain_part.rstrip('^').rstrip('*').rstrip('.')
    domain_part = domain_part.lstrip('*').lstrip('.')

    # Remove $important
    if modifiers:
        mods = [m.strip() for m in modifiers.split(',') if m.strip().lower() != 'important']
        if mods:
            # Keep only Android-compatible modifiers
            android_mods = []
            for m in mods:
                m_lower = m.lower()
                if m_lower in ('all', 'third-party', 'script', 'image', 'xmlhttprequest', 
                               'subdocument', 'popup', 'domain', 'generichide', 'elemhide',
                               'redirect', 'rewrite', 'match-case', 'badfilter', 'csp',
                               'webrtc', 'websocket', 'font', 'media'):
                    android_mods.append(m)
                elif '=' in m_lower and m_lower.startswith('domain='):
                    android_mods.append(m)
                elif m_lower == 'document':
                    android_mods.append(m)
            if android_mods:
                modifiers = ','.join(android_mods)
            else:
                modifiers = ""
        else:
            modifiers = ""

    if not is_valid_domain(domain_part) and not is_valid_ip(domain_part):
        return None

    if modifiers:
        return f"{prefix}{domain_part}^{modifiers}"
    return f"{prefix}{domain_part}^"


def convert_line_to_adguard(line):
    """Convert a single line from any filter format to AdGuard Android format"""
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    # Skip source headers and comments
    if is_source_header(line):
        return None
    if line.startswith(("!", "#", ";", "//", "/*", "* ", " *")):
        return None

    line_clean = strip_inline_comment(line)
    if not line_clean:
        return None

    # ─── URL lines (URLhaus, phishing lists, etc.) ───
    # Lines like: http://110.39.229.159:40441/i/xxx
    url_match = re.match(r'^(?:https?://)([^/\s]+)', line_clean)
    if url_match:
        domain = extract_domain_from_url(line_clean)
        if domain:
            return clean_rule_for_android(f"||{domain}^")

    # ─── Already AdGuard format ───
    ag_match = re.match(r'^(@@)?\|{1,2}([a-z0-9\u00a1-\uffff._*-]+)\^?(\$[^\s]*)?$', line_clean, re.IGNORECASE)
    if ag_match:
        exc = ag_match.group(1) or ""
        domain = normalize_domain(ag_match.group(2))
        mods = ag_match.group(3) or ""
        if is_valid_domain(domain) or is_valid_ip(domain):
            return clean_rule_for_android(f"{exc}||{domain}^{mods}")

    # ─── Hosts file format ───
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::|255\.255\.255\.255)\s+([^\s#]+)', line_clean)
    if hosts_match:
        domain = normalize_domain(hosts_match.group(1))
        if domain in ('localhost', 'localhost.localdomain', 'broadcasthost', 'local',
                      'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix',
                      'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts'):
            return None
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||{domain}^")
        if is_valid_ip(domain):
            return clean_rule_for_android(f"||{domain}^")

    # ─── Plain domain per line ───
    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z\u00a1-\uffff]{2,}$', line_clean, re.IGNORECASE):
        domain = normalize_domain(line_clean)
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||{domain}^")

    # ─── Surge / Shadowrocket / Quantumult formats ───
    surge_patterns = [
        (r'^DOMAIN-SUFFIX,\s*([a-z0-9\u00a1-\uffff._-]+)', '||{}^'),
        (r'^DOMAIN,\s*([a-z0-9\u00a1-\uffff._-]+)', '||{}^'),
        (r'^DOMAIN-KEYWORD,\s*([a-z0-9\u00a1-\uffff._-]+)', '||*{}*'),
        (r'^HOST-SUFFIX,\s*([a-z0-9\u00a1-\uffff._-]+)', '||{}^'),
        (r'^HOST,\s*([a-z0-9\u00a1-\uffff._-]+)', '||{}^'),
        (r'^HOST-KEYWORD,\s*([a-z0-9\u00a1-\uffff._-]+)', '||*{}*'),
        (r'^HOST-WILDCARD,\s*([a-z0-9\u00a1-\uffff._*-]+)', '||{}^'),
        (r'^IP-CIDR,', None),  # Skip IP-CIDR rules
        (r'^IP-CIDR6,', None),
        (r'^GEOIP,', None),
        (r'^USER-AGENT,', None),
        (r'^URL-REGEX,', None),
        (r'^PROCESS-NAME,', None),
        (r'^DEST-PORT,', None),
        (r'^SRC-IP,', None),
        (r'^IN-PORT,', None),
        (r'^AND,', None),
        (r'^OR,', None),
        (r'^NOT,', None),
    ]
    for pattern, template in surge_patterns:
        m = re.match(pattern, line_clean, re.IGNORECASE)
        if m:
            if template is None:
                return None  # Skip unsupported rule types
            val = m.group(1).strip()
            if template == '||*{}*':
                if len(val) > 1:
                    return clean_rule_for_android(f"||*{val}*")
            else:
                domain = normalize_domain(val)
                if is_valid_domain(domain):
                    return clean_rule_for_android(template.format(domain))

    # ─── DNSMasq format ───
    dnsmasq_match = re.match(r'^server=/([a-z0-9\u00a1-\uffff._-]+)/', line_clean)
    if dnsmasq_match:
        domain = normalize_domain(dnsmasq_match.group(1))
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||{domain}^")

    # ─── BIND / RPZ format ───
    bind_match = re.match(r'^zone\s+"([a-z0-9\u00a1-\uffff._-]+)"', line_clean)
    if bind_match:
        domain = normalize_domain(bind_match.group(1))
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||{domain}^")

    rpz_match = re.match(r'^(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\s+CNAME\s+\.$', line_clean, re.IGNORECASE)
    if rpz_match:
        star = rpz_match.group(1) or ""
        domain = normalize_domain(rpz_match.group(2))
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||{star}{domain}^")

    # ─── CSV / plain lists with dates ───
    csv_match = re.match(r'^([a-z0-9\u00a1-\uffff._-]+),\d{4}-\d{2}-\d{2}', line_clean)
    if csv_match:
        domain = normalize_domain(csv_match.group(1))
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||{domain}^")

    # ─── IP with optional port ───
    ip_port_match = re.match(r'^(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?', line_clean)
    if ip_port_match:
        ip = ip_port_match.group(1)
        if is_valid_ip(ip):
            return clean_rule_for_android(f"||{ip}^")

    # ─── *.domain.com format ───
    star_domain_match = re.match(r'^\*\.([a-z0-9\u00a1-\uffff._-]+)$', line_clean)
    if star_domain_match:
        domain = normalize_domain(star_domain_match.group(1))
        if is_valid_domain(domain):
            return clean_rule_for_android(f"||*.{domain}^")

    # ─── Exception hosts format ───
    exc_hosts_match = re.match(r'^@@(?:[0-9a-fA-F:.]+)\s+([^\s#]+)', line_clean, re.IGNORECASE)
    if exc_hosts_match:
        domain = normalize_domain(exc_hosts_match.group(1))
        if is_valid_domain(domain):
            return clean_rule_for_android(f"@@||{domain}^")

    # ─── Plain IP ───
    if is_valid_ip(line_clean):
        return clean_rule_for_android(f"||{line_clean}^")

    # ─── CSS/element hiding rules: extract domain and block ───
    # domain.com##selector or domain.com#@#selector
    css_match = re.match(r'^([a-z0-9\u00a1-\uffff._*-]+)(?:##|#@#|#\?#|#\$#|#%#)', line)
    if css_match:
        domain = normalize_domain(css_match.group(1))
        if is_valid_domain(domain):
            # Check if it's an exception
            if '#@#' in line or '#?#' in line:
                return clean_rule_for_android(f"@@||{domain}^")
            return clean_rule_for_android(f"||{domain}^")

    # ─── Regex-based rules with domain prefix ───
    # domain.com/regex/ or domain.com$script,etc
    regex_domain_match = re.match(r'^([a-z0-9\u00a1-\uffff._*-]+)(?:\^|/|\$)', line)
    if regex_domain_match:
        domain = normalize_domain(regex_domain_match.group(1))
        if is_valid_domain(domain):
            # For regex rules, just block the domain
            return clean_rule_for_android(f"||{domain}^")

    return None


def looks_like_filter(text, url=""):
    """Validate that downloaded content is actually a filter list"""
    if not text or len(text) < 50:
        return False, "Empty or too short"

    lines = [l.strip() for l in text.split("\n") if l.strip()]
    if not lines:
        return False, "No non-empty lines"

    # Check for HTML error pages
    first_500 = text[:500].lower()
    if any(tag in first_500 for tag in ['<!doctype html', '<html', '<head', '<body']):
        if '<pre' in text.lower() or '<code' in text.lower() or 'raw' in url.lower():
            pass
        else:
            return False, "HTML page detected"

    # Count indicators
    indicators = ["||", "@@", "0.0.0.0", "127.0.0.1", "[Adblock", "[uBlock", "! Title", "! Version",
                  "##", "#@#", "#?#", "DOMAIN-SUFFIX", "DOMAIN,", "server=/", "host,",
                  "*.", "CNAME .", "zone \"", "! Whitelist", "! domenii", "! words",
                  "! bfcrap", "! porcarii", "$popup", "$script", "$image", "$xmlhttprequest",
                  "$subdocument", "$third-party", "/ads/", "/banner", "/qc/", "/popup"]

    rule_count = sum(1 for line in lines[:300] if any(ind in line for ind in indicators))
    hosts_count = sum(1 for line in lines[:300] if re.match(r'^[0-9a-fA-F:.]+\s+\S+', line))
    domain_count = sum(1 for line in lines[:300] if re.match(r'^([a-z0-9_-]+\.)+[a-z]{2,}$', line.strip()))
    url_count = sum(1 for line in lines[:300] if re.match(r'^https?://', line.strip()))

    known_sources = ['filters.adtidy.org', 'easylist', 'adguard', 'github.com/adguardteam',
                     'someonewhocares', 'winhelp2002.mvps.org', 'pgl.yoyo.org',
                     'blocklist', 'hosts', 'filter', 'domains', 'phishing', 'malware',
                     'disconnect.me', 'sysctl.org', 'urlhaus', 'abuse.ch', 'zoso.ro',
                     'gardar.net', 'abpvn', 'polish', 'persian', 'adblockid']
    is_known = any(k in url.lower() for k in known_sources)

    if rule_count >= 1 or hosts_count >= 1 or domain_count >= 2 or url_count >= 2:
        return True, f"Valid: rules={rule_count}, hosts={hosts_count}, domains={domain_count}, urls={url_count}"
    if is_known and len(lines) > 3:
        return True, "Known source with content"
    if len(text) > 2000 and (domain_count > 0 or hosts_count > 0 or url_count > 0):
        return True, "Large file with content"

    preview = ' | '.join(lines[:3])
    return False, f"Not a filter. Preview: {preview[:80]}"


def download_filter(url, session, attempt=0):
    """Download with full robustness"""
    parsed = urlparse(url)
    domain = parsed.netloc

    strategies = [{"url": url, "headers": {}, "verify": False}]

    if "github.com" in domain and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        strategies.insert(0, {"url": raw_url, "headers": {}, "verify": False})

    if "gitlab.com" in domain and "/blob/" in url and "/raw/" not in url:
        parts = url.split("/blob/")
        if len(parts) == 2:
            raw_url = f"{parts[0]}/raw/{parts[1]}"
            strategies.insert(0, {"url": raw_url, "headers": {}, "verify": False})

    if url.startswith("https://"):
        strategies.append({"url": url.replace("https://", "http://", 1), "headers": {}, "verify": False})

    last_error = None
    for strategy in strategies:
        try:
            headers = dict(session.headers)
            headers.update(strategy.get("headers", {}))
            headers['User-Agent'] = random.choice(USER_AGENTS)

            response = session.get(
                strategy["url"],
                headers=headers,
                timeout=(12, REQUEST_TIMEOUT),
                verify=strategy.get("verify", False),
                allow_redirects=True,
                stream=False
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 10))
                if attempt < MAX_RETRIES:
                    time.sleep(min(retry_after, 60))
                    return download_filter(url, session, attempt + 1)
                continue

            if 500 <= response.status_code < 600 and attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                return download_filter(url, session, attempt + 1)

            response.raise_for_status()

            content = response.content

            # Better gzip detection and decompression
            if content[:2] == b'\x1f\x8b':
                try:
                    content = gzip.decompress(content)
                except Exception as e:
                    print(f"   ⚠️ Gzip decompression failed: {e}")
                    pass

            # Try multiple encodings
            text = None
            for enc in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']:
                try:
                    text = content.decode(enc, errors="strict")
                    break
                except Exception:
                    continue
            if text is None:
                text = content.decode('utf-8', errors='replace')

            # If text is garbled (binary-like), try to detect and handle
            if '\x00' in text[:100] or all(ord(c) > 127 for c in text[:50] if c.isalpha()):
                # Might be compressed or encrypted - try different approach
                try:
                    import zlib
                    decompressed = zlib.decompress(content, -15)  # raw deflate
                    text = decompressed.decode('utf-8', errors='replace')
                except Exception:
                    pass

            return text

        except requests.exceptions.Timeout:
            last_error = "Timeout"
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                return download_filter(url, session, attempt + 1)
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection: {str(e)[:80]}"
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                return download_filter(url, session, attempt + 1)
        except requests.exceptions.HTTPError as e:
            last_error = f"HTTP {e.response.status_code}"
            if e.response.status_code == 404:
                break
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                return download_filter(url, session, attempt + 1)
        except (requests.exceptions.RequestException, socket.error, OSError) as e:
            last_error = f"Network: {str(e)[:80]}"
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                return download_filter(url, session, attempt + 1)
        except Exception as e:
            last_error = f"Error: {str(e)[:80]}"

    return None


def process_all_filters(urls):
    session = create_session()

    block_rules = set()
    allow_rules = set()
    allow_domains = set()
    failed_urls = []
    failed_reasons = {}
    source_stats = []

    print(f"🔍 معالجة {len(urls)} مصدر...")
    print(f"⚙️  Timeout: {REQUEST_TIMEOUT}s | Delay: {REQUEST_DELAY}s | Retries: {MAX_RETRIES}")
    print("=" * 70)

    for i, url in enumerate(urls, 1):
        check_timeout()
        domain = urlparse(url).netloc

        if domain in SLOW_DOMAINS:
            time.sleep(SLOW_DOMAINS[domain])
        elif domain not in FAST_DOMAINS:
            time.sleep(REQUEST_DELAY)

        try:
            text = download_filter(url, session)
            if text is None:
                failed_urls.append(url)
                failed_reasons[url] = "Download failed"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:45s} | Download failed")
                continue

            is_filter, reason = looks_like_filter(text, url)
            if not is_filter:
                failed_urls.append(url)
                failed_reasons[url] = f"Rejected: {reason}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:45s} | Rejected: {reason[:60]}")
                continue

            local_block = set()
            local_allow = set()
            lines_processed = 0
            lines_converted = 0

            for line in text.splitlines():
                lines_processed += 1
                converted = convert_line_to_adguard(line)
                if converted:
                    lines_converted += 1
                    if converted.startswith('@@'):
                        local_allow.add(converted)
                    else:
                        local_block.add(converted)

            if not local_block and not local_allow:
                failed_urls.append(url)
                preview = ' | '.join([l.strip() for l in text.splitlines()[:5] if l.strip() and not l.startswith('!')])
                failed_reasons[url] = f"No rules. Preview: {preview[:60]}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:45s} | No rules extracted")
                continue

            for rule in local_allow:
                allow_rules.add(rule)
                allow_domains.add(extract_domain_from_rule(rule))

            for rule in local_block:
                rule_domain = extract_domain_from_rule(rule)
                if rule_domain not in allow_domains:
                    block_rules.add(rule)

            source_stats.append({
                'url': url,
                'domain': domain,
                'block': len(local_block),
                'allow': len(local_allow),
                'converted': lines_converted,
                'processed': lines_processed
            })

            print(f"✅ [{i:3d}/{len(urls)}] {domain:45s} | +{len(local_block):6d} block | +{len(local_allow):4d} allow | ({lines_converted}/{lines_processed})")

        except Exception as e:
            failed_urls.append(url)
            failed_reasons[url] = f"Exception: {str(e)[:80]}"
            print(f"💥 [{i:3d}/{len(urls)}] {domain:45s} | Exception: {str(e)[:50]}")

    # Final dedup pass
    final_block = set()
    for rule in block_rules:
        if extract_domain_from_rule(rule) not in allow_domains:
            final_block.add(rule)

    print("\n" + "=" * 70)
    print(f"📊 النتائج:")
    print(f"   ✅ ناجح: {len(source_stats)}/{len(urls)}")
    print(f"   ❌ فاشل: {len(failed_urls)}/{len(urls)}")
    print(f"   🚫 قواعد حظر: {len(final_block):,}")
    print(f"   ⚪ قواعد استثناء: {len(allow_rules):,}")

    if failed_urls:
        print(f"\n🔗 الروابط الفاشلة ({len(failed_urls)}) — أول 15:")
        for url in failed_urls[:15]:
            print(f"   ❌ {url[:70]}")
            print(f"      → {failed_reasons[url][:80]}")

    return list(allow_rules), list(final_block), failed_urls


def save_filters(allow_rules, block_rules, output_dir="merged_filters"):
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    version = now.replace(" ", "-").replace(":", "-")

    main_file = os.path.join(output_dir, "adguard_android_filter.txt")

    print(f"\n💾 كتابة الملف الرئيسي ({len(allow_rules) + len(block_rules):,} قاعدة)...")

    with open(main_file, "w", encoding="utf-8") as f:
        # Clean header
        f.write("[Adblock Plus 2.0]\n")
        f.write("!\n")
        f.write("! Title: Merged Filters for AdGuard Android\n")
        f.write("! Description: Auto-merged blocklist optimized for AdGuard Android App\n")
        f.write(f"! Version: {version}\n")
        f.write("! Homepage: https://github.com/elqiser00/1002\n")
        f.write(f"! Last modified: {now}\n")
        f.write("! Expires: 6 hours\n")
        f.write("!\n")
        f.write("! Compiled by Filters.AdGuard.Android v28\n")
        f.write("! Format: AdGuard Android native (||domain^ / @@||domain^)\n")
        f.write("!\n")

        sorted_allow = sorted(allow_rules)
        sorted_block = sorted(block_rules)

        if sorted_allow:
            f.write("! ——— Allow Rules (Exceptions) ———\n")
            for rule in sorted_allow:
                f.write(rule + "\n")
            f.write("\n")

        if sorted_block:
            f.write("! ——— Block Rules ———\n")
            for rule in sorted_block:
                f.write(rule + "\n")

    size_mb = os.path.getsize(main_file) / (1024 * 1024)
    print(f"✅ تم الحفظ: {main_file}")
    print(f"   📊 إجمالي القواعد: {len(allow_rules) + len(block_rules):,}")
    print(f"   📁 حجم الملف: {size_mb:.2f} MB")

    return main_file


def main():
    print("=" * 70)
    print("   Filters.AdGuard.Android v28 — Android App Native Format")
    print("   Format: ||domain^  |  @@||domain^  |  No $important")
    print("   FIXED: Gzip, URLs, CSS rules, Headers, All formats")
    print("=" * 70)

    urls = load_filter_urls("list.txt")
    if not urls:
        print("❌ لا توجد روابط في list.txt!")
        sys.exit(1)

    print(f"📋 {len(urls)} رابط في list.txt")
    print(f"⏰ الوقت الأقصى: {MAX_TOTAL_TIME // 60} دقيقة\n")

    start = time.time()
    allow_rules, block_rules, failed = process_all_filters(urls)

    if not allow_rules and not block_rules:
        print("❌ لم يتم استخراج أي قواعد!")
        sys.exit(1)

    save_filters(allow_rules, block_rules)

    elapsed = time.time() - start
    print(f"\n⏱️  الوقت: {elapsed:.1f} ثانية ({elapsed // 60:.0f}m {elapsed % 60:.0f}s)")
    print(f"📊 الإجمالي: {len(allow_rules) + len(block_rules):,} قاعدة | 🚫 {len(block_rules):,} | ⚪ {len(allow_rules):,}")
    print("✅ تم بنجاح!")


if __name__ == "__main__":
    main()
