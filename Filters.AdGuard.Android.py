#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Universal Filter Merger v16
=======================================================
- Fixed path issues for GitHub Actions
- Better plain domain list support (with inline comments)
- Support :: domain (IPv6 shorthand hosts)
- HTML response handling (auto-convert GitHub/raw URLs)
- Allow priority over block (@@ wins over ||)
- Strip *. from exceptions for cleaner rules
- Improved detection for small/single-format files
- Debug logging per URL
"""

import requests
import os
import sys
import time
import re
import json
import gzip
import random
from urllib.parse import urlparse
import urllib3
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────
MAX_LINE_LENGTH = 8192
REQUEST_TIMEOUT = 25
MAX_TOTAL_TIME = 1800
REQUEST_DELAY = 0.3
MAX_RETRIES = 3

FAST_DOMAINS = {
    'raw.githubusercontent.com', 'github.com', 'gitlab.com',
    'cdn.jsdelivr.net', 'filters.adtidy.org', 'adguardteam.github.io'
}

SLOW_DOMAINS = {
    'someonewhocares.org': 3.0,
    'winhelp2002.mvps.org': 3.0,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
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
        pool_connections=5,
        pool_maxsize=5,
        pool_block=False
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.headers.update({
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    })
    return session

def load_filter_urls(filename="list.txt"):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file 
                    if line.strip() and line.strip().startswith(("http://", "https://"))]
            return urls
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود!")
        return []

def normalize_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.rstrip('.').rstrip('*').rstrip('.')

def is_valid_domain(domain):
    if not domain or len(domain) > 253 or len(domain) < 2:
        return False
    domain_clean = domain.replace("*.", "").replace("(^|\.)", "").replace("$", "").replace("*", "")
    if domain_clean.startswith('.'):
        domain_clean = domain_clean[1:]
    # Support international domain names (punycode and unicode)
    pattern = r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z\u00a1-\uffff]{2,}$'
    if re.match(pattern, domain_clean):
        return True
    # Support pure punycode (xn--)
    if re.match(r'^xn--[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$', domain_clean):
        return True
    return False

def is_valid_ip(ip):
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True
    return False

def extract_domain_from_rule(rule):
    """Extract clean domain from an AdGuard rule for deduplication comparison"""
    clean = rule.lstrip("@").lstrip("|").rstrip("^")
    if '$' in clean:
        clean = clean.split('$')[0]
    if '/' in clean:
        clean = clean.split('/')[0]
    # Remove wildcard prefix for comparison
    clean = clean.lstrip("*.")
    return clean

def strip_inline_comment(line):
    """Remove inline comments (# or //) and return clean line"""
    if '#' in line:
        line = line.split('#')[0]
    if '//' in line:
        line = line.split('//')[0]
    return line.strip()

def extract_domain_from_css(line):
    css_match = re.match(r'^([a-z0-9\u00a1-\uffff._*-]+)(?:##|#@#|#\?#|#\$#|#%#)', line)
    if css_match:
        domain = normalize_domain(css_match.group(1))
        if is_valid_domain(domain):
            return domain
    return None

def extract_domain_from_url(line):
    url_match = re.match(r'^(?:https?://)([^/\s]+)', line)
    if url_match:
        domain = normalize_domain(url_match.group(1))
        if is_valid_domain(domain):
            return domain
    return None

def normalize_exception_rule(rule):
    """Clean up exception rules: remove wildcards and leading dots from domain"""
    if not rule.startswith("@@"):
        return rule
    # Extract domain part between @@|| and ^
    match = re.match(r'^@@\|\|(.+)\^$', rule)
    if not match:
        return rule
    domain = match.group(1)
    # Remove all leading wildcards and dots
    domain = domain.lstrip('*').lstrip('.')
    # Remove any remaining * characters in the domain (for exceptions, we want clean domains)
    domain = domain.replace('*', '')
    return f"@@||{domain}^"

def convert_to_adguard(line):
    original_line = line
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    # Skip pure comments
    if line.startswith(("!", "#", ";", "//", "/*")):
        return None
    if line.startswith(("$TTL", "@ IN SOA", " NS ", " NS\t")):
        return None
    if not line:
        return None

    # ─── Strip inline comments first ──────────────────────────────────────────
    line_clean = strip_inline_comment(line)
    if not line_clean:
        return None

    # ─── CSS rules (element hiding) ─────────────────────────────────────────
    css_domain = extract_domain_from_css(line)
    if css_domain:
        return f"||{css_domain}^"

    # ─── AdGuard/EasyList standard rules ────────────────────────────────────
    ag_standard = re.match(r'^(@@)?\|\|([a-z0-9\u00a1-\uffff._*-]+)\^(\$[^\s]*)?$', line, re.IGNORECASE)
    if ag_standard:
        exc = ag_standard.group(1) or ""
        domain = normalize_domain(ag_standard.group(2))
        if is_valid_domain(domain):
            result = f"{exc}||{domain}^"
            return normalize_exception_rule(result)
        return None

    # ─── Surge / Shadowrocket formats ───────────────────────────────────────
    surge_suffix = re.match(r'^DOMAIN-SUFFIX,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_suffix:
        domain = normalize_domain(surge_suffix.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    surge_domain = re.match(r'^DOMAIN,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_domain:
        domain = normalize_domain(surge_domain.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    surge_keyword = re.match(r'^DOMAIN-KEYWORD,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_keyword:
        keyword = surge_keyword.group(1).strip()
        if keyword and len(keyword) > 1:
            return f"||*{keyword}*"
        return None

    surge_wildcard = re.match(r'^DOMAIN-WILDCARD,([a-z0-9\u00a1-\uffff._*-]+)', line, re.IGNORECASE)
    if surge_wildcard:
        pattern = surge_wildcard.group(1).strip()
        if pattern.startswith("*."):
            domain = pattern[2:]
            if is_valid_domain(domain):
                return f"||*.{normalize_domain(domain)}^"
        elif "*." in pattern:
            parts = pattern.split("*.")
            if len(parts) == 2 and is_valid_domain(parts[1]):
                return f"||*.{normalize_domain(parts[1])}^"
        return None

    surge_host = re.match(r'^host,\s*([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_host:
        domain = normalize_domain(surge_host.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    surge_host_suffix = re.match(r'^host-suffix,\s*([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_host_suffix:
        domain = normalize_domain(surge_host_suffix.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    surge_host_kw = re.match(r'^host-keyword,\s*([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_host_kw:
        keyword = surge_host_kw.group(1).strip()
        if keyword and len(keyword) > 1:
            return f"||*{keyword}*"
        return None

    if re.match(r'^(USER-AGENT|URL-REGEX|AND|OR|NOT|IP-CIDR|IP-CIDR6|GEOIP|DEST-PORT|SRC-IP|IN-PORT|PROCESS-NAME|SUBNET),', line, re.IGNORECASE):
        return None

    # ─── CSV format (domain,date,...) ───────────────────────────────────────
    csv_match = re.match(r'^([a-z0-9\u00a1-\uffff._-]+),\d{4}-\d{2}-\d{2},', line)
    if csv_match:
        domain = normalize_domain(csv_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # ─── BIND zone format ───────────────────────────────────────────────────
    bind_match = re.match(r'^zone\s+"([a-z0-9\u00a1-\uffff._-]+)"\s+\{', line)
    if bind_match:
        domain = normalize_domain(bind_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # ─── dnsmasq format ──────────────────────────────────────────────────────
    dnsmasq_match = re.match(r'^server=/([a-z0-9\u00a1-\uffff._-]+)/', line)
    if dnsmasq_match:
        domain = normalize_domain(dnsmasq_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # ─── RPZ format ─────────────────────────────────────────────────────────
    rpz_match = re.match(r'^(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\s+CNAME\s+\.$', line, re.IGNORECASE)
    if rpz_match:
        star = rpz_match.group(1) or ""
        domain = normalize_domain(rpz_match.group(2))
        if is_valid_domain(domain):
            return f"||{star}{domain}^"
        return None

    # ─── Hosts with comment ─────────────────────────────────────────────────
    host_comment = re.match(r'^([a-z0-9\u00a1-\uffff._-]+)\s+#', line)
    if host_comment:
        domain = normalize_domain(host_comment.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # ─── URL format ──────────────────────────────────────────────────────────
    url_domain = extract_domain_from_url(line)
    if url_domain:
        return f"||{url_domain}^"

    # ─── Standard Hosts format: ANY_IP domain.com ─────────────────────────
    # Support any IP format: 0.0.0.0, 127.0.0.1, ::, ::1, 255.255.255.255, or any IP
    dns_match = re.match(r'^(?:[0-9a-fA-F:.]+)\s+([^\s#]+)', line)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        if domain in ('localhost', 'localhost.localdomain', 'broadcasthost', 'local'):
            return None
        if is_valid_domain(domain):
            return f"||{domain}^"
        if is_valid_ip(domain):
            return f"||{domain}^"
        return None

    # ─── Exception hosts: @@127.0.0.1 domain.com ────────────────────────────
    exc_dns = re.match(r'^@@(?:[0-9a-fA-F:.]+)\s+([^\s#]+)', line, re.IGNORECASE)
    if exc_dns:
        domain = normalize_domain(exc_dns.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None

    # ─── Plain wildcard domain: *.example.com ───────────────────────────────
    if line_clean.startswith("*.") and not line_clean.startswith("*." + " "):
        domain = line_clean[2:]
        if is_valid_domain(domain):
            return f"||*.{normalize_domain(domain)}^"
        return None

    # ─── Plain domain (possibly with inline comment already stripped) ────────
    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z\u00a1-\uffff]{2,}$', line_clean):
        if is_valid_domain(line_clean):
            return f"||{normalize_domain(line_clean)}^"
        return None

    # ─── Plain IP ──────────────────────────────────────────────────────────
    if is_valid_ip(line_clean):
        return f"||{line_clean}^"

    # ─── IP with port ──────────────────────────────────────────────────────
    ip_port_match = re.match(r'^(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?', line)
    if ip_port_match:
        ip = ip_port_match.group(1)
        if is_valid_ip(ip):
            return f"||{ip}^"
        return None

    # ─── Catch remaining AdGuard-like formats ──────────────────────────────
    ag_plain = re.match(r'^(@@)?(\|\|)?(\*\.)?([a-z0-9\u00a1-\uffff._-]+)$', line, re.IGNORECASE)
    if ag_plain:
        exc = ag_plain.group(1) or ""
        prefix = ag_plain.group(2) or "||"
        star = ag_plain.group(3) or ""
        domain = normalize_domain(ag_plain.group(4))
        if is_valid_domain(domain):
            result = f"{exc}{prefix}{star}{domain}^"
            return normalize_exception_rule(result)
        return None

    exc_plain = re.match(r'^@@(\|\|)?(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\^?$', line)
    if exc_plain:
        prefix = exc_plain.group(1) or "||"
        star = exc_plain.group(2) or ""
        domain = normalize_domain(exc_plain.group(3))
        if is_valid_domain(domain):
            result = f"@@{prefix}{star}{domain}^"
            return normalize_exception_rule(result)
        return None

    star_match = re.match(r'^(@@)?(\|\|)?\*\.([a-z0-9\u00a1-\uffff._-]+)\^?$', line, re.IGNORECASE)
    if star_match:
        exc = star_match.group(1) or ""
        prefix = star_match.group(2) or "||"
        domain = normalize_domain(star_match.group(3))
        if is_valid_domain(domain):
            result = f"{exc}{prefix}*.{domain}^"
            return normalize_exception_rule(result)
        return None

    return None

def looks_like_filter(text, url=""):
    if not text:
        return False, "Empty content"

    lines = text.split("\n")
    non_empty = [l.strip() for l in lines if l.strip()]

    if not non_empty:
        return False, "No non-empty lines"

    # Check if it's HTML
    if any(tag in text[:500].lower() for tag in ['<!doctype html', '<html', '<head', '<body']):
        # If it's HTML but contains pre/code tags with filter content, it might be a display page
        if '<pre' in text.lower() or '<code' in text.lower():
            # Try to extract content from pre tags
            return True, "HTML page with code block (will attempt extraction)"
        # Check if it's a GitHub page that needs raw conversion
        if 'github.com' in url.lower() and '/blob/' in url.lower():
            return False, "GitHub HTML page (use raw URL)"
        return False, "HTML response (not a filter file)"

    sample = non_empty[:200]

    rule_indicators = ["||", "@@", "0.0.0.0", "127.0.0.1", "[Adblock", "! Title", "! Version", 
                       "##", "#@#", "#?#", "CNAME .", "#Tracker", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", 
                       "DOMAIN-WILDCARD", "zone \"", "server=/", "host,", "||*", "*."]

    rule_count = sum(1 for line in sample if any(ind in line for ind in rule_indicators))

    meta_indicators = ["[Adblock", "! Title:", "! Version:", "! Expires:", "! Homepage:", 
                       "! Last modified:", "$TTL", "@ IN SOA", "!#", "!+"]
    meta_count = sum(1 for line in sample if any(ind in line for ind in meta_indicators))

    # Plain domain detection: lines that look like domains (with or without comments)
    domain_count = 0
    for line in sample:
        clean = strip_inline_comment(line)
        if re.match(r'^([a-z0-9_-]+\.)+[a-z]{2,}$', clean):
            domain_count += 1

    # Hosts format detection (any IP + domain)
    hosts_count = sum(1 for line in sample if re.match(r'^[0-9a-fA-F:.]+\s+\S+', line.strip()))

    # URL count
    url_count = sum(1 for line in sample if line.strip().startswith(("http://", "https://")))

    # If it's a known filter source domain, be more lenient
    known_filter_domains = ['filters.adtidy.org', 'easylist', 'adguard', 'github.com/AdguardTeam',
                           'someonewhocares', 'winhelp2002.mvps.org', 'pgl.yoyo.org', 
                           'malwaredomainlist', 'disconnect.me', 'hosts-file.net',
                           'blocklist', 'hosts', 'filter', 'domains', 'phishing', 'malware']
    is_known_source = any(k in url.lower() for k in known_filter_domains)

    # Decision logic
    if meta_count >= 1:
        return True, "Has filter metadata"
    if rule_count >= 2:
        return True, f"Has {rule_count} rule indicators"
    if hosts_count >= 2:
        return True, f"Has {hosts_count} hosts entries"
    if domain_count >= 3:
        return True, f"Has {domain_count} plain domains"
    if url_count >= 3:
        return True, f"Has {url_count} URLs"
    if is_known_source and len(non_empty) > 5:
        return True, "Known filter source with content"
    if len(text) > 10000 and (domain_count > 0 or hosts_count > 0):
        return True, "Large file with domain-like content"

    preview = ' | '.join(non_empty[:5])
    return False, f"Indicators: rules={rule_count}, hosts={hosts_count}, domains={domain_count}, meta={meta_count}. Preview: {preview[:80]}"

def download_filter(url, session, attempt=0):
    parsed = urlparse(url)
    domain = parsed.netloc

    strategies = [{"url": url, "headers": {}}]

    if "github.com" in domain and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        strategies.insert(0, {"url": raw_url, "headers": {}})

    if "gitlab.com" in domain and "/blob/" in url and "/raw/" not in url:
        parts = url.split("/blob/")
        if len(parts) == 2:
            raw_url = f"{parts[0]}/raw/{parts[1]}"
            strategies.insert(0, {"url": raw_url, "headers": {}})

    if url.startswith("https://"):
        strategies.append({"url": url.replace("https://", "http://", 1), "headers": {}})

    last_error = None

    for strategy in strategies:
        try:
            session.headers['User-Agent'] = random.choice(USER_AGENTS)
            headers = dict(session.headers)
            headers.update(strategy.get("headers", {}))

            response = session.get(
                strategy["url"],
                headers=headers,
                timeout=(8, REQUEST_TIMEOUT),
                verify=False,
                allow_redirects=True
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 5))
                time.sleep(retry_after)
                if attempt < MAX_RETRIES:
                    return download_filter(url, session, attempt + 1)
                continue

            response.raise_for_status()

            content = response.content
            if content[:2] == b'\x1f\x8b':
                try:
                    content = gzip.decompress(content)
                except Exception:
                    pass

            for enc in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'ascii']:
                try:
                    text = content.decode(enc, errors="replace")
                    break
                except Exception:
                    continue
            else:
                text = content.decode('utf-8', errors='replace')

            return text

        except requests.exceptions.Timeout:
            last_error = "Timeout"
            if attempt < MAX_RETRIES:
                return download_filter(url, session, attempt + 1)
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection: {str(e)[:60]}"
        except requests.exceptions.HTTPError as e:
            last_error = f"HTTP {e.response.status_code}"
            if e.response.status_code == 404:
                break
        except Exception as e:
            last_error = str(e)[:100]

    return None

def process_all_filters(urls):
    session = create_session()
    block_rules = set()
    allow_rules = set()
    allow_domains = set()  # Track allow domains for priority
    failed_urls = []
    failed_reasons = {}

    print(f"🔍 معالجة {len(urls)} مصدر... (Sequential mode)")
    print(f"⚙️  Timeout: {REQUEST_TIMEOUT}s | Delay: {REQUEST_DELAY}s | Retries: {MAX_RETRIES}")
    print("=" * 70)

    for i, url in enumerate(urls, 1):
        check_timeout()

        domain = urlparse(url).netloc

        if domain in SLOW_DOMAINS:
            delay = SLOW_DOMAINS[domain]
            print(f"⏳ [{domain}] slow domain, waiting {delay}s...")
            time.sleep(delay)
        elif domain not in FAST_DOMAINS:
            time.sleep(REQUEST_DELAY)

        try:
            text = download_filter(url, session)
            if text is None:
                failed_urls.append(url)
                failed_reasons[url] = "Download failed (all strategies exhausted)"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | Download failed")
                print(f"   ↳ {url[:80]}...")
                continue

            is_filter, reason = looks_like_filter(text, url)
            if not is_filter:
                failed_urls.append(url)
                failed_reasons[url] = f"Rejected: {reason}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | Rejected: {reason[:50]}")
                print(f"   ↳ {url[:80]}...")
                continue

            rules = []
            css_domains = set()
            lines_processed = 0
            lines_converted = 0

            for line in text.splitlines():
                lines_processed += 1
                converted = convert_to_adguard(line)
                if converted:
                    lines_converted += 1
                    if '##' in line or '#@#' in line or '#?#' in line:
                        css_domain = extract_domain_from_css(line)
                        if css_domain and css_domain not in css_domains:
                            css_domains.add(css_domain)
                            rules.append(converted)
                    else:
                        rules.append(converted)

            if not rules:
                preview_lines = [l.strip() for l in text.splitlines()[:10] 
                                if l.strip() and not l.startswith('!') and not l.startswith('#')]
                preview = ' | '.join(preview_lines[:3])
                failed_urls.append(url)
                failed_reasons[url] = f"No valid rules extracted. Preview: {preview[:60]}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | No rules extracted")
                print(f"   ↳ Preview: {preview[:60]}")
                continue

            new_block = []
            new_allow = []

            for rule in rules:
                # Normalize exception rules
                rule = normalize_exception_rule(rule)

                if rule.startswith("@@"):
                    if rule not in allow_rules:
                        allow_rules.add(rule)
                        new_allow.append(rule)
                        # Track the domain for priority checking
                        allow_domains.add(extract_domain_from_rule(rule))
                else:
                    # Check if this domain is already allowed (allow priority)
                    rule_domain = extract_domain_from_rule(rule)
                    if rule_domain in allow_domains:
                        # Skip this block rule - the domain is already allowed
                        continue
                    if rule not in block_rules:
                        block_rules.add(rule)
                        new_block.append(rule)

            print(f"✅ [{i:3d}/{len(urls)}] {domain:40s} | +{len(new_block):6d} block | +{len(new_allow):4d} allow | ({lines_converted}/{lines_processed} lines)")

        except Exception as e:
            failed_urls.append(url)
            failed_reasons[url] = f"Exception: {str(e)[:80]}"
            print(f"💥 [{i:3d}/{len(urls)}] {domain:40s} | Exception: {str(e)[:50]}")
            print(f"   ↳ {url[:80]}...")

    # Sort: exceptions first, then blocks
    sorted_rules = sorted(allow_rules, key=lambda x: extract_domain_from_rule(x))
    sorted_rules.extend(sorted(block_rules, key=lambda x: extract_domain_from_rule(x)))

    print("=" * 70)
    print(f"📊 النتائج:")
    print(f"   ✅ ناجح: {len(urls) - len(failed_urls)}/{len(urls)}")
    print(f"   ❌ فاشل: {len(failed_urls)}/{len(urls)}")
    print(f"   🚫 قواعد حظر: {len(block_rules):,}")
    print(f"   ✅ قواعد استثناء: {len(allow_rules):,}")
    print(f"   🛡️  دومينات مستثناة (أولوية): {len(allow_domains):,}")

    if failed_urls:
        print(f"\n🔗 الروابط الفاشلة ({len(failed_urls)}):")
        for url in failed_urls[:20]:
            print(f"   ❌ {url[:80]}")
            print(f"      السبب: {failed_reasons[url][:100]}")
        if len(failed_urls) > 20:
            print(f"   ... و {len(failed_urls) - 20} روابط أخرى")

    return sorted_rules, failed_urls

def save_filters(rules, output_dir="merged_filters", total_urls=0, failed_count=0):
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"""! Title: Merged Filters for AdGuard Android
! Description: مجمع فلاتر متقدم لـ AdGuard Android
! Version: {now.replace(" ", "-").replace(":", "-")}
! Last Modified: {now}
! Expires: 6 hours
! Sources: {total_urls - failed_count} ناجح | {failed_count} فاشل | إجمالي: {total_urls}
! Total Rules: {len(rules):,}
!
"""

    main_file = os.path.join(output_dir, "adguard_android_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write("\n".join(rules))

    print(f"\n✅ تم الحفظ: {main_file}")
    print(f"   📊 إجمالي القواعد: {len(rules):,}")

    stats = {
        "generated_at": now,
        "total_rules": len(rules),
        "allow_rules": sum(1 for r in rules if r.startswith("@@")),
        "block_rules": sum(1 for r in rules if not r.startswith("@@")),
        "total_sources": total_urls,
        "successful_sources": total_urls - failed_count,
        "failed_sources": failed_count
    }
    with open(os.path.join(output_dir, "stats.json"), 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    return main_file

def main():
    print("=" * 70)
    print("   Filters.AdGuard.Android v16 - Sequential Mode")
    print("   يدعم: Surge | Quantumult X | BIND | CSV | dnsmasq | DNS RPZ | Hosts | URLs | CSS | AdGuard | Plain Domains | Inline Comments | Allow Priority")
    print("=" * 70)

    urls = load_filter_urls("list.txt")
    if not urls:
        print("❌ لا توجد روابط في list.txt!")
        sys.exit(1)

    print(f"📋 {len(urls)} رابط في list.txt")
    print(f"⏰ الوقت الأقصى: {MAX_TOTAL_TIME//60} دقيقة\n")

    start = time.time()
    rules, failed = process_all_filters(urls)

    if not rules:
        print("❌ لم يتم استخراج أي قواعد!")
        sys.exit(1)

    save_filters(rules, total_urls=len(urls), failed_count=len(failed))

    elapsed = time.time() - start
    print(f"\n⏱️  الوقت: {elapsed:.1f} ثانية ({elapsed//60:.0f}m {elapsed%60:.0f}s)")
    print(f"📊 الإجمالي: {len(rules):,} قاعدة")
    print("✅ تم بنجاح!")

if __name__ == "__main__":
    main()
