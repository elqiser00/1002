#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Universal Filter Merger v18
=======================================================
- Per-source output files (delta updates via !#include)
- Auto-extract source names from filter metadata
- Allow priority over block (@@ wins over ||)
- Clean ALL rules: remove *. and . from domain start
- Auto-cleanup removed sources
- Support all hosts formats with inline comments
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
    adapter = requests.adapters.HTTPAdapter(pool_connections=5, pool_maxsize=5, pool_block=False)
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
    pattern = r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z\u00a1-\uffff]{2,}$'
    if re.match(pattern, domain_clean):
        return True
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
    """Extract clean domain from rule for deduplication comparison"""
    clean = rule.lstrip("@").lstrip("|").rstrip("^")
    if '$' in clean:
        clean = clean.split('$')[0]
    if '/' in clean:
        clean = clean.split('/')[0]
    # Remove ALL leading wildcards and dots
    clean = clean.lstrip('*').lstrip('.')
    return clean

def strip_inline_comment(line):
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

def clean_rule(rule):
    """Remove leading wildcards and dots from any rule: ||*.domain^ -> ||domain^"""
    if not rule:
        return rule
    is_exc = rule.startswith("@@")
    prefix = "@@||" if is_exc else "||"

    # Extract domain part between || and ^ or between || and ^$
    match = re.match(r'^(@@)?\|\|(.+)\^(\$[^\s]*)?$', rule)
    if not match:
        return rule

    domain = match.group(2)
    # Remove all leading wildcards and dots
    domain = domain.lstrip('*').lstrip('.')
    # Remove any remaining * characters inside the domain (for clean rules)
    if '*' in domain and not domain.startswith('*.'):
        domain = domain.replace('*', '')

    suffix = match.group(3) or ""

    return f"{prefix}{domain}^{suffix}"

def extract_source_name(text, url):
    """Extract filter name from source file metadata or URL"""
    lines = text.split('\n')[:50]
    for line in lines:
        title_match = re.match(r'^!\s*Title:\s*(.+)$', line, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
    domain = urlparse(url).netloc
    return domain

def convert_to_adguard(line):
    original_line = line
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None
    if line.startswith(("!", "#", ";", "//", "/*")):
        return None
    if line.startswith(("$TTL", "@ IN SOA", " NS ", " NS\t")):
        return None
    if not line:
        return None

    line_clean = strip_inline_comment(line)
    if not line_clean:
        return None

    css_domain = extract_domain_from_css(line)
    if css_domain:
        return clean_rule(f"||{css_domain}^")

    ag_standard = re.match(r'^(@@)?\|\|([a-z0-9\u00a1-\uffff._*-]+)\^(\$[^\s]*)?$', line, re.IGNORECASE)
    if ag_standard:
        exc = ag_standard.group(1) or ""
        domain = normalize_domain(ag_standard.group(2))
        if is_valid_domain(domain):
            result = f"{exc}||{domain}^"
            return clean_rule(result)
        return None

    surge_suffix = re.match(r'^DOMAIN-SUFFIX,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_suffix:
        domain = normalize_domain(surge_suffix.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    surge_domain = re.match(r'^DOMAIN,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_domain:
        domain = normalize_domain(surge_domain.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
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
                return clean_rule(f"||*.{normalize_domain(domain)}^")
        elif "*." in pattern:
            parts = pattern.split("*.")
            if len(parts) == 2 and is_valid_domain(parts[1]):
                return clean_rule(f"||*.{normalize_domain(parts[1])}^")
        return None

    surge_host = re.match(r'^host,\s*([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_host:
        domain = normalize_domain(surge_host.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    surge_host_suffix = re.match(r'^host-suffix,\s*([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_host_suffix:
        domain = normalize_domain(surge_host_suffix.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    surge_host_kw = re.match(r'^host-keyword,\s*([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_host_kw:
        keyword = surge_host_kw.group(1).strip()
        if keyword and len(keyword) > 1:
            return f"||*{keyword}*"
        return None

    if re.match(r'^(USER-AGENT|URL-REGEX|AND|OR|NOT|IP-CIDR|IP-CIDR6|GEOIP|DEST-PORT|SRC-IP|IN-PORT|PROCESS-NAME|SUBNET),', line, re.IGNORECASE):
        return None

    csv_match = re.match(r'^([a-z0-9\u00a1-\uffff._-]+),\d{4}-\d{2}-\d{2},', line)
    if csv_match:
        domain = normalize_domain(csv_match.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    bind_match = re.match(r'^zone\s+"([a-z0-9\u00a1-\uffff._-]+)"\s+\{', line)
    if bind_match:
        domain = normalize_domain(bind_match.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    dnsmasq_match = re.match(r'^server=/([a-z0-9\u00a1-\uffff._-]+)/', line)
    if dnsmasq_match:
        domain = normalize_domain(dnsmasq_match.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    rpz_match = re.match(r'^(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\s+CNAME\s+\.$', line, re.IGNORECASE)
    if rpz_match:
        star = rpz_match.group(1) or ""
        domain = normalize_domain(rpz_match.group(2))
        if is_valid_domain(domain):
            return clean_rule(f"||{star}{domain}^")
        return None

    host_comment = re.match(r'^([a-z0-9\u00a1-\uffff._-]+)\s+#', line)
    if host_comment:
        domain = normalize_domain(host_comment.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        return None

    url_domain = extract_domain_from_url(line)
    if url_domain:
        return clean_rule(f"||{url_domain}^")

    dns_match = re.match(r'^(?:[0-9a-fA-F:.]+)\s+([^\s#]+)', line)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        if domain in ('localhost', 'localhost.localdomain', 'broadcasthost', 'local'):
            return None
        if is_valid_domain(domain):
            return clean_rule(f"||{domain}^")
        if is_valid_ip(domain):
            return clean_rule(f"||{domain}^")
        return None

    exc_dns = re.match(r'^@@(?:[0-9a-fA-F:.]+)\s+([^\s#]+)', line, re.IGNORECASE)
    if exc_dns:
        domain = normalize_domain(exc_dns.group(1))
        if is_valid_domain(domain):
            return clean_rule(f"@@||{domain}^")
        return None

    if line_clean.startswith("*.") and not line_clean.startswith("*." + " "):
        domain = line_clean[2:]
        if is_valid_domain(domain):
            return clean_rule(f"||*.{normalize_domain(domain)}^")
        return None

    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z\u00a1-\uffff]{2,}$', line_clean):
        if is_valid_domain(line_clean):
            return clean_rule(f"||{normalize_domain(line_clean)}^")
        return None

    if is_valid_ip(line_clean):
        return clean_rule(f"||{line_clean}^")

    ip_port_match = re.match(r'^(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?', line)
    if ip_port_match:
        ip = ip_port_match.group(1)
        if is_valid_ip(ip):
            return clean_rule(f"||{ip}^")
        return None

    ag_plain = re.match(r'^(@@)?(\|\|)?(\*\.)?([a-z0-9\u00a1-\uffff._-]+)$', line, re.IGNORECASE)
    if ag_plain:
        exc = ag_plain.group(1) or ""
        prefix = ag_plain.group(2) or "||"
        star = ag_plain.group(3) or ""
        domain = normalize_domain(ag_plain.group(4))
        if is_valid_domain(domain):
            result = f"{exc}{prefix}{star}{domain}^"
            return clean_rule(result)
        return None

    exc_plain = re.match(r'^@@(\|\|)?(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\^?$', line)
    if exc_plain:
        prefix = exc_plain.group(1) or "||"
        star = exc_plain.group(2) or ""
        domain = normalize_domain(exc_plain.group(3))
        if is_valid_domain(domain):
            result = f"@@{prefix}{star}{domain}^"
            return clean_rule(result)
        return None

    star_match = re.match(r'^(@@)?(\|\|)?\*\.([a-z0-9\u00a1-\uffff._-]+)\^?$', line, re.IGNORECASE)
    if star_match:
        exc = star_match.group(1) or ""
        prefix = star_match.group(2) or "||"
        domain = normalize_domain(star_match.group(3))
        if is_valid_domain(domain):
            result = f"{exc}{prefix}*.{domain}^"
            return clean_rule(result)
        return None

    return None

def looks_like_filter(text, url=""):
    if not text:
        return False, "Empty content"
    lines = text.split("\n")
    non_empty = [l.strip() for l in lines if l.strip()]
    if not non_empty:
        return False, "No non-empty lines"
    if any(tag in text[:500].lower() for tag in ['<!doctype html', '<html', '<head', '<body']):
        if '<pre' in text.lower() or '<code' in text.lower():
            return True, "HTML page with code block"
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
    domain_count = 0
    for line in sample:
        clean = strip_inline_comment(line)
        if re.match(r'^([a-z0-9_-]+\.)+[a-z]{2,}$', clean):
            domain_count += 1
    hosts_count = sum(1 for line in sample if re.match(r'^[0-9a-fA-F:.]+\s+\S+', line.strip()))
    url_count = sum(1 for line in sample if line.strip().startswith(("http://", "https://")))
    known_filter_domains = ['filters.adtidy.org', 'easylist', 'adguard', 'github.com/AdguardTeam',
                           'someonewhocares', 'winhelp2002.mvps.org', 'pgl.yoyo.org', 
                           'malwaredomainlist', 'disconnect.me', 'hosts-file.net',
                           'blocklist', 'hosts', 'filter', 'domains', 'phishing', 'malware']
    is_known_source = any(k in url.lower() for k in known_filter_domains)
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
            response = session.get(strategy["url"], headers=headers, timeout=(8, REQUEST_TIMEOUT), verify=False, allow_redirects=True)
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
    source_data = []
    all_allow_domains = set()
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

        source_info = {
            'url': url,
            'name': domain,
            'block_rules': set(),
            'allow_rules': set(),
            'success': False,
            'lines_converted': 0,
            'lines_processed': 0
        }

        try:
            text = download_filter(url, session)
            if text is None:
                failed_urls.append(url)
                failed_reasons[url] = "Download failed"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | Download failed")
                source_data.append(source_info)
                continue

            is_filter, reason = looks_like_filter(text, url)
            if not is_filter:
                failed_urls.append(url)
                failed_reasons[url] = f"Rejected: {reason}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | Rejected: {reason[:50]}")
                source_data.append(source_info)
                continue

            source_info['name'] = extract_source_name(text, url)

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
                            if converted.startswith("@@"):
                                source_info['allow_rules'].add(converted)
                            else:
                                source_info['block_rules'].add(converted)
                    else:
                        if converted.startswith("@@"):
                            source_info['allow_rules'].add(converted)
                        else:
                            source_info['block_rules'].add(converted)

            if not source_info['block_rules'] and not source_info['allow_rules']:
                preview_lines = [l.strip() for l in text.splitlines()[:10] 
                                if l.strip() and not l.startswith('!') and not l.startswith('#')]
                preview = ' | '.join(preview_lines[:3])
                failed_urls.append(url)
                failed_reasons[url] = f"No valid rules. Preview: {preview[:60]}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | No rules extracted")
                source_data.append(source_info)
                continue

            source_info['success'] = True
            source_info['lines_converted'] = lines_converted
            source_info['lines_processed'] = lines_processed

            for rule in source_info['allow_rules']:
                all_allow_domains.add(extract_domain_from_rule(rule))

            print(f"✅ [{i:3d}/{len(urls)}] {domain:40s} | +{len(source_info['block_rules']):6d} block | +{len(source_info['allow_rules']):4d} allow | ({lines_converted}/{lines_processed} lines) | [{source_info['name'][:30]}]")

        except Exception as e:
            failed_urls.append(url)
            failed_reasons[url] = f"Exception: {str(e)[:80]}"
            print(f"💥 [{i:3d}/{len(urls)}] {domain:40s} | Exception: {str(e)[:50]}")

        source_data.append(source_info)

    print("\n🛡️  تطبيق أولوية الاستثناءات...")
    total_block = set()
    total_allow = set()

    for source in source_data:
        if not source['success']:
            continue
        for rule in source['allow_rules']:
            total_allow.add(rule)
        for rule in source['block_rules']:
            rule_domain = extract_domain_from_rule(rule)
            if rule_domain not in all_allow_domains:
                total_block.add(rule)

    print(f"   ✅ قواعد استثناء نهائية: {len(total_allow):,}")
    print(f"   🚫 قواعد حظر نهائية: {len(total_block):,}")

    sorted_allow = sorted(total_allow, key=lambda x: extract_domain_from_rule(x))
    sorted_block = sorted(total_block, key=lambda x: extract_domain_from_rule(x))

    print("=" * 70)
    print(f"📊 النتائج:")
    print(f"   ✅ ناجح: {sum(1 for s in source_data if s['success'])}/{len(urls)}")
    print(f"   ❌ فاشل: {len(failed_urls)}/{len(urls)}")

    if failed_urls:
        print(f"\n🔗 الروابط الفاشلة ({len(failed_urls)}):")
        for url in failed_urls[:20]:
            print(f"   ❌ {url[:80]}")
            print(f"      السبب: {failed_reasons[url][:100]}")
        if len(failed_urls) > 20:
            print(f"   ... و {len(failed_urls) - 20} روابط أخرى")

    return source_data, sorted_allow, sorted_block, failed_urls

def save_filters(source_data, allow_rules, block_rules, output_dir="merged_filters", total_urls=0, failed_count=0):
    os.makedirs(output_dir, exist_ok=True)
    sources_dir = os.path.join(output_dir, "sources")
    os.makedirs(sources_dir, exist_ok=True)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    include_lines = []

    exc_file = os.path.join(sources_dir, "000_exceptions.txt")
    with open(exc_file, 'w', encoding='utf-8') as f:
        f.write(f"! Title: Exceptions (Allow Rules)\n")
        f.write(f"! Description: استثناءات عامة - أولوية على الحظر\n")
        f.write(f"! Last Modified: {now}\n")
        f.write(f"! Rules: {len(allow_rules):,}\n")
        f.write("!\n")
        f.write("\n".join(allow_rules))
    include_lines.append("!#include sources/000_exceptions.txt")
    print(f"\n📁 [000] Exceptions: {len(allow_rules):,} rules")

    source_idx = 1
    for source in source_data:
        if not source['success']:
            continue

        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', source['name'])[:40]
        filename = f"{source_idx:03d}_{safe_name}.txt"
        filepath = os.path.join(sources_dir, filename)

        source_block = []
        for rule in source['block_rules']:
            rule_domain = extract_domain_from_rule(rule)
            is_allowed = any(extract_domain_from_rule(a) == rule_domain for a in allow_rules)
            if not is_allowed:
                source_block.append(rule)

        if not source_block:
            continue

        source_block_sorted = sorted(source_block, key=lambda x: extract_domain_from_rule(x))

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"! Title: {source['name']}\n")
            f.write(f"! Source: {source['url']}\n")
            f.write(f"! Description: {len(source_block_sorted):,} block rules\n")
            f.write(f"! Last Modified: {now}\n")
            f.write(f"! Original Allow Rules: {len(source['allow_rules'])}\n")
            f.write(f"! Original Block Rules: {len(source['block_rules'])}\n")
            f.write(f"! Final Block Rules: {len(source_block_sorted)}\n")
            f.write("!\n")
            f.write("\n".join(source_block_sorted))

        include_lines.append(f"!#include sources/{filename}")
        print(f"📁 [{source_idx:03d}] {source['name'][:40]:40s} | {len(source_block_sorted):6,} rules | {filename}")
        source_idx += 1

    current_files = set()
    for line in include_lines:
        if line.startswith("!#include sources/"):
            fname = line.replace("!#include sources/", "")
            current_files.add(fname)
    current_files.add("000_exceptions.txt")

    removed_old = 0
    if os.path.exists(sources_dir):
        for old_file in os.listdir(sources_dir):
            if old_file not in current_files:
                os.remove(os.path.join(sources_dir, old_file))
                removed_old += 1
    if removed_old > 0:
        print(f"\n🗑️  تم حذف {removed_old} ملف مصدر قديم")

    main_file = os.path.join(output_dir, "adguard_android_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(f"! Title: Merged Filters for AdGuard Android\n")
        f.write(f"! Description: مجمع فلاتر متقدم لـ AdGuard Android - Delta Update Enabled\n")
        f.write(f"! Version: {now.replace(' ', '-').replace(':', '-')}\n")
        f.write(f"! Last Modified: {now}\n")
        f.write(f"! Expires: 6 hours\n")
        f.write(f"! Sources: {total_urls - failed_count} ناجح | {failed_count} فاشل | إجمالي: {total_urls}\n")
        f.write(f"! Total Rules: {len(allow_rules) + len(block_rules):,}\n")
        f.write(f"! Allow Rules: {len(allow_rules):,}\n")
        f.write(f"! Block Rules: {len(block_rules):,}\n")
        f.write(f"! Format: Uses !#include for per-source delta updates\n")
        f.write(f"! Note: AdGuard loads each included file separately (caches per file)\n")
        f.write("!\n")
        f.write("\n".join(include_lines))

    print(f"\n✅ تم الحفظ: {main_file}")
    print(f"   📊 إجمالي القواعد: {len(allow_rules) + len(block_rules):,}")
    print(f"   📁 ملفات فرعية: {len(include_lines)}")
    print(f"   📂 المجلد: {sources_dir}/")

    stats = {
        "generated_at": now,
        "total_rules": len(allow_rules) + len(block_rules),
        "allow_rules": len(allow_rules),
        "block_rules": len(block_rules),
        "total_sources": total_urls,
        "successful_sources": total_urls - failed_count,
        "failed_sources": failed_count,
        "source_files": len(include_lines) - 1,
        "delta_update_enabled": True
    }
    with open(os.path.join(output_dir, "stats.json"), 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    return main_file

def main():
    print("=" * 70)
    print("   Filters.AdGuard.Android v18 - Delta Update Mode")
    print("   يدعم: Per-source files | !#include | Delta updates | Allow Priority | Clean Rules")
    print("=" * 70)

    urls = load_filter_urls("list.txt")
    if not urls:
        print("❌ لا توجد روابط في list.txt!")
        sys.exit(1)

    print(f"📋 {len(urls)} رابط في list.txt")
    print(f"⏰ الوقت الأقصى: {MAX_TOTAL_TIME//60} دقيقة\n")

    start = time.time()
    source_data, allow_rules, block_rules, failed = process_all_filters(urls)

    if not allow_rules and not block_rules:
        print("❌ لم يتم استخراج أي قواعد!")
        sys.exit(1)

    save_filters(source_data, allow_rules, block_rules, total_urls=len(urls), failed_count=len(failed))

    elapsed = time.time() - start
    print(f"\n⏱️  الوقت: {elapsed:.1f} ثانية ({elapsed//60:.0f}m {elapsed%60:.0f}s)")
    print(f"📊 الإجمالي: {len(allow_rules) + len(block_rules):,} قاعدة")
    print("✅ تم بنجاح!")

if __name__ == "__main__":
    main()
