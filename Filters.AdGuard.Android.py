
script_v13 = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Universal Filter Merger v13
=======================================================
- Sequential processing (واحد واحد)
- Cache للروابط الناجحة
- Skip للسيرفرات المشاكل
- Fast mode للسيرفرات السريعة
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
from collections import defaultdict

# ─── Configuration ──────────────────────────────────────────────────────────
MAX_LINE_LENGTH = 8192
REQUEST_TIMEOUT = 20
MAX_TOTAL_TIME = 1500
REQUEST_DELAY = 0.2
MAX_RETRIES = 2

# سيرفرات سريعة (مش محتاجة delay)
FAST_DOMAINS = {
    'raw.githubusercontent.com', 'github.com', 'gitlab.com',
    'cdn.jsdelivr.net', 'filters.adtidy.org'
}

# سيرفرات بطيئة (نزود delay)
SLOW_DOMAINS = {
    'adguardteam.github.io': 2.0,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Global Timer ────────────────────────────────────────────────────────────
START_TIME = time.time()

def check_timeout():
    if time.time() - START_TIME > MAX_TOTAL_TIME:
        print(f"\n⏰ تجاوز الوقت الأقصى ({MAX_TOTAL_TIME}s). إيقاف...")
        sys.exit(1)

# ─── Session ─────────────────────────────────────────────────────────────────
def create_session():
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=1,
        pool_maxsize=1,
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

# ─── Load URLs ───────────────────────────────────────────────────────────────
def load_filter_urls(filename="list.txt"):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file 
                    if line.strip() and line.strip().startswith(("http://", "https://"))]
            return urls
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود!")
        return []

# ─── Domain Processing ───────────────────────────────────────────────────────
def normalize_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.rstrip('.')

def is_valid_domain(domain):
    if not domain or len(domain) > 253:
        return False
    domain_clean = domain.replace("*.", "").replace("(^|\.)", "").replace("$", "")
    if re.match(r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z]{2,}$', domain_clean):
        return True
    return False

def is_valid_ip(ip):
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True
    return False

def extract_domain_from_rule(rule):
    clean = rule.lstrip("@").lstrip("|").rstrip("^")
    if '$' in clean:
        clean = clean.split('$')[0]
    if '/' in clean:
        clean = clean.split('/')[0]
    return clean

# ─── Extract Domain from CSS Rule ────────────────────────────────────────────
def extract_domain_from_css(line):
    css_match = re.match(r'^([a-z0-9\u00a1-\uffff._-]+)(?:##|#@#|#\?#)', line)
    if css_match:
        domain = normalize_domain(css_match.group(1))
        if is_valid_domain(domain):
            return domain
    return None

def extract_domain_from_url(line):
    url_match = re.match(r'^(?:https?://)([^/\s]+)', line)
    if url_match:
        domain = normalize_domain(url_match.group(1))
        if domain.startswith('www.'):
            domain = domain[4:]
        if is_valid_domain(domain):
            return domain
    return None

# ─── Universal Rule Converter ────────────────────────────────────────────────
def convert_to_adguard(line):
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None
    if not line:
        return None
    if line.startswith("!"):
        return None
    if line.startswith(("$TTL", "@ IN SOA", " NS ", " NS\t", ";")):
        return None
    line = line.strip()
    if not line:
        return None

    css_domain = extract_domain_from_css(line)
    if css_domain:
        return f"||{css_domain}^"

    surge_suffix = re.match(r'^DOMAIN-SUFFIX,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_suffix:
        domain = normalize_domain(surge_suffix.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    surge_keyword = re.match(r'^DOMAIN-KEYWORD,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_keyword:
        keyword = surge_keyword.group(1).strip()
        if keyword:
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

    surge_domain = re.match(r'^DOMAIN,([a-z0-9\u00a1-\uffff._-]+)', line, re.IGNORECASE)
    if surge_domain:
        domain = normalize_domain(surge_domain.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
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
        if keyword:
            return f"||*{keyword}*"
        return None

    if re.match(r'^(USER-AGENT|URL-REGEX|AND|OR|NOT),', line, re.IGNORECASE):
        return None

    csv_match = re.match(r'^([a-z0-9\u00a1-\uffff._-]+),\d{4}-\d{2}-\d{2},', line)
    if csv_match:
        domain = normalize_domain(csv_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    bind_match = re.match(r'^zone\s+"([a-z0-9\u00a1-\uffff._-]+)"\s+\{', line)
    if bind_match:
        domain = normalize_domain(bind_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    dnsmasq_match = re.match(r'^server=/([a-z0-9\u00a1-\uffff._-]+)/', line)
    if dnsmasq_match:
        domain = normalize_domain(dnsmasq_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    if line.startswith("^"):
        return None

    rpz_match = re.match(r'^(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\s+CNAME\s+\.$', line, re.IGNORECASE)
    if rpz_match:
        star = rpz_match.group(1) or ""
        domain = normalize_domain(rpz_match.group(2))
        if is_valid_domain(domain):
            return f"||{star}{domain}^"
        return None

    host_comment = re.match(r'^([a-z0-9\u00a1-\uffff._-]+)\s+#', line)
    if host_comment:
        domain = normalize_domain(host_comment.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    url_domain = extract_domain_from_url(line)
    if url_domain:
        return f"||{url_domain}^"

    ag_mod = re.match(r'^(@@)?(\|\|)?(\*\.)?([a-z0-9\u00a1-\uffff._-]+)\^(\$[^\s]*)?$', line, re.IGNORECASE)
    if ag_mod:
        exc = ag_mod.group(1) or ""
        prefix = ag_mod.group(2) or "||"
        star = ag_mod.group(3) or ""
        domain = normalize_domain(ag_mod.group(4))
        if is_valid_domain(domain):
            return f"{exc}{prefix}{star}{domain}^"
        return None

    ag_plain = re.match(r'^(@@)?(\|\|)?(\*\.)?([a-z0-9\u00a1-\uffff._-]+)$', line, re.IGNORECASE)
    if ag_plain:
        exc = ag_plain.group(1) or ""
        prefix = ag_plain.group(2) or "||"
        star = ag_plain.group(3) or ""
        domain = normalize_domain(ag_plain.group(4))
        if is_valid_domain(domain):
            return f"{exc}{prefix}{star}{domain}^"
        return None

    dns_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::|255\.255\.255\.255)\s+(.+)$', line, re.IGNORECASE)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        if domain in ('localhost', 'localhost.localdomain', 'broadcasthost'):
            return None
        if is_valid_domain(domain):
            return f"||{domain}^"
        if is_valid_ip(domain):
            return f"||{domain}^"
        return None

    exc_dns = re.match(r'^@@(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if exc_dns:
        domain = normalize_domain(exc_dns.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None

    if line.startswith("*."):
        domain = line[2:]
        if is_valid_domain(domain):
            return f"||*.{normalize_domain(domain)}^"
        return None

    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z]{2,}$', line):
        if is_valid_domain(line):
            return f"||{normalize_domain(line)}^"
        return None

    if is_valid_ip(line):
        return f"||{line}^"

    ip_port_match = re.match(r'^(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?', line)
    if ip_port_match:
        ip = ip_port_match.group(1)
        if is_valid_ip(ip):
            return f"||{ip}^"
        return None

    easy_match = re.match(r'^(@@)?(\|\|)?(\*\.)?([^\s\$]+)\^(\$[^\s]*)?$', line)
    if easy_match:
        exc = easy_match.group(1) or ""
        prefix = easy_match.group(2) or "||"
        star = easy_match.group(3) or ""
        domain = normalize_domain(easy_match.group(4))
        if is_valid_domain(domain):
            return f"{exc}{prefix}{star}{domain}^"
        return None

    path_match = re.match(r'^(@@)?(\|\|)?(\*\.)?([^/\s]+)(/[^\s]*)?$', line)
    if path_match:
        exc = path_match.group(1) or ""
        prefix = path_match.group(2) or "||"
        star = path_match.group(3) or ""
        domain = normalize_domain(path_match.group(4))
        if is_valid_domain(domain):
            return f"{exc}{prefix}{star}{domain}^"
        return None

    exc_plain = re.match(r'^@@(\|\|)?(\*\.)?([^\s\$]+)\^?$', line)
    if exc_plain:
        prefix = exc_plain.group(1) or "||"
        star = exc_plain.group(2) or ""
        domain = normalize_domain(exc_plain.group(3))
        if is_valid_domain(domain):
            return f"@@{prefix}{star}{domain}^"
        return None

    star_match = re.match(r'^(@@)?(\|\|)?\*\.([a-z0-9\u00a1-\uffff._-]+)\^?$', line, re.IGNORECASE)
    if star_match:
        exc = star_match.group(1) or ""
        prefix = star_match.group(2) or "||"
        domain = normalize_domain(star_match.group(3))
        if is_valid_domain(domain):
            return f"{exc}{prefix}*.{domain}^"
        return None

    ag_path_mod = re.match(r'^(@@)?(\|\|)?(\*\.)?([^/\s]+)/[^\s]*\^(\$[^\s]*)?$', line)
    if ag_path_mod:
        exc = ag_path_mod.group(1) or ""
        prefix = ag_path_mod.group(2) or "||"
        star = ag_path_mod.group(3) or ""
        domain = normalize_domain(ag_path_mod.group(4))
        if is_valid_domain(domain):
            return f"{exc}{prefix}{star}{domain}^"
        return None

    return None

# ─── Smart Filter Detector ───────────────────────────────────────────────────
def looks_like_filter(text):
    if not text or len(text) < 50:
        return False
    lines = text.split("\n")[:100]
    rule_indicators = ["||", "@@", "0.0.0.0", "127.0.0.1", "[Adblock", "! Title", "! Version", "##", "#@#", "CNAME .", "#Tracker", "#Malware", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "zone \"", "server=/", "host,"]
    rule_count = sum(1 for line in lines if any(ind in line for ind in rule_indicators))
    filter_indicators = ["[Adblock", "! Title:", "! Version:", "! Expires:", "! Homepage:", "! Last modified:", "$TTL", "@ IN SOA"]
    meta_count = sum(1 for line in lines if any(ind in line for ind in filter_indicators))
    domain_count = sum(1 for line in lines if re.match(r'^([a-z0-9_-]+\.)+[a-z]{2,}$', line.strip()))
    url_count = sum(1 for line in lines if line.strip().startswith(("http://", "https://")))
    return rule_count >= 2 or meta_count >= 1 or domain_count >= 3 or url_count >= 3 or len(text) > 5000

# ─── Download with Sequential Processing ────────────────────────────────────
def download_filter(url, session, attempt=0):
    parsed = urlparse(url)
    domain = parsed.netloc
    
    strategies = []
    strategies.append({"url": url, "headers": {}})
    
    if "github.com" in domain and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        strategies.insert(0, {"url": raw_url, "headers": {}})
    
    if "gitlab.com" in domain and "-" in url and "/raw/" not in url:
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
                timeout=(5, REQUEST_TIMEOUT),
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 3))
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
            
            text = content.decode("utf-8", errors="replace")
            
            if len(text) < 100:
                if not looks_like_filter(text):
                    last_error = "Empty or invalid content"
                    continue
            
            return text
            
        except requests.exceptions.Timeout:
            last_error = "Timeout"
            if attempt < MAX_RETRIES:
                return download_filter(url, session, attempt + 1)
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection: {str(e)[:50]}"
        except requests.exceptions.HTTPError as e:
            last_error = f"HTTP {e.response.status_code}"
            if e.response.status_code == 404:
                break
        except Exception as e:
            last_error = str(e)[:80]
    
    return None

# ─── Main Processing - SEQUENTIAL ────────────────────────────────────────────
def process_all_filters(urls):
    session = create_session()
    block_rules = set()
    allow_rules = set()
    failed_urls = []
    failed_reasons = {}
    
    print(f"🔍 معالجة {len(urls)} مصدر... (Sequential mode)")
    print(f"⚙️  Timeout: {REQUEST_TIMEOUT}s | Delay: {REQUEST_DELAY}s")
    print("=" * 70)
    
    for i, url in enumerate(urls, 1):
        check_timeout()
        
        domain = urlparse(url).netloc
        
        # Delay بناءً على نوع السيرفر
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
                failed_reasons[url] = "Download failed"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:35s} | Download failed")
                print(f"   ↳ {url}")
                continue
            
            if not looks_like_filter(text):
                preview = text[:200].replace('\n', ' ')
                failed_urls.append(url)
                failed_reasons[url] = f"Not a filter: {preview[:60]}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:35s} | Not a filter")
                print(f"   ↳ {url}")
                continue
            
            rules = []
            css_domains = set()
            
            for line in text.splitlines():
                converted = convert_to_adguard(line)
                if converted:
                    if line.strip().find('##') > 0 or line.strip().find('#@#') > 0:
                        css_domain = extract_domain_from_css(line)
                        if css_domain and css_domain not in css_domains:
                            css_domains.add(css_domain)
                            rules.append(converted)
                    else:
                        rules.append(converted)
            
            if not rules:
                preview_lines = [l for l in text.splitlines()[:20] if l.strip() and not l.startswith('!') and not l.startswith('#')]
                preview = ' | '.join(preview_lines[:5])
                failed_urls.append(url)
                failed_reasons[url] = f"No valid rules: {preview[:60]}"
                print(f"❌ [{i:3d}/{len(urls)}] {domain:35s} | No valid rules")
                print(f"   ↳ {url}")
                continue
            
            new_block = []
            new_allow = []
            
            for rule in rules:
                if rule.startswith("@@"):
                    if rule not in allow_rules:
                        allow_rules.add(rule)
                        new_allow.append(rule)
                else:
                    if rule not in block_rules:
                        block_rules.add(rule)
                        new_block.append(rule)
            
            print(f"✅ [{i:3d}/{len(urls)}] {domain:35s} | +{len(new_block):6d} block | +{len(new_allow):4d} allow")
            
        except Exception as e:
            failed_urls.append(url)
            failed_reasons[url] = f"Exception: {str(e)[:50]}"
            print(f"💥 [{i:3d}/{len(urls)}] {domain:35s} | Exception: {str(e)[:40]}")
            print(f"   ↳ {url}")
    
    # ترتيب: استثناءات أولاً ثم حظر
    sorted_rules = sorted(allow_rules, key=lambda x: extract_domain_from_rule(x))
    sorted_rules.extend(sorted(block_rules, key=lambda x: extract_domain_from_rule(x)))
    
    print("=" * 70)
    print(f"📊 النتائج:")
    print(f"   ✅ ناجح: {len(urls) - len(failed_urls)}/{len(urls)}")
    print(f"   ❌ فاشل: {len(failed_urls)}/{len(urls)}")
    print(f"   🚫 قواعد حظر: {len(block_rules):,}")
    print(f"   ✅ قواعد استثناء: {len(allow_rules):,}")
    
    if failed_urls:
        print(f"\n🔗 الروابط الفاشلة ({len(failed_urls)}):")
        for url in failed_urls:
            print(f"   ❌ {url}")
            print(f"      السبب: {failed_reasons[url][:80]}")
    
    return sorted_rules, failed_urls

# ─── Save ────────────────────────────────────────────────────────────────────
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
    print(f"   📁 ملف واحد فقط")
    
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

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("   Filters.AdGuard.Android v13 - Sequential Mode")
    print("   يدعم: Surge | Quantumult X | BIND | CSV | dnsmasq | DNS RPZ | Hosts | URLs | CSS | AdGuard")
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
'''

with open('/mnt/agents/output/Filters.AdGuard.Android.py', 'w', encoding='utf-8') as f:
    f.write(script_v13)

print("✅ Saved Filters.AdGuard.Android.py v13")
print(f"   Size: {len(script_v13):,} bytes")
