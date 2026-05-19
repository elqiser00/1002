#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Universal Filter Merger v4
=====================================================
يدعم جميع صيغ الفلاتر ويحولها لـ AdGuard Android
"""

import requests
import os
import sys
import time
import re
import json
import gzip
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import urllib3
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────
MAX_LINES_PER_PART = 1_500_000
MAX_LINE_LENGTH = 8192
REQUEST_TIMEOUT = 120
REQUEST_DELAY_MIN = 0.5
REQUEST_DELAY_MAX = 2.0
MAX_WORKERS = 8
MAX_RETRIES = 10
BACKOFF_FACTOR = 2

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Session ─────────────────────────────────────────────────────────────────
def create_session():
    session = requests.Session()
    retry_strategy = requests.adapters.Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        raise_on_status=False
    )
    adapter = requests.adapters.HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS * 3,
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
    # دعم IDN + نطاقات عادية
    if re.match(r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z]{2,}$', domain):
        return True
    return False

def extract_domain_from_rule(rule):
    """استخراج النطاق من أي قاعدة"""
    # إزالة @@ و || و ^ و modifiers
    clean = rule.lstrip("@").lstrip("|").rstrip("^")
    if '$' in clean:
        clean = clean.split('$')[0]
    if '/' in clean:
        clean = clean.split('/')[0]
    return clean

# ─── Universal Rule Converter ────────────────────────────────────────────────
def convert_to_adguard(line):
    """
    محول شامل يدعم جميع صيغ الفلاتر:
    - AdGuard: ||domain^, ||domain^$modifier, @@||domain^$modifier
    - Hosts: 0.0.0.0 domain, 127.0.0.1 domain
    - Plain domain: domain.com
    - Wildcard: *.domain.com
    - EasyList: ||domain^$third-party, ||domain^$popup
    - DNS: domain (plain)
    """
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    # تجاهل التعليقات والأسطر الفارغة والميتا-داتا
    if not line or line.startswith(("!", "#", ";", "[", "$", "%", "&", "*", "//", "@")):
        # استثناء: @@||domain^ (قواعد استثناء AdGuard)
        if not line.startswith("@@"):
            return None

    # ── 1. قواعد AdGuard مع modifiers ────────────────────────────────────
    # ||domain^$third-party,important,etc
    ag_mod = re.match(r'^(@@)?\|\|([a-z0-9\u00a1-\uffff._-]+)\^(\$[^\s]*)?$', line, re.IGNORECASE)
    if ag_mod:
        exc = ag_mod.group(1) or ""
        domain = normalize_domain(ag_mod.group(2))
        if is_valid_domain(domain):
            return f"{exc}||{domain}^"
        return None

    # ── 2. قواعد AdGuard بدون ^ ─────────────────────────────────────────
    # ||domain (بدون ^)
    ag_plain = re.match(r'^(@@)?\|\|([a-z0-9\u00a1-\uffff._-]+)$', line, re.IGNORECASE)
    if ag_plain:
        exc = ag_plain.group(1) or ""
        domain = normalize_domain(ag_plain.group(2))
        if is_valid_domain(domain):
            return f"{exc}||{domain}^"
        return None

    # ── 3. قواعد DNS / hosts ─────────────────────────────────────────────
    dns_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::|255\.255\.255\.255)\s+(.+)$', line, re.IGNORECASE)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        # تجاهل localhost
        if domain in ('localhost', 'localhost.localdomain', 'broadcasthost'):
            return None
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # ── 4. قواعد استثناء DNS ─────────────────────────────────────────────
    exc_dns = re.match(r'^@@(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if exc_dns:
        domain = normalize_domain(exc_dns.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None

    # ── 5. Wildcard domains ──────────────────────────────────────────────
    if line.startswith("*."):
        domain = line[2:]
        if is_valid_domain(domain):
            return f"||{normalize_domain(domain)}^"
        return None

    # ── 6. نطاق صريح (بدون بادئة) ────────────────────────────────────────
    # domain.com أو domain.co.uk
    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z]{2,}$', line):
        if is_valid_domain(line):
            return f"||{normalize_domain(line)}^"
        return None

    # ── 7. IP مباشرة ─────────────────────────────────────────────────────
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', line):
        return f"||{line}^"

    # ── 8. قواعد EasyList المتقدمة ──────────────────────────────────────
    # ||domain.com^$third-party
    easy_match = re.match(r'^(@@)?\|\|([^\s\$]+)\^(\$[^\s]*)?$', line)
    if easy_match:
        exc = easy_match.group(1) or ""
        domain = normalize_domain(easy_match.group(2))
        if is_valid_domain(domain):
            return f"{exc}||{domain}^"
        return None

    # ── 9. قواعد مسار (path rules) ──────────────────────────────────────
    # ||domain.com/path
    path_match = re.match(r'^(@@)?\|\|([^/\s]+)(/[^\s]*)?$', line)
    if path_match:
        exc = path_match.group(1) or ""
        domain = normalize_domain(path_match.group(2))
        if is_valid_domain(domain):
            return f"{exc}||{domain}^"
        return None

    # ── 10. قواعد نطاق مع استثناء مسار ──────────────────────────────────
    # @@||domain.com
    exc_plain = re.match(r'^@@\|\|([^\s\$]+)\^?$', line)
    if exc_plain:
        domain = normalize_domain(exc_plain.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None

    return None

# ─── Smart Filter Detector ───────────────────────────────────────────────────
def looks_like_filter(text):
    """اكتشاف ذكي لمحتوى الفلتر"""
    if not text or len(text) < 50:
        return False

    lines = text.split("\n")[:100]

    # مؤشرات القواعد
    rule_indicators = ["||", "@@", "0.0.0.0", "127.0.0.1", "[Adblock", "! Title", "! Version"]
    rule_count = sum(1 for line in lines if any(ind in line for ind in rule_indicators))

    # مؤشرات الفلتر
    filter_indicators = ["[Adblock", "! Title:", "! Version:", "! Expires:", "! Homepage:", "! Last modified:"]
    meta_count = sum(1 for line in lines if any(ind in line for ind in filter_indicators))

    # لو فيه metadata أو قواعد كفاية
    return rule_count >= 2 or meta_count >= 1 or len(text) > 5000

# ─── Advanced Download ───────────────────────────────────────────────────────
def download_filter(url, session, attempt=0):
    parsed = urlparse(url)
    domain = parsed.netloc

    strategies = []

    # 1. الرابط الأصلي
    strategies.append({"url": url, "headers": {}})

    # 2. GitHub blob → raw
    if "github.com" in domain and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        strategies.insert(0, {"url": raw_url, "headers": {}})

    # 3. GitLab blob → raw
    if "gitlab.com" in domain and "-" in url and "/raw/" not in url:
        parts = url.split("/blob/")
        if len(parts) == 2:
            raw_url = f"{parts[0]}/raw/{parts[1]}"
            strategies.insert(0, {"url": raw_url, "headers": {}})

    # 4. HTTP fallback
    if url.startswith("https://"):
        strategies.append({"url": url.replace("https://", "http://", 1), "headers": {}})

    last_error = None

    for strategy in strategies:
        try:
            delay = random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX)
            if attempt > 0:
                delay *= (attempt + 1) * 0.5
            time.sleep(delay)

            session.headers['User-Agent'] = random.choice(USER_AGENTS)

            headers = dict(session.headers)
            headers.update(strategy.get("headers", {}))

            response = session.get(
                strategy["url"],
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 10))
                print(f"⏳ Rate limit: {domain}, waiting {retry_after}s...")
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

            # التحقق من المحتوى
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

# ─── Main Processing ─────────────────────────────────────────────────────────
def process_all_filters(urls):
    session = create_session()
    block_rules = set()
    allow_rules = set()
    failed_urls = []
    failed_reasons = {}

    print(f"🔍 معالجة {len(urls)} مصدر...")
    print(f"⚙️  Workers: {MAX_WORKERS} | Timeout: {REQUEST_TIMEOUT}s")
    print("=" * 70)

    def process_one(url):
        text = download_filter(url, session)
        if text is None:
            return url, [], False, "Download failed"

        if not looks_like_filter(text):
            # جرب نعرض شوية من المحتوى للتشخيص
            preview = text[:200].replace('\n', ' ')
            return url, [], False, f"Not a filter (preview: {preview[:80]}...)"

        rules = []
        for line in text.splitlines():
            converted = convert_to_adguard(line)
            if converted:
                rules.append(converted)

        if not rules:
            # تشخيص: اعرض شوية أسطر من الملف
            preview_lines = [l for l in text.splitlines()[:20] if l.strip() and not l.startswith('!')]
            preview = ' | '.join(preview_lines[:5])
            return url, [], False, f"No valid rules (sample: {preview[:100]}...)"

        return url, rules, True, "OK"

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_one, url): url for url in urls}

        for i, future in enumerate(as_completed(futures), 1):
            url, rules, success, reason = future.result()
            domain = urlparse(url).netloc[:35]

            if success and rules:
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
            else:
                failed_urls.append(url)
                failed_reasons[url] = reason
                print(f"❌ [{i:3d}/{len(urls)}] {domain:35s} | {reason[:50]}")

    # ترتيب
    sorted_rules = sorted(allow_rules, key=lambda x: extract_domain_from_rule(x))
    sorted_rules.extend(sorted(block_rules, key=lambda x: extract_domain_from_rule(x)))

    print("=" * 70)
    print(f"📊 النتائج:")
    print(f"   ✅ ناجح: {len(urls) - len(failed_urls)}/{len(urls)}")
    print(f"   ❌ فاشل: {len(failed_urls)}/{len(urls)}")
    print(f"   🚫 قواعد حظر: {len(block_rules):,}")
    print(f"   ✅ قواعد استثناء: {len(allow_rules):,}")

    if failed_urls:
        reason_counts = {}
        for reason in failed_reasons.values():
            key = reason.split('(')[0].strip()
            reason_counts[key] = reason_counts.get(key, 0) + 1
        print(f"\n📋 أسباب الفشل:")
        for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"   - {reason}: {count}")

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

    if len(rules) > MAX_LINES_PER_PART:
        parts = (len(rules) // MAX_LINES_PER_PART) + (1 if len(rules) % MAX_LINES_PER_PART else 0)
        print(f"📦 تقسيم إلى {parts} جزء...")
        for i in range(parts):
            part_file = os.path.join(output_dir, f"adguard_android_filter_part_{i+1:02d}.txt")
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write(header)
                start = i * MAX_LINES_PER_PART
                end = min(start + MAX_LINES_PER_PART, len(rules))
                f.write("\n".join(rules[start:end]))
            print(f"   ✅ الجزء {i+1}: {end-start:,} قاعدة")

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
    print("   Filters.AdGuard.Android v4 - Universal Filter Merger")
    print("=" * 70)

    urls = load_filter_urls("list.txt")
    if not urls:
        print("❌ لا توجد روابط في list.txt!")
        sys.exit(1)

    print(f"📋 {len(urls)} رابط في list.txt\n")

    start = time.time()
    rules, failed = process_all_filters(urls)

    if not rules:
        print("❌ لم يتم استخراج أي قواعد!")
        sys.exit(1)

    save_filters(rules, total_urls=len(urls), failed_count=len(failed))

    print(f"\n⏱️  الوقت: {time.time()-start:.1f} ثانية")
    print(f"📊 الإجمالي: {len(rules):,} قاعدة")
    print("✅ تم بنجاح!")

if __name__ == "__main__":
    main()
