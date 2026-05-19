#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Advanced Filter Merger v3
====================================================
محسّن لتجنب Rate Limiting ويدعم جميع أنواع الروابط
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
MAX_LINE_LENGTH = 4096
REQUEST_TIMEOUT = 120
REQUEST_DELAY_MIN = 1.0
REQUEST_DELAY_MAX = 3.0
MAX_WORKERS = 5           # قللنا علشان Rate Limit
MAX_RETRIES = 8
BACKOFF_FACTOR = 3

# User-Agents متعددة (تقليد متصفحات حقيقية)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Session ─────────────────────────────────────────────────────────────────
def create_session():
    session = requests.Session()

    # Retry strategy أقوى
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

    # Headers شبه متصفح حقيقي
    session.headers.update({
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    })

    return session

# ─── Load URLs ───────────────────────────────────────────────────────────────
def load_filter_urls(filename="list.txt"):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            urls = []
            for line in file:
                line = line.strip()
                if line and line.startswith(("http://", "https://")):
                    urls.append(line)
            return urls
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود!")
        return []

# ─── Rule Processing ─────────────────────────────────────────────────────────
def normalize_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.rstrip('.')

def is_valid_domain(domain):
    if not domain or len(domain) > 253:
        return False
    if re.match(r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z]{2,}$', domain):
        return True
    return False

def convert_to_adguard(line):
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    if not line or line.startswith(("!", "#", ";", "[", "$", "%", "&", "*", "//")):
        return None

    # AdGuard rules
    ag_match = re.match(r'^(@@)?\|\|([a-z0-9\u00a1-\uffff._-]+)\^?$', line, re.IGNORECASE)
    if ag_match:
        exc = ag_match.group(1) or ""
        domain = normalize_domain(ag_match.group(2))
        if is_valid_domain(domain):
            return f"{exc}||{domain}^"
        return None

    # DNS / hosts
    dns_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # Exception DNS
    exc_dns = re.match(r'^@@(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if exc_dns:
        domain = normalize_domain(exc_dns.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None

    # Wildcard
    if line.startswith("*."):
        domain = line[2:]
        if is_valid_domain(domain):
            return f"||{normalize_domain(domain)}^"
        return None

    # Plain domain
    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z]{2,}$', line):
        if is_valid_domain(line):
            return f"||{normalize_domain(line)}^"
        return None

    # Direct IP
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', line):
        return f"||{line}^"

    return None

# ─── Advanced Download ───────────────────────────────────────────────────────
def download_filter(url, session, attempt=0):
    """تحميل مع retry متقدم ومعالجة جميع الحالات"""

    parsed = urlparse(url)
    domain = parsed.netloc

    # استراتيجيات متعددة
    strategies = []

    # 1. الروابط المباشرة
    strategies.append({
        "url": url,
        "headers": {
            'Host': domain,
            'Referer': f"https://{domain}/",
        }
    })

    # 2. GitHub blob → raw
    if "github.com" in domain and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        strategies.insert(0, {
            "url": raw_url,
            "headers": {'Host': 'raw.githubusercontent.com'}
        })

    # 3. GitLab blob → raw
    if "gitlab.com" in domain and "/blob/" in url:
        parts = url.split("/blob/")
        if len(parts) == 2:
            raw_url = f"{parts[0]}/raw/{parts[1]}"
            strategies.insert(0, {
                "url": raw_url,
                "headers": {'Host': 'gitlab.com'}
            })

    # 4. HTTP fallback
    if url.startswith("https://"):
        strategies.append({
            "url": url.replace("https://", "http://", 1),
            "headers": {'Host': domain}
        })

    last_error = None

    for strategy in strategies:
        try:
            # Delay عشوائي لتجنب pattern detection
            delay = random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX)
            if attempt > 0:
                delay *= (attempt + 1)
            time.sleep(delay)

            # تحديث User-Agent عشوائي
            session.headers['User-Agent'] = random.choice(USER_AGENTS)

            headers = session.headers.copy()
            headers.update(strategy.get("headers", {}))

            response = session.get(
                strategy["url"],
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                stream=False
            )

            # التعامل مع rate limit
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 5))
                print(f"⏳ Rate limit on {domain}, waiting {retry_after}s...")
                time.sleep(retry_after)
                if attempt < MAX_RETRIES:
                    return download_filter(url, session, attempt + 1)
                continue

            response.raise_for_status()

            # فك ضغط
            content = response.content
            if content[:2] == b'\x1f\x8b':
                try:
                    content = gzip.decompress(content)
                except Exception:
                    pass

            text = content.decode("utf-8", errors="replace")

            # التحقق السريع
            if len(text) < 100:
                # محتوى قصير جداً، ربما error page
                if not any(ind in text for ind in ["||", "@@", "0.0.0.0", "127.0.0.1"]):
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

def looks_like_filter(text):
    if not text or len(text) < 50:
        return False
    lines = text.split("\n")[:50]
    indicators = ["||", "@@", "0.0.0.0", "127.0.0.1", "#", "!"]
    count = sum(1 for line in lines if any(ind in line for ind in indicators))
    return count >= 2

# ─── Main Processing ─────────────────────────────────────────────────────────
def process_all_filters(urls):
    session = create_session()
    block_rules = set()
    allow_rules = set()
    failed_urls = []
    failed_reasons = {}

    print(f"🔍 معالجة {len(urls)} مصدر...")
    print(f"⚙️  Workers: {MAX_WORKERS} | Timeout: {REQUEST_TIMEOUT}s | Delay: {REQUEST_DELAY_MIN}-{REQUEST_DELAY_MAX}s")
    print("=" * 70)

    def process_one(url):
        text = download_filter(url, session)
        if text is None:
            return url, [], False, "Download failed"

        if not looks_like_filter(text):
            return url, [], False, "Not a filter file"

        rules = []
        for line in text.splitlines():
            converted = convert_to_adguard(line)
            if converted:
                rules.append(converted)

        if not rules:
            return url, [], False, "No valid rules found"

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
                print(f"❌ [{i:3d}/{len(urls)}] {domain:35s} | {reason}")

    # ترتيب
    sorted_rules = sorted(allow_rules, key=lambda x: x.lstrip("@|").rstrip("^"))
    sorted_rules.extend(sorted(block_rules, key=lambda x: x.lstrip("|").rstrip("^")))

    print("=" * 70)
    print(f"📊 النتائج:")
    print(f"   ✅ ناجح: {len(urls) - len(failed_urls)}/{len(urls)}")
    print(f"   ❌ فاشل: {len(failed_urls)}/{len(urls)}")
    print(f"   🚫 قواعد حظر: {len(block_rules):,}")
    print(f"   ✅ قواعد استثناء: {len(allow_rules):,}")

    # عرض أسباب الفشل الأكثر شيوعاً
    if failed_urls:
        reason_counts = {}
        for reason in failed_reasons.values():
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
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
    print("   Filters.AdGuard.Android v3 - Filter Merger")
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
