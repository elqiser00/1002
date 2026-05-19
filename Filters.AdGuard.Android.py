#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Advanced Filter Merger for AdGuard Android App
=========================================================================
يجمع فلاتر متعددة من list.txt، ينظفها، يحولها لصيغة AdGuard Android
"""

import requests
import os
import sys
import time
import re
import json
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import ssl
import urllib3
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────
MAX_LINES_PER_PART = 1_500_000
MAX_LINE_LENGTH = 4096
REQUEST_TIMEOUT = 90
REQUEST_DELAY = 0.3
MAX_WORKERS = 15
MAX_RETRIES = 5
BACKOFF_FACTOR = 2
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Session ─────────────────────────────────────────────────────────────────
def create_session():
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        max_retries=requests.adapters.Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        ),
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS * 2
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.headers.update({
        'User-Agent': USER_AGENT,
        'Accept': 'text/plain,application/octet-stream,*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    })
    return session

# ─── Load URLs ───────────────────────────────────────────────────────────────
def load_filter_urls(filename="list.txt"):
    """تحميل روابط الفلاتر من ملف list.txt - سطر واحد = رابط واحد"""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            urls = []
            for line in file:
                line = line.strip()
                # قبول أي سطر يبدأ بـ http
                if line and line.startswith(("http://", "https://")):
                    urls.append(line)
            return urls
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود!")
        return []

# ─── Rule Processing ─────────────────────────────────────────────────────────
def normalize_domain(domain):
    """تطبيع النطاق"""
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.rstrip('.')

def is_valid_domain(domain):
    """التحقق من صحة النطاق"""
    if not domain or len(domain) > 253:
        return False
    # نطاق عادي أو IDN
    if re.match(r'^[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(\.[a-z0-9\u00a1-\uffff]([a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?)*\.[a-zA-Z]{2,}$', domain):
        return True
    return False

def convert_to_adguard(line):
    """تحويل أي سطر لصيغة AdGuard Android"""
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    # تجاهل التعليقات والأسطر الفارغة
    if not line or line.startswith(("!", "#", ";", "[", "$", "%", "&", "*", "//")):
        return None

    # ── قواعد AdGuard جاهزة ─────────────────────────────────────────────
    # ||domain^ أو @@||domain^
    ag_match = re.match(r'^(@@)?\|\|([a-z0-9\u00a1-\uffff._-]+)\^?$', line, re.IGNORECASE)
    if ag_match:
        exc = ag_match.group(1) or ""
        domain = normalize_domain(ag_match.group(2))
        if is_valid_domain(domain):
            return f"{exc}||{domain}^"
        return None

    # ── قواعد DNS / hosts ────────────────────────────────────────────────
    dns_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None

    # ── قواعد استثناء DNS ────────────────────────────────────────────────
    exc_dns = re.match(r'^@@(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if exc_dns:
        domain = normalize_domain(exc_dns.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None

    # ── wildcard *.domain.com ────────────────────────────────────────────
    if line.startswith("*."):
        domain = line[2:]
        if is_valid_domain(domain):
            return f"||{normalize_domain(domain)}^"
        return None

    # ── نطاق صريح (بدون بادئة) ──────────────────────────────────────────
    if re.match(r'^([a-z0-9\u00a1-\uffff_-]+\.)+[a-zA-Z]{2,}$', line):
        if is_valid_domain(line):
            return f"||{normalize_domain(line)}^"
        return None

    # ── IP مباشرة ────────────────────────────────────────────────────────
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', line):
        return f"||{line}^"

    return None

# ─── Download ────────────────────────────────────────────────────────────────
def download_filter(url, session):
    """تحميل الفلتر مع معالجة جميع المشاكل"""
    strategies = [
        {"url": url, "verify": False, "allow_redirects": True, "timeout": REQUEST_TIMEOUT},
        {"url": url.replace("https://", "http://", 1), "verify": False, "allow_redirects": True, "timeout": REQUEST_TIMEOUT},
        {"url": url, "verify": False, "allow_redirects": False, "timeout": REQUEST_TIMEOUT},
    ]

    # تحويل GitHub blob لـ raw
    if "github.com" in url and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        strategies.insert(0, {"url": raw_url, "verify": False, "allow_redirects": True, "timeout": REQUEST_TIMEOUT})

    last_error = None
    for attempt, strategy in enumerate(strategies):
        try:
            time.sleep(REQUEST_DELAY * attempt)
            response = session.get(
                strategy["url"],
                verify=strategy.get("verify", False),
                allow_redirects=strategy.get("allow_redirects", True),
                timeout=strategy.get("timeout", REQUEST_TIMEOUT)
            )

            # يدوي redirect
            if response.status_code in (301, 302, 307, 308) and not strategy.get("allow_redirects", True):
                loc = response.headers.get("Location", "")
                if loc:
                    if not loc.startswith("http"):
                        loc = urljoin(strategy["url"], loc)
                    return download_filter(loc, session)

            response.raise_for_status()

            # فك ضغط
            content = response.content
            if content[:2] == b'\x1f\x8b':
                try:
                    content = gzip.decompress(content)
                except Exception:
                    pass

            return content.decode("utf-8", errors="replace")

        except Exception as e:
            last_error = str(e)[:100]
            continue

    print(f"⚠️ فشل تحميل {urlparse(url).netloc}: {last_error}")
    return None

def looks_like_filter(text):
    """التحقق السريع"""
    lines = text.split("\n")[:30]
    indicators = ["||", "@@", "0.0.0.0", "127.0.0.1"]
    return sum(1 for line in lines if any(ind in line for ind in indicators)) >= 2

# ─── Main Processing ─────────────────────────────────────────────────────────
def process_all_filters(urls):
    session = create_session()
    block_rules = set()
    allow_rules = set()
    failed = []

    print(f"🔍 معالجة {len(urls)} مصدر...")
    print("=" * 60)

    def process_one(url):
        text = download_filter(url, session)
        if not text:
            return url, [], False

        if not looks_like_filter(text):
            return url, [], False

        rules = []
        for line in text.splitlines():
            converted = convert_to_adguard(line)
            if converted:
                rules.append(converted)
        return url, rules, True

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_one, url): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            url, rules, success = future.result()
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

                print(f"✅ [{i:3d}/{len(urls)}] {domain:35s} | +{len(new_block):5d} block | +{len(new_allow):4d} allow")
            else:
                failed.append(url)
                print(f"❌ [{i:3d}/{len(urls)}] {domain:35s} | فشل")

            if i < len(urls):
                time.sleep(REQUEST_DELAY)

    # ترتيب: استثناءات أولاً
    sorted_rules = sorted(allow_rules, key=lambda x: x.lstrip("@|").rstrip("^"))
    sorted_rules.extend(sorted(block_rules, key=lambda x: x.lstrip("|").rstrip("^")))

    print("=" * 60)
    print(f"📊 نتائج: {len(allow_rules)} allow | {len(block_rules)} block | {len(failed)} failed")

    return sorted_rules, failed

# ─── Save ────────────────────────────────────────────────────────────────────
def save_filters(rules, output_dir="merged_filters", sources=0, failed=0):
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"""! Title: Merged Filters for AdGuard Android
! Description: مجمع فلاتر متقدم لـ AdGuard Android
! Version: {now.replace(" ", "-").replace(":", "-")}
! Last Modified: {now}
! Expires: 6 hours
! Sources: {sources} | Failed: {failed}
! Total Rules: {len(rules):,}
!
! ==================== ملاحظات ====================
! - الاستثناءات (@@) في البداية
! - قواعد الحظر تليها
! - تم إزالة التكرارات
! ==================================================
!
"""

    main_file = os.path.join(output_dir, "adguard_android_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write("\n".join(rules))

    print(f"\n✅ تم الحفظ: {main_file} ({len(rules):,} قاعدة)")

    # تقسيم
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

    # stats.json
    stats = {
        "generated_at": now,
        "total_rules": len(rules),
        "allow_rules": sum(1 for r in rules if r.startswith("@@")),
        "block_rules": sum(1 for r in rules if not r.startswith("@@")),
        "sources": sources,
        "failed": failed
    }
    with open(os.path.join(output_dir, "stats.json"), 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    return main_file

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("   Filters.AdGuard.Android - Filter Merger")
    print("=" * 60)

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

    save_filters(rules, sources=len(urls)-len(failed), failed=len(failed))

    print(f"\n⏱️  الوقت: {time.time()-start:.1f} ثانية")
    print(f"📊 الإجمالي: {len(rules):,} قاعدة")
    print("✅ تم بنجاح!")

if __name__ == "__main__":
    main()
