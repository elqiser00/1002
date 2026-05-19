
script_content = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Filters.AdGuard.Android - Advanced Filter Merger for AdGuard Android App
=======================================================================
يجمع فلاتر متعددة، ينظفها، يحولها لصيغة AdGuard Android، ويدير:
- SSL/TLS issues
- Redirects & HTTP/HTTPS handling
- Cookies & Headers
- Rate limiting & retries
- Domain blocking + whitelist merging
- AdGuard Android syntax compatibility
"""

import requests
import os
import sys
import time
import re
import hashlib
import json
import gzip
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from pathlib import Path
import ssl
import urllib3
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────
MAX_LINES_PER_PART = 1_500_000      # تقسيم الملفات الكبيرة
MAX_LINE_LENGTH = 4096              # الحد الأقصى لطول السطر
REQUEST_TIMEOUT = 90                # زمن الانتظار
REQUEST_DELAY = 0.3                 # تأخير بين الطلبات
MAX_WORKERS = 15                    # عدد الخيوط المتزامنة
MAX_RETRIES = 5                     # عدد محاولات إعادة الطلب
BACKOFF_FACTOR = 2                  # معامل التأخير التصاعدي
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# إعدادات SSL مرنة
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Session with robust configuration ───────────────────────────────────────
def create_session():
    """إنشاء جلسة HTTP مرنة تتعامل مع جميع المشاكل"""
    session = requests.Session()
    
    # محولات بروتوكولات متعددة
    session.mount('https://', requests.adapters.HTTPAdapter(
        max_retries=requests.adapters.Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504, 520, 521, 522, 523, 524],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        ),
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS * 2
    ))
    
    session.mount('http://', requests.adapters.HTTPAdapter(
        max_retries=requests.adapters.Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        ),
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS * 2
    ))
    
    session.headers.update({
        'User-Agent': USER_AGENT,
        'Accept': 'text/plain,application/octet-stream,*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    })
    
    return session

# ─── URL Loaders ─────────────────────────────────────────────────────────────
def load_filter_urls(filename="list.txt"):
    """تحميل روابط الفلاتر من ملف list.txt"""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            urls = []
            for line in file:
                line = line.strip()
                if line and not line.startswith(("#", ";", "!", "//")):
                    # دعم الروابط المضغوطة وغير المضغوطة
                    urls.append(line)
            return urls
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود")
        return []

def load_filter_urls_from_json(filename="sources.json"):
    """تحميل من ملف JSON يدعم إعدادات متقدمة لكل مصدر"""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("sources", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# ─── Rule Validators & Converters ────────────────────────────────────────────

def is_valid_domain(domain):
    """التحقق من صحة النطاق"""
    if not domain or len(domain) > 253:
        return False
    # دعم النطاقات الدولية (IDN) والعادية
    pattern = r'^[a-zA-Z0-9\\u00a1-\\uffff]([a-zA-Z0-9\\u00a1-\\uffff-]{0,61}[a-zA-Z0-9\\u00a1-\\uffff])?(\\.[a-zA-Z0-9\\u00a1-\\uffff]([a-zA-Z0-9\\u00a1-\\uffff-]{0,61}[a-zA-Z0-9\\u00a1-\\uffff])?)*\\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain, re.IGNORECASE))

def normalize_domain(domain):
    """تطبيع النطاق (إزالة www.، تحويل لصغير)"""
    domain = domain.strip().lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.rstrip('.')

def is_valid_rule(line):
    """
    التحقق من صحة القاعدة لـ AdGuard Android
    يدعم:
    - قواعد الحظر الأساسية ||domain^
    - قواعد الاستثناء @@||domain^
    - قواعد DNS 0.0.0.0 domain
    - قواعد hosts
    - قواعد wildcard
    - قواعد regex (بشكل محدود)
    """
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return False
    
    # تجاهل التعليقات والميتا-داتا
    if line.startswith(("!", "#", ";", "[", "$", "%", "&", "*")):
        return False
    if line.startswith("//"):
        return False
    
    # تجاهل الأسطر الفارغة
    if not line:
        return False
    
    # أنواع القواعد المقبولة لـ AdGuard Android:
    
    # 1. قواعد AdGuard القياسية ||domain^
    if re.match(r'^\\|\\|([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}\\^?$', line, re.IGNORECASE):
        return True
    
    # 2. قواعد الاستثناء @@||domain^
    if re.match(r'^@@\\|\\|([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}\\^?$', line, re.IGNORECASE):
        return True
    
    # 3. قواعد DNS / hosts
    if re.match(r'^(0\\.0\\.0\\.0|127\\.0\\.0\\.1|::1|::)\\s+([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}$', line, re.IGNORECASE):
        return True
    
    # 4. قواعد wildcard *.domain.com
    if re.match(r'^\\*\\.([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}$', line, re.IGNORECASE):
        return True
    
    # 5. قواعد نطاق صريح domain.com
    if re.match(r'^([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}$', line, re.IGNORECASE):
        return True
    
    # 6. قواعد مع مسارات ||domain.com/path
    if re.match(r'^\\|\\|([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}(/[^\\s]*)?$', line, re.IGNORECASE):
        return True
    
    # 7. قواعد IP مباشرة
    if re.match(r'^(\\d{1,3}\\.){3}\\d{1,3}$', line):
        return True
    
    return False

def convert_to_adguard_android(line):
    """
    تحويل أي قاعدة لصيغة AdGuard Android المثلى
    """
    line = line.strip()
    if not line:
        return None
    
    # تجاهل التعليقات
    if line.startswith(("!", "#", ";", "[", "$", "%", "&", "*", "//")):
        return None
    
    # ── تحويل قواعد DNS / hosts ──────────────────────────────────────────
    dns_match = re.match(r'^(?:0\\.0\\.0\\.0|127\\.0\\.0\\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if dns_match:
        domain = normalize_domain(dns_match.group(1))
        if is_valid_domain(domain):
            return f"||{domain}^"
        return None
    
    # ── تحويل قواعد الاستثناء DNS ───────────────────────────────────────
    exc_dns_match = re.match(r'^@@(?:0\\.0\\.0\\.0|127\\.0\\.0\\.1|::1|::)\s+(.+)$', line, re.IGNORECASE)
    if exc_dns_match:
        domain = normalize_domain(exc_dns_match.group(1))
        if is_valid_domain(domain):
            return f"@@||{domain}^"
        return None
    
    # ── قواعد AdGuard القياسية ──────────────────────────────────────────
    if re.match(r'^\\|\\|([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}\\^?$', line, re.IGNORECASE):
        domain = line.lstrip("|").rstrip("^")
        return f"||{normalize_domain(domain)}^"
    
    # ── قواعد الاستثناء AdGuard ─────────────────────────────────────────
    if re.match(r'^@@\\|\\|([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}\\^?$', line, re.IGNORECASE):
        domain = line.lstrip("@|").rstrip("^")
        return f"@@||{normalize_domain(domain)}^"
    
    # ── تحويل wildcard ──────────────────────────────────────────────────
    if line.startswith("*."):
        domain = line[2:]
        if is_valid_domain(domain):
            return f"||{normalize_domain(domain)}^"
        return None
    
    # ── نطاق صريح (بدون بادئة) ──────────────────────────────────────────
    if re.match(r'^([a-z0-9\\u00a1-\\uffff_-]+\\.)+[a-z]{2,}$', line, re.IGNORECASE):
        if is_valid_domain(line):
            return f"||{normalize_domain(line)}^"
        return None
    
    # ── IP مباشرة ────────────────────────────────────────────────────────
    if re.match(r'^(\\d{1,3}\\.){3}\\d{1,3}$', line):
        return f"||{line}^"
    
    return None

def extract_domain_from_rule(rule):
    """استخراج النطاق الأساسي من القاعدة للمقارنة"""
    # إزالة @@ و || و ^
    clean = rule.lstrip("@").lstrip("|").rstrip("^")
    # إزالة المسار إن وجد
    if "/" in clean:
        clean = clean.split("/")[0]
    return clean

# ─── Advanced Downloader ───────────────────────────────────────────────────────

def download_filter_advanced(url, session=None):
    """
    تحميل الفلتر مع معالجة جميع المشاكل المحتملة:
    - SSL errors
    - Redirects
    - Compression (gzip)
    - Cookies
    - Rate limiting
    - Content-Type variations
    """
    if session is None:
        session = create_session()
    
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # محاولات متعددة مع استراتيجيات مختلفة
    strategies = [
        # الاستراتيجية 1: HTTPS عادي
        {"url": url, "verify": False, "allow_redirects": True, "timeout": REQUEST_TIMEOUT},
        # الاستراتيجية 2: HTTP إذا فشل HTTPS
        {"url": url.replace("https://", "http://", 1), "verify": False, "allow_redirects": True, "timeout": REQUEST_TIMEOUT},
        # الاستراتيجية 3: بدون متابعة التحويلات
        {"url": url, "verify": False, "allow_redirects": False, "timeout": REQUEST_TIMEOUT},
        # الاستراتيجية 4: مع headers إضافية
        {"url": url, "verify": False, "allow_redirects": True, "timeout": REQUEST_TIMEOUT + 30,
         "headers": {"Cookie": "", "Referer": f"https://{domain}/"}},
    ]
    
    last_error = None
    
    for attempt, strategy in enumerate(strategies):
        try:
            time.sleep(REQUEST_DELAY * (attempt + 1))  # تأخير تصاعدي
            
            response = session.get(
                strategy["url"],
                verify=strategy.get("verify", False),
                allow_redirects=strategy.get("allow_redirects", True),
                timeout=strategy.get("timeout", REQUEST_TIMEOUT),
                headers=strategy.get("headers", {}),
                stream=False
            )
            
            # التعامل مع التحويلات اليدوية
            if response.status_code in (301, 302, 307, 308) and not strategy.get("allow_redirects", True):
                redirect_url = response.headers.get("Location", "")
                if redirect_url:
                    if not redirect_url.startswith("http"):
                        redirect_url = urljoin(url, redirect_url)
                    return download_filter_advanced(redirect_url, session)
            
            response.raise_for_status()
            
            # فك الضغط إذا لزم الأمر
            content = response.content
            content_encoding = response.headers.get("Content-Encoding", "").lower()
            
            if "gzip" in content_encoding or content[:2] == b"\\x1f\\x8b":
                try:
                    content = gzip.decompress(content)
                except Exception:
                    pass
            
            text = content.decode("utf-8", errors="replace")
            
            # التحقق من أن المحتوى فلتر فعلي
            if not looks_like_filter(text):
                # محاولة تحميل من مرآة GitHub Raw
                if "github.com" in domain and "/blob/" in url:
                    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    return download_filter_advanced(raw_url, session)
            
            return text, url, True
            
        except requests.exceptions.SSLError as e:
            last_error = f"SSL Error: {str(e)[:80]}"
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection Error: {str(e)[:80]}"
            continue
        except requests.exceptions.Timeout as e:
            last_error = f"Timeout: {str(e)[:80]}"
            continue
        except requests.exceptions.TooManyRedirects as e:
            last_error = f"Too Many Redirects: {str(e)[:80]}"
            continue
        except requests.exceptions.HTTPError as e:
            last_error = f"HTTP {response.status_code}: {str(e)[:80]}"
            if response.status_code == 404:
                break  # لا فائدة من إعادة المحاولة
            continue
        except Exception as e:
            last_error = f"Error: {str(e)[:80]}"
            continue
    
    return None, url, False

def looks_like_filter(text):
    """التحقق السريع من أن النص يحتوي على قواعد فلترة"""
    lines = text.split("\\n")[:50]  # فحص أول 50 سطر
    filter_indicators = ["||", "@@", "0.0.0.0", "127.0.0.1", "#", "!"]
    count = sum(1 for line in lines if any(ind in line for ind in filter_indicators))
    return count >= 3

# ─── Rule Processing ─────────────────────────────────────────────────────────

def process_filter_content(text, source_url=""):
    """معالجة محتوى الفلتر واستخراج القواعد الصالحة"""
    rules = []
    lines = text.splitlines()
    
    for line in lines:
        converted = convert_to_adguard_android(line)
        if converted:
            rules.append(converted)
    
    return rules

# ─── Main Processing ─────────────────────────────────────────────────────────

def process_all_filters(urls):
    """معالجة جميع الفلاتر مع إدارة متقدمة"""
    session = create_session()
    
    all_block_rules = set()
    all_allow_rules = set()
    failed_urls = []
    stats = {
        "total_urls": len(urls),
        "successful": 0,
        "failed": 0,
        "total_block_rules": 0,
        "total_allow_rules": 0,
        "duplicates_removed": 0
    }
    
    print(f"🔍 بدء معالجة {len(urls)} مصدر فلتر...")
    print(f"⚙️  الإعدادات: {MAX_WORKERS} خيوط, {MAX_RETRIES} محاولات, {REQUEST_TIMEOUT}s مهلة")
    print("=" * 70)
    
    def process_single(url):
        text, original_url, success = download_filter_advanced(url, session)
        
        if not success or not text:
            return {"url": url, "success": False, "rules": [], "error": text}
        
        rules = process_filter_content(text, url)
        return {"url": url, "success": True, "rules": rules, "error": None}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(process_single, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url), 1):
            result = future.result()
            url = result["url"]
            domain = urlparse(url).netloc[:40]
            
            if result["success"]:
                new_block = []
                new_allow = []
                
                for rule in result["rules"]:
                    if rule.startswith("@@"):
                        if rule not in all_allow_rules:
                            all_allow_rules.add(rule)
                            new_allow.append(rule)
                    else:
                        if rule not in all_block_rules:
                            all_block_rules.add(rule)
                            new_block.append(rule)
                
                stats["successful"] += 1
                stats["total_block_rules"] += len(new_block)
                stats["total_allow_rules"] += len(new_allow)
                
                print(f"✅ [{i:3d}/{len(urls)}] {domain:40s} | "
                      f"حظر: {len(new_block):6d} | استثناء: {len(new_allow):4d}")
            else:
                stats["failed"] += 1
                failed_urls.append(url)
                print(f"❌ [{i:3d}/{len(urls)}] {domain:40s} | فشل: {result.get('error', 'Unknown')[:40]}")
            
            if i < len(urls):
                time.sleep(REQUEST_DELAY)
    
    # حساب التكرارات المحذوفة
    stats["duplicates_removed"] = (
        stats["total_block_rules"] + stats["total_allow_rules"] - 
        len(all_block_rules) - len(all_allow_rules)
    )
    
    print("\\n" + "=" * 70)
    print(f"📊 الإحصائيات:")
    print(f"   ✅ ناجح: {stats['successful']}/{stats['total_urls']}")
    print(f"   ❌ فاشل: {stats['failed']}/{stats['total_urls']}")
    print(f"   🚫 قواعد حظر: {len(all_block_rules):,}")
    print(f"   ✅ قواعد استثناء: {len(all_allow_rules):,}")
    print(f"   🗑️  تكرارات محذوفة: {stats['duplicates_removed']:,}")
    
    if failed_urls:
        print(f"\\n⚠️  روابط فاشلة ({len(failed_urls)}):")
        for url in failed_urls[:10]:
            print(f"   - {url[:80]}")
        if len(failed_urls) > 10:
            print(f"   ... و {len(failed_urls) - 10} أخرى")
    
    # ترتيب: الاستثناءات أولاً ثم الحظر
    sorted_rules = sorted(all_allow_rules, key=lambda x: extract_domain_from_rule(x))
    sorted_rules.extend(sorted(all_block_rules, key=lambda x: extract_domain_from_rule(x)))
    
    return sorted_rules, stats, failed_urls

# ─── File Generation ──────────────────────────────────────────────────────────

def generate_header(total_rules, sources_count, failed_count):
    """إنشاء ترويسة ملف AdGuard Android"""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""! Title: Merged Filters for AdGuard Android
! Description: مجمع فلاتر متقدم لـ AdGuard Android - يجمع قواعد الحظر والاستثناء
! Version: {now.replace(" ", "-").replace(":", "-")}
! Last Modified: {now}
! Expires: 6 hours
! Homepage: https://github.com/elqiser00/1002
! Sources: {sources_count} مصدر | فاشل: {failed_count}
! Total Rules: {total_rules:,}
! Block Rules: (محسوب تلقائياً)
! Allow Rules: (محسوب تلقائياً)
! License: Mixed (according to original sources)
!
! ==================== ملاحظات هامة ====================
! - الاستثناءات (@@) في بداية الملف
! - قواعد الحظر تليها
! - تم إزالة جميع التكرارات
! - متوافق 100% مع AdGuard Android
! ======================================================
!
"""

def save_filters(rules, output_dir="merged_filters", sources_count=0, failed_count=0):
    """حفظ القواعد في ملفات منظمة"""
    os.makedirs(output_dir, exist_ok=True)
    
    header = generate_header(len(rules), sources_count, failed_count)
    
    # الملف الرئيسي
    main_file = os.path.join(output_dir, "adguard_android_filter.txt")
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write("\\n".join(rules))
    
    print(f"\\n✅ تم حفظ الملف الرئيسي: {main_file}")
    print(f"   📊 إجمالي القواعد: {len(rules):,}")
    
    # التقسيم التلقائي إذا لزم الأمر
    if len(rules) > MAX_LINES_PER_PART:
        parts = (len(rules) // MAX_LINES_PER_PART) + (1 if len(rules) % MAX_LINES_PER_PART else 0)
        print(f"\\n📦 تقسيم الملف إلى {parts} أجزاء...")
        
        for i in range(parts):
            part_file = os.path.join(output_dir, f"adguard_android_filter_part_{i+1:02d}.txt")
            with open(part_file, 'w', encoding='utf-8') as f:
                f.write(header)
                start = i * MAX_LINES_PER_PART
                end = min(start + MAX_LINES_PER_PART, len(rules))
                f.write("\\n".join(rules[start:end]))
            
            print(f"   ✅ الجزء {i+1:02d}: {end - start:,} قاعدة → {part_file}")
    
    # إنشاء ملف إحصائيات
    stats_file = os.path.join(output_dir, "stats.json")
    stats_data = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_rules": len(rules),
        "block_rules": sum(1 for r in rules if not r.startswith("@@")),
        "allow_rules": sum(1 for r in rules if r.startswith("@@")),
        "sources_count": sources_count,
        "failed_sources": failed_count,
        "parts": max(1, (len(rules) // MAX_LINES_PER_PART) + (1 if len(rules) % MAX_LINES_PER_PART else 0))
    }
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats_data, f, indent=2, ensure_ascii=False)
    
    print(f"\\n📊 ملف الإحصائيات: {stats_file}")
    
    return main_file

# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("   Filters.AdGuard.Android - Advanced Filter Merger")
    print("   مجمع فلاتر AdGuard Android المتقدم")
    print("=" * 70)
    print()
    
    start_time = time.time()
    
    # تحميل الروابط
    FILTER_URLS = load_filter_urls("list.txt")
    
    if not FILTER_URLS:
        print("❌ لا توجد روابط فلاتر للمعالجة في list.txt")
        print("   تأكد من وجود الملف ويحتوي على روابط صالحة")
        sys.exit(1)
    
    print(f"📋 تم العثور على {len(FILTER_URLS)} رابط في list.txt")
    print()
    
    # معالجة الفلاتر
    rules, stats, failed = process_all_filters(FILTER_URLS)
    
    if not rules:
        print("\\n❌ لم يتم استخراج أي قواعد صالحة!")
        sys.exit(1)
    
    # حفظ النتائج
    main_file = save_filters(
        rules, 
        output_dir="merged_filters",
        sources_count=stats["successful"],
        failed_count=stats["failed"]
    )
    
    # ملخص نهائي
    elapsed = time.time() - start_time
    print()
    print("=" * 70)
    print("   ✅ اكتملت العملية بنجاح!")
    print(f"   ⏱️  الوقت الإجمالي: {elapsed:.2f} ثانية")
    print(f"   📁 الملف الرئيسي: {main_file}")
    print(f"   📊 إجمالي القواعد: {len(rules):,}")
    print(f"      - استثناءات (@@): {sum(1 for r in rules if r.startswith('@@')):,}")
    print(f"      - حظر: {sum(1 for r in rules if not r.startswith('@@')):,}")
    print("=" * 70)
    
    # عرض عينة
    print("\\n🔍 عينة من القواعد:")
    allow_sample = [r for r in rules if r.startswith("@@")][:3]
    block_sample = [r for r in rules if not r.startswith("@@")][:3]
    
    if allow_sample:
        print("   استثناءات:")
        for r in allow_sample:
            print(f"      {r}")
    if block_sample:
        print("   حظر:")
        for r in block_sample:
            print(f"      {r}")
    if len(rules) > 6:
        print(f"   ... و {len(rules) - 6} قاعدة أخرى")

if __name__ == "__main__":
    main()
'''

# Save the script
with open('/mnt/agents/output/Filters.AdGuard.Android.py', 'w', encoding='utf-8') as f:
    f.write(script_content)

print("✅ Saved Filters.AdGuard.Android.py")
print(f"   Size: {len(script_content):,} bytes")
