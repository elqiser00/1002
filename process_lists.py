import os
import re
import requests
from urllib.parse import urlparse
from collections import defaultdict

# اسم ملف الإدخال الذي يحتوي على روابط الفلاتر
INPUT_FILE = "list.txt"
# اسم ملف الإخراج النهائي بتنسيق dnsmasq
OUTPUT_FILE = "dnsmasq_blocklist.conf"

def read_filter_urls(filepath):
    """يقرأ قائمة روابط الفلاتر من ملف الإدخال."""
    with open(filepath, 'r', encoding='utf-8') as f:
        # تجاهل الأسطر الفارغة والتعليقات
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    return urls

def download_content(url):
    """يحاول تنزيل محتوى الرابط، ويعيد None في حال الفشل."""
    try:
        # استخدام مهلة زمنية لتجنب التعليق
        response = requests.get(url, timeout=30)
        response.raise_for_status() # التحقق من أن الطلب نجح (كود 200)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"خطأ في تنزيل {url}: {e}")
        return None

def extract_domains_from_line(line):
    """
    يستخرج الدومين من سطر نصي.
    يتعامل مع تنسيقات hosts (مثل 0.0.0.0 example.com) وتنسيقات النطاق العادية.
    """
    # إزالة المسافات البيضاء والتعليقات
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # محاولة استخراج الدومين من تنسيق hosts: IP DOMAIN
    parts = line.split()
    if len(parts) >= 2 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
        # التأكد من أن الجزء الثاني يشبه الدومين
        domain_candidate = parts[1].lower()
        if '.' in domain_candidate:
            return domain_candidate
    
    # إذا لم يكن تنسيق hosts، افترض أن السطر قد يكون دومينًا مباشرًا أو تعليقًا
    # إزالة أي أحرف غير صالحة من البداية والنهاية
    domain = line.split()[0].lower() if line.split() else ""
    # التحقق من صحة تنسيق الدومين الأساسي
    if re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', domain):
        return domain
    
    return None

def parse_filters(urls):
    """
    ينزّل ويحلل جميع ملفات الفلاتر، ويصنف الدومينات إلى قوائم بيضاء وسوداء.
    """
    blocklist = set()
    allowlist = set()
    
    # كلمات مفتاحية شائعة لتحديد نوع القائمة في الرابط
    ALLOW_KEYWORDS = ['allow', 'whitelist', 'white-list', 'white_list']
    BLOCK_KEYWORDS = ['block', 'blacklist', 'black-list', 'black_list', 'adblock', 'hosts']

    for url in urls:
        print(f"معالجة: {url}")
        content = download_content(url)
        if not content:
            continue

        # تحديد نوع القائمة بناءً على كلمات مفتاحية في الرابط
        url_lower = url.lower()
        is_allowlist_url = any(keyword in url_lower for keyword in ALLOW_KEYWORDS)
        
        for line in content.splitlines():
            domain = extract_domains_from_line(line)
            if domain:
                if is_allowlist_url:
                    allowlist.add(domain)
                else:
                    blocklist.add(domain)
    
    return blocklist, allowlist

def apply_priority(blocklist, allowlist):
    """
    يطبق قاعدة الأولوية: أي دومين في القائمة البيضاء يُزال من القائمة السوداء.
    """
    print(f"\nتم العثور على {len(blocklist)} دومين في القائمة السوداء و {len(allowlist)} دومين في القائمة البيضاء.")
    
    # إزالة الدومينات الموجودة في القائمة البيضاء من القائمة السوداء
    final_blocklist = blocklist - allowlist
    
    print(f"بعد تطبيق قاعدة الأولوية، عدد الدومينات في القائمة السوداء النهائية: {len(final_blocklist)}")
    return final_blocklist

def format_dnsmasq(domains, output_path):
    """
    يكتب الدومينات النهائية بتنسيق dnsmasq إلى ملف الإخراج.
    التنسيق: address=/domain.com/0.0.0.0
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# قائمة الحظر المُنشأة تلقائياً - تنسيق dnsmasq\n")
        f.write("# تاريخ الإنشاء: " + str(os.popen('date').read().strip()) + "\n\n")
        for domain in sorted(domains): # الترتيب الأبجدي لسهولة القراءة
            f.write(f"address=/{domain}/0.0.0.0\n")
    print(f"تم إنشاء ملف {output_path} بنجاح.")

def main():
    print("بدء عملية معالجة قوائم الفلاتر...")
    
    # 1. قراءة روابط الفلاتر من ملف list.txt
    filter_urls = read_filter_urls(INPUT_FILE)
    if not filter_urls:
        print(f"لم يتم العثور على روابط في ملف {INPUT_FILE}. إنهاء العملية.")
        return

    # 2. تنزيل وتحليل القوائم
    blocklist, allowlist = parse_filters(filter_urls)
    
    # 3. تطبيق قاعدة الأولوية (القائمة البيضاء تتغلب على السوداء)
    final_blocklist = apply_priority(blocklist, allowlist)
    
    # 4. كتابة النتيجة النهائية بتنسيق dnsmasq
    format_dnsmasq(final_blocklist, OUTPUT_FILE)
    
    print("اكتملت العملية بنجاح.")

if __name__ == "__main__":
    main()
