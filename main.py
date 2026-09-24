import os
import re
import requests
import gzip
import zipfile
import io
from urllib.parse import urlparse

# إعدادات
LIST_FILE_URL = "https://raw.githubusercontent.com/elqiser00/1002/main/list.txt" # تأكد أن الرابط Raw
OUTPUT_DIR = "zero"
MAX_SIZE_MB = 90
CHUNK_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024

def download_content(url):
    """تحميل المحتوى مع معالجة الأخطاء والضغط"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # تجاهل تحقق SSL أحياناً قد يسبب مشاكل، لكن نستخدم verify=True للأمان إلا إذا فشل
        try:
            response = requests.get(url, headers=headers, timeout=30, verify=True)
        except requests.exceptions.SSLError:
            print(f"SSL Error for {url}, retrying without verification...")
            response = requests.get(url, headers=headers, timeout=30, verify=False)
        
        response.raise_for_status()
        
        # التعامل مع الملفات المضغوطة تلقائياً بناءً على الهيدر أو الامتداد
        content = response.content
        
        if url.endswith('.gz') or 'gzip' in response.headers.get('Content-Encoding', ''):
            try:
                content = gzip.decompress(content).decode('utf-8', errors='ignore')
            except:
                content = content.decode('utf-8', errors='ignore')
        elif url.endswith('.zip'):
            try:
                z = zipfile.ZipFile(io.BytesIO(content))
                # نفترض أن الملف الأول داخل الزيب هو الليست
                filename = z.namelist()[0]
                content = z.read(filename).decode('utf-8', errors='ignore')
            except:
                content = content.decode('utf-8', errors='ignore')
        else:
            content = content.decode('utf-8', errors='ignore')
            
        return content
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return ""

def normalize_rule(line):
    """
    تنظيف السطر وإرجاع (domain, type)
    type: 'block' or 'allow' or None (invalid)
    """
    line = line.strip()
    
    # تجاهل الأسطر الفارغة والتعليقات
    if not line or line.startswith('!') or line.startswith('#'):
        return None, None

    # استخراج الدومين الأساسي
    # نمط الحظر: ||domain^
    # نمط السماح: @@||domain^
    
    is_allow = False
    clean_line = line
    
    if clean_line.startswith('@@'):
        is_allow = True
        clean_line = clean_line[2:] # إزالة @@
    
    # إزالة || من البداية و ^ من النهاية وأي خيارات أخرى مثل $important, $third-party الخ
    # الهدف هو الوصول للدومين الصافي
    if clean_line.startswith('||'):
        clean_line = clean_line[2:]
    
    # إزالة أي شيء بعد ^ أو $
    domain_part = re.split(r'[\^\$]', clean_line)[0]
    
    # تنظيف إضافي للدومين (إزالة http/https/www إذا وجدت بشكل خاطئ في المصدر)
    # لكن في AdGuard ||domain^ يكفي، لذا سنحتفظ بالدومين كما هو بعد التنظيف
    
    if not domain_part:
        return None, None
        
    return domain_part.lower(), 'allow' if is_allow else 'block'

def process_lists():
    # 1. قراءة list.txt
    print("Downloading main list.txt...")
    main_list_content = download_content(LIST_FILE_URL)
    if not main_list_content:
        raise Exception("Could not download list.txt")

    source_urls = [line.strip() for line in main_list_content.splitlines() if line.strip() and not line.strip().startswith('#')]
    
    all_rules = {} # key: domain, value: 'block' or 'allow'
    
    print(f"Found {len(source_urls)} sources to process.")

    # 2. معالجة كل مصدر
    for url in source_urls:
        print(f"Processing: {url}")
        content = download_content(url)
        lines = content.splitlines()
        
        for line in lines:
            domain, rule_type = normalize_rule(line)
            if domain:
                # منطق التصادم المباشر أثناء الجمع
                if domain in all_rules:
                    existing_type = all_rules[domain]
                    if existing_type != rule_type:
                        # تضارب: واحد حظر والآخر سمح -> احذف الاثنين
                        del all_rules[domain]
                    # لو نفس النوع، لا تفعل شيئاً (تجنب التكرار)
                else:
                    all_rules[domain] = rule_type

    print(f"Total unique domains after collision removal: {len(all_rules)}")

    # 3. تجهيز المخرجات
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # تحويل الديكت لقائمة سطور
    final_lines = []
    for domain, rule_type in all_rules.items():
        if rule_type == 'block':
            # ||ad.doubleclick.net^$important
            final_lines.append(f"||{domain}^$important")
        else:
            # @@||ad.doubleclick.net^$important
            final_lines.append(f"@@||{domain}^$important")

    # ترتيب الأبجدي لتسهيل القراءة والمقارنة المستقبلية
    final_lines.sort()

    # 4. التقسيم حسب الحجم (Chunking)
    total_size = sum(len(line.encode('utf-8')) + 1 for line in final_lines) # +1 for newline
    print(f"Total estimated size: {total_size / (1024*1024):.2f} MB")

    if total_size <= CHUNK_SIZE_BYTES:
        # ملف واحد
        output_path = os.path.join(OUTPUT_DIR, "filter_list.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines))
        print(f"Saved to {output_path}")
    else:
        # تقسيم لملفات
        chunk_index = 1
        current_chunk = []
        current_size = 0
        
        for line in final_lines:
            line_bytes = len(line.encode('utf-8')) + 1
            if current_size + line_bytes > CHUNK_SIZE_BYTES and current_chunk:
                # حفظ الملف الحالي وبدء جديد
                output_path = os.path.join(OUTPUT_DIR, f"filter_list_{chunk_index}.txt")
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_chunk))
                print(f"Saved chunk {chunk_index} to {output_path}")
                
                current_chunk = []
                current_size = 0
                chunk_index += 1
            
            current_chunk.append(line)
            current_size += line_bytes
            
        # حفظ آخر جزء
        if current_chunk:
            output_path = os.path.join(OUTPUT_DIR, f"filter_list_{chunk_index}.txt")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(current_chunk))
            print(f"Saved final chunk {chunk_index} to {output_path}")

if __name__ == "__main__":
    process_lists()
