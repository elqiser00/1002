import os
import re
import gzip
import zipfile
import requests
import io
from urllib.parse import urlparse

# إعدادات الجلسة لتجاوز خطأ 403
SESSION = requests.Session()
SESSION.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
})

MAX_FILE_SIZE_MB = 90
OUTPUT_DIR = "zero"
INPUT_FILE = "list.txt"

def download_content(url):
    """تحميل المحتوى مع معالجة الضغط والروابط المختلفة"""
    try:
        response = SESSION.get(url.strip(), timeout=30)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '')
        raw_data = response.content
        
        # فك ضغط GZIP
        if 'gzip' in content_type or url.endswith('.gz'):
            try:
                return gzip.decompress(raw_data).decode('utf-8', errors='ignore')
            except Exception:
                pass
        
        # فك ضغط ZIP
        if 'zip' in content_type or url.endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_data)) as z:
                    texts = []
                    for name in z.namelist():
                        if not name.endswith('/'):
                            texts.append(z.read(name).decode('utf-8', errors='ignore'))
                    return "\n".join(texts)
            except Exception:
                pass
                
        return raw_data.decode('utf-8', errors='ignore')
        
    except Exception as e:
        print(f"⚠️ Error processing {url}: {e}")
        return ""

def extract_domain(line):
    """استخراج الدومين النظيف من سطر الفلتر"""
    line = line.strip()
    
    # تجاهل التعليقات والريجيكس والأسطر الفارغة
    if not line or line.startswith(('#', '!', '[')) or '/' in line and '*' in line:
        return None, None
    
    is_allowed = False
    clean_line = line
    
    # تحديد نوع الفلتر
    if line.startswith('@@'):
        is_allowed = True
        clean_line = line[2:]
    
    # إزالة الخيارات مثل $important, $third-party وغيرها
    if '$' in clean_line:
        clean_line = clean_line.split('$')[0]
    
    # تنظيف بادئات AdBlock و Hosts
    patterns_to_remove = [
        r'^\|\|', r'^\^$', r'^0\.0\.0\.0\s+', r'^127\.0\.0\.1\s+', 
        r'^::1\s+', r'^255\.255\.255\.255\s+', r'^fe00::0\s+', r'^ff00::0\s+'
    ]
    
    for pattern in patterns_to_remove:
        clean_line = re.sub(pattern, '', clean_line, flags=re.IGNORECASE).strip()
    
    # التحقق من أنه دومين صالح (يحتوي على نقطة ولا يحتوي على رموز غير مسموحة)
    if '.' in clean_line and not re.search(r'[\/\*\?\[\]\(\)\{\}\\]', clean_line):
        # إزالة أي trailing dots أو whitespace
        domain = clean_line.rstrip('.')
        return domain.lower(), is_allowed
        
    return None, None

def process_filters():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ {INPUT_FILE} not found!")
        return
        
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    blocked_domains = set()
    allowed_domains = set()
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"🚀 Starting processing of {len(urls)} sources...")
    
    for url in urls:
        print(f"📥 Fetching: {url}")
        content = download_content(url)
        if not content:
            continue
            
        lines = content.splitlines()
        for line in lines:
            domain, is_allowed = extract_domain(line)
            if domain:
                if is_allowed:
                    allowed_domains.add(domain)
                else:
                    blocked_domains.add(domain)
    
    # المنطق المطلوب: إذا وجد الدومين في المسموح والمحظور يتم حذفهما معاً
    unique_blocked = blocked_domains - allowed_domains
    
    print(f"✅ Total unique blocked domains after conflict resolution: {len(unique_blocked)}")
    
    # تقسيم الملفات حسب الحجم
    write_output_files(sorted(unique_blocked))

def write_output_files(domains):
    file_index = 1
    current_size = 0
    current_lines = []
    
    # رأس ثابت لملفات AdGuard
    header = "! Title: Zero Filter\n! Description: Unique domains processed filter list\n"
    base_size = len(header.encode('utf-8'))
    
    for domain in domains:
        # صيغة AdGuard المطلوبة
        adg_line = f"||{domain}^\n"
        line_size = len(adg_line.encode('utf-8'))
        
        if current_size + line_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            save_file(file_index, header + "".join(current_lines))
            file_index += 1
            current_lines = []
            current_size = base_size
            
        current_lines.append(adg_line)
        current_size += line_size
        
    if current_lines:
        save_file(file_index, header + "".join(current_lines))

def save_file(index, content):
    filename = f"{OUTPUT_DIR}/blacklist_{index}.txt" if index > 1 else f"{OUTPUT_DIR}/blacklist.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"💾 Saved: {filename}")

if __name__ == "__main__":
    process_filters()
