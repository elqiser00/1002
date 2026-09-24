import os
import re
import gzip
import zipfile
import requests
import io

SESSION = requests.Session()

MAX_FILE_SIZE_MB = 90
OUTPUT_DIR = "zero"
INPUT_FILE = "list.txt"

def download_content(url):
    """تحميل المحتوى مع معالجة خاصة لـ Codeberg والملفات المضغوطة"""
    url = url.strip()
    
    # تحويل روابط Codeberg/Gitea إلى صيغة raw مباشرة
    if 'codeberg.org' in url and '/raw/branch/' not in url:
        url = url.replace('/src/branch/', '/raw/branch/')
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/plain, */*;q=0.1',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    }
    
    try:
        response = SESSION.get(url, headers=headers, timeout=30, allow_redirects=True)
        
        # إعادة المحاولة بإضافة .txt إذا تم الحظر
        if response.status_code == 403 and not url.endswith('.txt'):
            print(f"   🔄 Retrying with .txt suffix for: {url}")
            response = SESSION.get(url + ".txt", headers=headers, timeout=30)
            
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
        
    except requests.exceptions.HTTPError as e:
        print(f"⚠️ Access Denied ({e.response.status_code}) for: {url}")
    except Exception as e:
        print(f"⚠️ Error processing {url}: {type(e).__name__}: {str(e)[:100]}")
        
    return ""

def extract_domain(line):
    """استخراج الدومين النظيف وحذف Regex والتعليقات والرؤوس نهائياً"""
    line = line.strip()
    
    # حذف فوري لأي سطر يحتوي على Regex أو تعليقات أو رؤوس
    if not line or line.startswith(('#', '!', '[')):
        return None, None
    
    # حذف أي سطر يحتوي على رموز Regex أو مسارات URL
    if re.search(r'[/\*\?\[\]\(\)\{\}\|\\]', line):
        return None, None
    
    is_allowed = False
    clean_line = line
    
    # تحديد نوع الفلتر
    if line.startswith('@@'):
        is_allowed = True
        clean_line = line[2:]
    
    # إزالة خيارات AdGuard مثل $important
    if '$' in clean_line:
        clean_line = clean_line.split('$')[0]
    
    # تنظيف بادئات Hosts و AdBlock
    patterns_to_remove = [
        r'^\|\|', r'\^$', r'^0\.0\.0\.0\s+', r'^127\.0\.0\.1\s+', 
        r'^::1\s+', r'^255\.255\.255\.255\s+', r'^fe00::0\s+', r'^ff00::0\s+'
    ]
    
    for pattern in patterns_to_remove:
        clean_line = re.sub(pattern, '', clean_line, flags=re.IGNORECASE).strip()
    
    # التحقق النهائي من أنه دومين نقي فقط
    if '.' in clean_line and re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', clean_line):
        return clean_line.lower(), is_allowed
        
    return None, None

def process_filters():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ {INPUT_FILE} not found!")
        return
        
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    blocked_domains = set()
    allowed_domains = set()
    
    # إزالة الروابط المكررة من قائمة المصادر
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        urls = list(set(line.strip() for line in f if line.strip() and not line.startswith('#')))
    
    print(f"🚀 Starting processing of {len(urls)} unique sources...")
    
    for url in urls:
        print(f"📥 Fetching: {url}")
        content = download_content(url)
        if not content:
            continue
            
        for line in content.splitlines():
            domain, is_allowed = extract_domain(line)
            if domain:
                if is_allowed:
                    allowed_domains.add(domain)
                else:
                    blocked_domains.add(domain)
    
    # حذف الدومينات التي تظهر في المسموح والمحظور معاً
    unique_blocked = blocked_domains - allowed_domains
    
    print(f"✅ Total unique blocked domains after deduplication & conflict resolution: {len(unique_blocked)}")
    write_output_files(sorted(unique_blocked))

def write_output_files(domains):
    file_index = 1
    current_size = 0
    current_lines = []
    
    header = "! Title: Zero Filter\n! Description: Unique domains processed filter list\n"
    base_size = len(header.encode('utf-8'))
    
    for domain in domains:
        adg_line = f"||{domain}^\n"
        line_size = len(adg_line.encode('utf-8'))
        
        # تقسيم الملف عند تجاوز 90 ميجابايت
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
