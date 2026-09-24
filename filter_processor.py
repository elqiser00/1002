import os
import re
import gzip
import zipfile
import requests
import io
from datetime import datetime

SESSION = requests.Session()

MAX_FILE_SIZE_MB = 90
OUTPUT_DIR = "zero"
INPUT_FILE = "list.txt"

# متغيرات الإحصائيات العامة
stats = {
    'total_sources': 0,
    'successful_sources': 0,
    'total_raw_lines': 0,
    'raw_blocked': 0,
    'raw_allowed': 0,
    'ignored_lines': 0,
    'final_unique': 0,
    'removed_conflicts': 0,
    'files_created': []
}

def normalize_url(url):
    url = url.strip()
    if 'github.com' in url and '/raw/refs/heads/' in url:
        url = url.replace('/raw/refs/heads/', '/raw/')
    if 'codeberg.org' in url and '/src/branch/' in url:
        url = url.replace('/src/branch/', '/raw/branch/')
    return url

def download_content(url):
    url = normalize_url(url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/plain, */*;q=0.1',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    try:
        response = SESSION.get(url, headers=headers, timeout=30, allow_redirects=True)
        if response.status_code == 403 and not url.endswith('.txt'):
            response = SESSION.get(url + ".txt", headers=headers, timeout=30)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '')
        raw_data = response.content
        
        if 'gzip' in content_type or url.endswith('.gz'):
            try: return gzip.decompress(raw_data).decode('utf-8', errors='ignore')
            except: pass
        
        if 'zip' in content_type or url.endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_data)) as z:
                    return "\n".join([z.read(n).decode('utf-8', errors='ignore') for n in z.namelist() if not n.endswith('/')])
            except: pass
                
        return raw_data.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"⚠️ Error ({type(e).__name__}) for: {url}")
        return ""

def extract_domain(line):
    line = line.strip()
    if not line or line.startswith(('#', '!', '[')):
        stats['ignored_lines'] += 1
        return None, None
    if re.search(r'[/\*\?\[\]\(\)\{\}\\]', line):
        stats['ignored_lines'] += 1
        return None, None

    is_allowed = False
    clean_line = line
    if line.startswith('@@'):
        is_allowed = True
        clean_line = line[2:]
    
    if '$' in clean_line:
        clean_line = clean_line.split('$')[0]
    
    for pattern in [r'^\|\|', r'\^$', r'\^', r'^0\.0\.0\.0\s+', r'^127\.0\.0\.1\s+', r'^::1\s+', r'^255\.255\.255\.255\s+']:
        clean_line = re.sub(pattern, '', clean_line, flags=re.IGNORECASE).strip()
    
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
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        urls = list(set(normalize_url(line) for line in f if line.strip() and not line.startswith('#')))
    
    stats['total_sources'] = len(urls)
    print(f"🚀 Starting processing of {stats['total_sources']} sources...\n")
    
    for url in urls:
        print(f"📥 Fetching: {url}")
        content = download_content(url)
        if not content: continue
        stats['successful_sources'] += 1
            
        lines_in_source = content.splitlines()
        stats['total_raw_lines'] += len(lines_in_source)
        
        for line in lines_in_source:
            domain, is_allowed = extract_domain(line)
            if domain:
                if is_allowed:
                    allowed_domains.add(domain)
                    stats['raw_allowed'] += 1
                else:
                    blocked_domains.add(domain)
                    stats['raw_blocked'] += 1
    
    # حساب التعارضات
    conflicts = blocked_domains.intersection(allowed_domains)
    stats['removed_conflicts'] = len(conflicts)
    unique_blocked = blocked_domains - allowed_domains
    stats['final_unique'] = len(unique_blocked)
    
    write_output_files(sorted(unique_blocked))
    print_final_statistics()

def write_output_files(domains):
    file_index = 1
    current_size = 0
    current_lines = []
    header = "! Title: Zero Filter\n! Description: Unique domains processed filter list\n"
    base_size = len(header.encode('utf-8'))
    
    print(f"\n📦 Writing {len(domains)} domains to files...")
    
    for domain in domains:
        adg_line = f"||{domain}^\n"
        line_size = len(adg_line.encode('utf-8'))
        
        if current_size + line_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            save_file(file_index, header + "".join(current_lines), len(current_lines))
            file_index += 1
            current_lines = []
            current_size = base_size
            
        current_lines.append(adg_line)
        current_size += line_size
        
    if current_lines:
        save_file(file_index, header + "".join(current_lines), len(current_lines))

def save_file(index, content, domain_count):
    filename = f"{OUTPUT_DIR}/blacklist_{index}.txt" if index > 1 else f"{OUTPUT_DIR}/blacklist.txt"
    size_mb = len(content.encode('utf-8')) / (1024 * 1024)
    stats['files_created'].append({'name': filename, 'size_mb': size_mb, 'domains': domain_count})
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"💾 Saved: {filename} ({size_mb:.2f} MB, {domain_count:,} domains)")

def print_final_statistics():
    print("\n" + "="*60)
    print("📊 FINAL STATISTICS REPORT")
    print("="*60)
    print(f"📥 Sources Processed    : {stats['successful_sources']}/{stats['total_sources']}")
    print(f"📄 Total Lines Scanned : {stats['total_raw_lines']:,}")
    print(f"🚫 Ignored (Regex/etc) : {stats['ignored_lines']:,}")
    print(f"✅ Raw Blocked Domains : {stats['raw_blocked']:,}")
    print(f"🟢 Raw Allowed Domains : {stats['raw_allowed']:,}")
    print(f"⚔️  Conflicts Removed  : {stats['removed_conflicts']:,}")
    print(f"🎯 Final Unique Domains: {stats['final_unique']:,}")
    print("-" * 60)
    print("📁 FILE BREAKDOWN:")
    for file in stats['files_created']:
        print(f"   - {file['name']:25} | {file['size_mb']:6.2f} MB | {file['domains']:>8,} domains")
    print("="*60)
    print(f"✅ Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

if __name__ == "__main__":
    process_filters()
