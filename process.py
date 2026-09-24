import os
import sys
import re
import socket
import requests
import tldextract
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Configuration
LIST_FILE = 'list.txt'
OUTPUT_FOLDER = 'zero'
MAX_SIZE_BYTES = 85 * 1024 * 1024 # 85 MB

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize requests session with FULL Browser Headers to bypass 403 Forbidden
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
})

def extract_domain(rule):
    rule = rule.strip()
    if not rule or rule.startswith(('!', '[', ' ', '#')):
        return None
        
    # Ignore pure regex rules
    if rule.startswith('/') or rule.startswith('@/'):
        return None
        
    is_exception = rule.startswith('@@')
    if is_exception:
        clean_rule = rule[2:]
    else:
        clean_rule = rule
        
    # Remove element hiding rules
    if '#' in clean_rule and not clean_rule.startswith('#'):
        clean_rule = clean_rule.split('#')[0]
        
    # Handle hosts file format
    hosts_match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1|255\.255\.255\.255)\s+([^\s#]+)', clean_rule)
    if hosts_match:
        domain_str = hosts_match.group(2)
        if domain_str == 'localhost': return None
        base_rule = domain_str
    else:
        # Check domain= option
        if 'domain=' in clean_rule and (clean_rule.startswith('$') or clean_rule.startswith('*')):
            match = re.search(r'domain=([^,\$]+)', clean_rule)
            if match:
                base_rule = match.group(1).strip('~')
            else:
                base_rule = clean_rule.split('$')[0]
        else:
            base_rule = clean_rule.split('$')[0]
            
            # Remove protocols and AdBlock prefixes
            base_rule = re.sub(r'^\|?https?://', '', base_rule)
            base_rule = re.sub(r'^\|\|', '', base_rule)
            
            # Remove wildcards and regex markers
            if '*' in base_rule or '\\' in base_rule or '?' in base_rule:
                return None
                
            # Remove paths, anchors, etc.
            base_rule = base_rule.split('/')[0]
            base_rule = base_rule.split('^')[0]
            base_rule = base_rule.split(':')[0] # Remove ports
            base_rule = base_rule.split('%')[0] # Remove url encoded stuff
            
    # Clean up trailing/leading dots or hyphens
    base_rule = base_rule.strip('.-')
    
    if not base_rule:
        return None
        
    # Filter out IP addresses
    try:
        socket.inet_aton(base_rule)
        return None
    except socket.error:
        pass
        
    ext = tldextract.extract(base_rule)
    if ext.domain and ext.suffix:
        domain = f"{ext.domain}.{ext.suffix}"
        if ext.subdomain:
            domain = f"{ext.subdomain}.{domain}"
            
        # Final validation
        if '.' not in domain:
            return None
        if len(domain) > 253:
            return None
            
        return domain, is_exception
        
    return None

def process_list(url):
    blocked = set()
    accepted = set()
    try:
        print(f"Fetching: {url}")
        
        # Add referer dynamically based on the URL to bypass hotlink protection
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        referer = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        
        res = session.get(url, timeout=30, verify=False, headers={'Referer': referer})
        res.raise_for_status()
        
        # Handle content decoding safely
        if res.headers.get('Content-Encoding') == 'br':
            try:
                import brotli
                content = brotli.decompress(res.content).decode('utf-8', errors='ignore')
            except ImportError:
                content = res.content.decode('utf-8', errors='ignore')
        else:
            res.encoding = res.apparent_encoding or 'utf-8'
            content = res.text
            
        for line in content.splitlines():
            result = extract_domain(line)
            if result:
                domain, is_exception = result
                if is_exception:
                    accepted.add(domain)
                else:
                    blocked.add(domain)
    except Exception as e:
        print(f"Error processing {url}: {e}")
        
    return blocked, accepted

def main():
    if not os.path.exists(LIST_FILE):
        print(f"{LIST_FILE} not found.")
        sys.exit(1)
        
    with open(LIST_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
    all_blocked = set()
    all_accepted = set()
    
    # Use ThreadPoolExecutor for faster downloading
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_list, url): url for url in urls}
        for future in as_completed(futures):
            blocked, accepted = future.result()
            all_blocked.update(blocked)
            all_accepted.update(accepted)
            
    # Conflict resolution: 
    # لو الدومين موجود في البلوك وفي الوايت ليست، يتشالوا الاتنين عشان يفتح بشكل طبيعي
    conflicts = all_blocked.intersection(all_accepted)
    print(f"Found {len(conflicts)} conflicting domains. Removing them completely.")
    all_blocked -= conflicts
    
    # شيلنا أي دومين اتصنف كـ accepted خالص من قائمة البلوك النهائية
    all_blocked -= all_accepted
    
    print(f"Final unique blocked domains: {len(all_blocked)}")
    
    # Prepare rules (Blacklist ONLY - No @@ rules anymore)
    rules = []
    for domain in all_blocked:
        rules.append(f"||{domain}^$important")
        
    # Sort rules for consistency
    rules.sort()
    
    # Save to files
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
        
    file_idx = 1
    current_file_path = os.path.join(OUTPUT_FOLDER, f"blacklist{file_idx}.txt")
    
    with open(current_file_path, 'w', encoding='utf-8') as f:
        current_size = 0
        for rule in rules:
            line = rule + '\n'
            line_bytes = len(line.encode('utf-8'))
            if current_size + line_bytes > MAX_SIZE_BYTES and current_size > 0:
                file_idx += 1
                current_file_path = os.path.join(OUTPUT_FOLDER, f"blacklist{file_idx}.txt")
                f = open(current_file_path, 'w', encoding='utf-8')
                current_size = 0
            f.write(line)
            current_size += line_bytes
            
    print(f"Processing complete. Files saved in '{OUTPUT_FOLDER}' folder.")

if __name__ == "__main__":
    main()
