import re
import json
import os
from dotenv import load_dotenv

load_dotenv()

def read_email(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def normalize_text(text):
    text = text.lower()

    replacements = {
        '[at]': '@',
        '(at)': '@',
        ' at ': '@',
        '[dot]': '.',
        '(dot)': '.',
        ' dot ': '.',
        ' @ ': '@',
        ' . ': '.',
    }

    for k, v in replacements.items():
        text = text.replace(k, v)

    return text

def extract_iocs(text):
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = list(set([
        re.sub(r'^https?://', '', url).split('/')[0]
        for url in urls
    ]))
    emails = re.findall(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    text
)
    return {
        "urls": list(set(urls)),
        "ips": list(set(ips)),
        "domains": domains,
        "emails": list(set(emails))
    }

def main():
    samples_dir = 'samples'
    
    for filename in os.listdir(samples_dir):
        if filename.endswith('.txt') or filename.endswith('.eml'):
            filepath = os.path.join(samples_dir, filename)
            print(f"\n--- Analyzing: {filename} ---")
            
            text = read_email(filepath)
            text = normalize_text(text)
            iocs = extract_iocs(text)
            
            print(f"URLs found:    {len(iocs['urls'])}")
            print(f"IPs found:     {len(iocs['ips'])}")
            print(f"Domains found: {len(iocs['domains'])}")
            print(f"Emails found:  {len(iocs['emails'])}")
            print(json.dumps(iocs, indent=2))

if __name__ == "__main__":
    main()