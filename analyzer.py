import re
import json
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

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

def check_domain_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "domain": domain,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "harmless": stats["harmless"]
        }
    else:
        return {"domain": domain, "error": response.status_code}

def check_ip_abuse(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        return {
            "ip": ip,
            "abuse_score": data["data"]["abuseConfidenceScore"],
            "country": data["data"]["countryCode"]
        }
    else:
        return {"ip": ip, "error": "API request failed"}

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

            url_results = {}
            for url in iocs['urls']:
                print(f"  Checking URL: {url}")
                url_results[url] = check_domain_virustotal(url)
                time.sleep(2)

            ip_results = {}
            for ip in iocs['ips']:
                print(f"  Checking IP:  {ip}")
                ip_results[ip] = check_ip_abuse(ip)
                time.sleep(2)

if __name__ == "__main__":
    main()