import argparse
import re
import os
import time
import ipaddress
from functools import lru_cache
from typing import Set
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Rate limit: VT allows 4 requests/min = 15s between calls
VT_DELAY = 15
ABUSE_DELAY = 1

REQUEST_TIMEOUT_S = 10
RETRY_ATTEMPTS = 2
RETRY_SLEEP_S = 2

MIN_ENGINES_MALICIOUS = 3

TRUSTED_DOMAINS = {
    "outlook.com", "microsoft.com", "office.com", "live.com",
    "google.com", "gmail.com", "apple.com", "paypal.com",
    "amazon.com", "yahoo.com",
}

FILE_EXTS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx",
    "xls", "xlsx", "html", "htm",
}

LEET = str.maketrans("0134", "olea")


def is_trusted(domain):
    return any(domain == trusted or domain.endswith("." + trusted) for trusted in TRUSTED_DOMAINS)


def has_no_data(result):
    return (
        result.get("malicious", 0)
        + result.get("suspicious", 0)
        + result.get("harmless", 0)
        + result.get("undetected", 0)
    ) == 0


def read_email(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def normalize_text(text):
    text = text.lower()
    replacements = {
        '[at]': '@',
        '(at)': '@',
        '[dot]': '.',
        '(dot)': '.',
        '[.]': '.',
        '(.)': '.',
        '[:]': ':',
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    text = re.sub(r'\bhxxp', 'http', text)
    return text

def _get_with_retry(url: str, *, headers=None, params=None) -> requests.Response:
    last_err: Exception | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT_S)
        except requests.RequestException as e:
            last_err = e
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_SLEEP_S)
    assert last_err is not None
    raise last_err

def _is_valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4
    except ValueError:
        return False

def is_internal_ip(value: str) -> bool:
    """
    Treat non-global addresses as internal/unroutable for enrichment purposes.
    This includes RFC1918, loopback, link-local, multicast, reserved, etc.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not ip.is_global

def _extract_domains_from_text(text: str) -> Set[str]:
    # Basic "domain.tld" extractor for raw text (not only URLs).
    # This intentionally avoids matching IP-like strings.
    pattern = re.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b',
        re.IGNORECASE,
    )
    candidates = set(m.group(0).strip(".").lower() for m in pattern.finditer(text))
    out: Set[str] = set()
    for d in candidates:
        if not d:
            continue
        if _is_valid_ipv4(d):
            continue
        if d.rsplit(".", 1)[-1] in FILE_EXTS:
            continue
        out.add(d)
    return out

def _extract_urls(text: str) -> list[str]:
    # After normalize_text, common defanged forms (hxxp, [.] etc.) should be repaired.
    # This extracts http(s) URLs and also "www." links.
    urls: set[str] = set()
    for m in re.finditer(r'\bhttps?://[^\s<>"\']+', text, re.IGNORECASE):
        urls.add(m.group(0).rstrip(').,;\'"'))
    for m in re.finditer(r'\bwww\.[^\s<>"\']+', text, re.IGNORECASE):
        urls.add("http://" + m.group(0).rstrip(').,;\'"'))
    return sorted(urls)

def extract_iocs(text):
    urls = _extract_urls(text)
    
    raw_domains = []
    for url in urls:
        netloc = urlparse(url).netloc
        # Strip port number if present
        netloc = netloc.split(':')[0]
        raw_domains.append(netloc)

    # Filter out anything that is actually an IP (properly)
    domains_from_urls = set()
    for d in raw_domains:
        if not d:
            continue
        if _is_valid_ipv4(d):
            continue
        domains_from_urls.add(d.lower())

    ips_raw = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    ips = []
    for ip in ips_raw:
        if _is_valid_ipv4(ip):
            # normalize (e.g. leading zeros) via ipaddress
            ips.append(str(ipaddress.ip_address(ip)))

    emails = re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text)

    domains_from_text = _extract_domains_from_text(text)
    domains_from_emails = set()
    for e in emails:
        parts = e.split("@", 1)
        if len(parts) == 2 and parts[1]:
            domains_from_emails.add(parts[1].lower().strip("."))

    domains = sorted(set().union(domains_from_urls, domains_from_text, domains_from_emails))

    return {
        "urls": list(set(urls)),
        "ips": sorted(set(ips)),
        "domains": domains,
        "emails": list(set(emails))
    }

@lru_cache(maxsize=2048)
def check_domain_virustotal(domain):
    try:
        if not VT_API_KEY:
            return {"error": "Missing VIRUSTOTAL_API_KEY"}
        if not domain or "." not in domain:
            return {"error": "Invalid domain"}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        response = _get_with_retry(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "undetected": stats["undetected"],
                "harmless": stats["harmless"]
            }
        elif response.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

@lru_cache(maxsize=4096)
def check_ip_abuseipdb(ip):
    try:
        if not ABUSE_API_KEY:
            return {"error": "Missing ABUSEIPDB_API_KEY"}
        if not _is_valid_ipv4(ip):
            return {"error": "Invalid IPv4"}
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = _get_with_retry(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
        )
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "abuse_score": data["abuseConfidenceScore"],
                "total_reports": data["totalReports"],
                "country": data["countryCode"],
                "isp": data.get("isp", "N/A")
            }
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def verdict_domain(domain, result):
    if "error" in result:
        return "⚠️  ERROR"
    if is_trusted(domain):
        return "🟢 TRUSTED (known legitimate)"
    if has_no_data(result):
        return "⚪ UNKNOWN (no reputation data)"
    if result["malicious"] >= MIN_ENGINES_MALICIOUS:
        return "🔴 MALICIOUS"
    if result["malicious"] > 0 or result["suspicious"] > 0:
        return "🟡 SUSPICIOUS"
    return "🟢 CLEAN"

def verdict_ip(result):
    if "error" in result:
        return "⚠️  ERROR"
    score = result.get("abuse_score", 0)
    if score > 25:
        return "🔴 MALICIOUS"
    if score > 0:
        return "🟡 SUSPICIOUS"
    return "🟢 CLEAN"

def _heuristic_assessment(text: str, iocs, domain_results, ip_results):
    score = 0
    reasons: list[str] = []
    actions: list[str] = []

    # Strong signals from enrichment
    for d, r in domain_results.items():
        if "error" in r or is_trusted(d):
            continue
        malicious = r.get("malicious", 0)
        suspicious = r.get("suspicious", 0)
        if malicious >= MIN_ENGINES_MALICIOUS:
            score += 80
            reasons.append(f"Domain flagged malicious by {malicious} VirusTotal engines: {d}")
        elif malicious > 0 or suspicious > 0:
            score += 35
            reasons.append(f"Domain flagged suspicious by VirusTotal: {d}")
        elif has_no_data(r):
            score += 10
            reasons.append(f"Domain has no reputation data on VirusTotal (possibly new): {d}")

    for ip, r in ip_results.items():
        if r.get("skipped") or "error" in r:
            continue
        abuse = int(r.get("abuse_score", 0) or 0)
        if abuse > 25:
            score += 70
            reasons.append(f"IP has high abuse score ({abuse}%) on AbuseIPDB: {ip}")
        elif abuse > 0:
            score += 20
            reasons.append(f"IP has non-zero abuse score ({abuse}%) on AbuseIPDB: {ip}")

    # Content heuristics
    keyword_hits = []
    keywords = [
        "verify", "password", "login", "sign in", "account", "suspended", "suspend",
        "urgent", "immediately", "action required", "update", "security", "invoice",
        "payment", "refund", "wire", "bank", "mfa", "2fa", "one-time", "otp",
    ]
    for k in keywords:
        if k in text:
            keyword_hits.append(k)
    if keyword_hits:
        score += min(25, 5 * len(set(keyword_hits)))
        reasons.append(f"Social-engineering language present ({len(set(keyword_hits))} keyword hits)")

    # Brand-looking domains (simple heuristic)
    suspicious_brands = ["paypal", "microsoft", "office", "outlook", "apple", "google", "dhl", "fedex", "amazon", "bank"]
    for d in iocs.get("domains", []):
        if is_trusted(d):
            continue
        d_norm = d.translate(LEET)
        for b in suspicious_brands:
            if b in d_norm:
                score += 10
                reasons.append(f"Possible brand-impersonation domain: {d}")
                break

    # Volume heuristics
    if len(iocs.get("urls", [])) >= 3:
        score += 10
        reasons.append("Multiple URLs present")

    score = min(score, 100)

    # Verdict buckets
    if score >= 60:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "MEDIUM RISK"
    elif score >= 15:
        verdict = "LOW RISK"
    else:
        verdict = "UNLIKELY (LOW SIGNAL)"

    if verdict in {"HIGH RISK", "MEDIUM RISK"}:
        actions.extend([
            "Do not click links or open attachments",
            "Quarantine the message and report as phishing",
            "Block listed domains/IPs in email/web controls (if confirmed malicious)",
        ])
    else:
        actions.extend([
            "If unsure, validate sender via an out-of-band channel",
            "Treat links as untrusted; open only in a safe sandbox if needed",
        ])

    return {"score": score, "verdict": verdict, "reasons": reasons[:8], "actions": actions[:6]}

def generate_report(filename, text, iocs, domain_results, ip_results):
    assessment = _heuristic_assessment(text, iocs, domain_results, ip_results)
    lines = []
    lines.append("=" * 55)
    lines.append("       PHISHING ANALYSIS REPORT")
    lines.append("=" * 55)
    lines.append(f"  Sample  : {filename}")
    lines.append(f"  Verdict : {assessment['verdict']} (score: {assessment['score']})")
    lines.append(f"  URLs    : {len(iocs['urls'])}")
    lines.append(f"  Domains : {len(iocs['domains'])}")
    lines.append(f"  IPs     : {len(iocs['ips'])}")
    lines.append(f"  Emails  : {len(iocs['emails'])}")
    lines.append("=" * 55)

    lines.append("\n[ CONCLUSION ]\n")
    if assessment["reasons"]:
        lines.append("  Key signals:")
        for r in assessment["reasons"]:
            lines.append(f"  - {r}")
    else:
        lines.append("  Key signals: none (heuristics saw low signal)")
    lines.append("\n  Recommended actions:")
    for a in assessment["actions"]:
        lines.append(f"  - {a}")

    lines.append("\n[ DOMAIN ANALYSIS — VirusTotal ]\n")
    for domain, result in domain_results.items():
        lines.append(f"  Domain  : {domain}")
        lines.append(f"  Verdict : {verdict_domain(domain, result)}")
        if "error" not in result:
            lines.append(f"  Malicious  : {result['malicious']} engines")
            lines.append(f"  Suspicious : {result['suspicious']} engines")
            lines.append(f"  Harmless   : {result['harmless']} engines")
        else:
            lines.append(f"  Error   : {result['error']}")
        lines.append("")

    lines.append("[ IP ANALYSIS — AbuseIPDB ]\n")
    for ip, result in ip_results.items():
        lines.append(f"  IP      : {ip}")
        if result.get("skipped"):
            lines.append(f"  Verdict : ⚪ SKIPPED (private/internal IP)")
        else:
            lines.append(f"  Verdict : {verdict_ip(result)}")
            if "error" not in result:
                lines.append(f"  Abuse Score   : {result['abuse_score']}%")
                lines.append(f"  Total Reports : {result['total_reports']}")
                lines.append(f"  Country       : {result['country']}")
                lines.append(f"  ISP           : {result['isp']}")
            else:
                lines.append(f"  Error   : {result['error']}")
        lines.append("")

    lines.append("[ SENDER / RECIPIENT EMAILS ]\n")
    for email in iocs['emails']:
        lines.append(f"  {email}")

    return "\n".join(lines)

def analyze_file(filepath, report_path):
    filename = os.path.basename(filepath)
    print(f"\n{'='*40}")
    print(f"Analyzing: {filename}")
    print(f"{'='*40}")

    text = normalize_text(read_email(filepath))
    iocs = extract_iocs(text)

    print(f"  URLs    : {len(iocs['urls'])}")
    print(f"  Domains : {len(iocs['domains'])}")
    print(f"  IPs     : {len(iocs['ips'])}")
    print(f"  Emails  : {len(iocs['emails'])}")

    domain_results = {}
    for domain in iocs['domains']:
        print(f"\n  [VT]  Checking domain: {domain}")
        cache_before = check_domain_virustotal.cache_info()
        domain_results[domain] = check_domain_virustotal(domain)
        cache_after = check_domain_virustotal.cache_info()
        result = domain_results[domain]
        print(f"        Verdict: {verdict_domain(domain, result)}")
        if cache_after.hits == cache_before.hits:
            print(f"        Waiting {VT_DELAY}s (rate limit)...")
            time.sleep(VT_DELAY)
        else:
            print("        (cached) no wait")

    ip_results = {}
    for ip in iocs['ips']:
        if is_internal_ip(ip):
            print(f"\n  [IP]  Skipping internal/unroutable IP: {ip}")
            ip_results[ip] = {"skipped": True}
            continue
        print(f"\n  [IP]  Checking: {ip}")
        cache_before = check_ip_abuseipdb.cache_info()
        ip_results[ip] = check_ip_abuseipdb(ip)
        cache_after = check_ip_abuseipdb.cache_info()
        result = ip_results[ip]
        print(f"        Verdict: {verdict_ip(result)}")
        if cache_after.hits == cache_before.hits:
            time.sleep(ABUSE_DELAY)
        else:
            print("        (cached) no wait")

    report = generate_report(filename, text, iocs, domain_results, ip_results)
    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\n  ✅ Report saved: {report_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze phishing email samples.")
    parser.add_argument(
        "email_file",
        nargs="?",
        help="Path to one .txt or .eml file. Omit to analyze every sample in samples/.",
    )
    parser.add_argument(
        "report_path",
        nargs="?",
        help="Optional output path for the report (only valid with email_file).",
    )
    args = parser.parse_args(argv)

    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    if args.email_file:
        if not os.path.isfile(args.email_file):
            parser.error(f"input file does not exist: {args.email_file}")
        if os.path.splitext(args.email_file)[1].lower() not in {".txt", ".eml"}:
            parser.error("input file must have a .txt or .eml extension")

        default_report_name = os.path.splitext(os.path.basename(args.email_file))[0]
        if not args.report_path:
            report_path = os.path.join(
                reports_dir, f"{default_report_name}_report.txt"
            )
        elif os.path.isdir(args.report_path) or args.report_path.endswith(
            (os.sep, "/", "\\")
        ):
            report_path = os.path.join(
                args.report_path, f"{default_report_name}_report.txt"
            )
        else:
            report_path = args.report_path
        if os.path.abspath(report_path) == os.path.abspath(args.email_file):
            parser.error("report path must not overwrite the input file")
        analyze_file(args.email_file, report_path)
        return

    if args.report_path:
        parser.error("report_path can only be used when email_file is provided")

    samples_dir = "samples"
    for filename in os.listdir(samples_dir):
        if os.path.splitext(filename)[1].lower() not in {".txt", ".eml"}:
            continue
        filepath = os.path.join(samples_dir, filename)
        report_filename = f"{os.path.splitext(filename)[0]}_report.txt"
        analyze_file(filepath, os.path.join(reports_dir, report_filename))

if __name__ == "__main__":
    main()