"""Passive phishing triage engine and CLI. Scores are heuristics, not probabilities."""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

from .email_parser import (MAX_INPUT_BYTES, defang, extract_iocs, is_internal_ip,
                          normalize_text, parse_email, url_host)
from .threat_intel import IntelClient
from .paths import ENV_FILE, INPUT_DIR, REPORTS_DIR

KNOWN_DOMAINS = {"outlook.com", "microsoft.com", "office.com", "live.com", "google.com",
                 "gmail.com", "apple.com", "paypal.com", "amazon.com", "yahoo.com",
                 "dhl.com", "fedex.com"}
BRANDS = {"paypal", "microsoft", "office", "outlook", "apple", "google", "dhl", "fedex", "amazon"}
LEET = str.maketrans("0134", "olea")
KEYWORDS = ("verify", "password", "login", "sign in", "account", "suspended", "urgent",
            "immediately", "action required", "invoice", "payment", "refund", "wire", "mfa", "otp")


def is_trusted(domain):
    """Known brand context only; never overrides negative reputation evidence."""
    return any(domain == d or domain.endswith("." + d) for d in KNOWN_DOMAINS)


def verdict_domain(domain, result):
    status = result.get("status", "ok")
    if status != "ok":
        return {"skipped": "NOT CHECKED", "error": "LOOKUP FAILED", "no_data": "UNKNOWN"}[status]
    if result.get("malicious", 0) >= 3:
        return "MALICIOUS REPUTATION"
    if result.get("malicious", 0) or result.get("suspicious", 0):
        return "SUSPICIOUS REPUTATION"
    return "NO DETECTIONS (not proof of safety)"


def _heuristic_assessment(text, iocs, domain_results, ip_results, headers=None, attachments=None):
    findings = []

    def add(rule, weight, summary, evidence):
        findings.append({"rule": rule, "weight": weight, "summary": summary, "evidence": evidence})

    for domain, result in domain_results.items():
        if result.get("status") != "ok":
            continue
        if result.get("malicious", 0) >= 3:
            add("domain_reputation", 80, "Domain flagged by at least three VirusTotal engines", domain)
        elif result.get("malicious", 0) or result.get("suspicious", 0):
            add("domain_reputation", 35, "Domain has suspicious reputation detections", domain)
    for ip, result in ip_results.items():
        if result.get("status") == "ok" and result.get("abuse_score", 0):
            add("ip_reputation", 70 if result["abuse_score"] > 25 else 20,
                "IP has reported abuse; may be a shared or legitimate relay", ip)
    hits = [k for k in KEYWORDS if re.search(r"\b" + re.escape(k) + r"\b", text, re.I)]
    if hits:
        add("social_language", min(25, 5 * len(hits)), "Social-engineering language", ", ".join(hits))
    lookalikes = [d for d in iocs["domains"] if not is_trusted(d)
                 and any(b in d.translate(LEET) for b in BRANDS)]
    if lookalikes:
        add("brand_lookalike", min(20, 10 * len(lookalikes)),
            "Possible brand impersonation; verify ownership", ", ".join(lookalikes))
    for url in iocs["urls"]:
        parsed = urlsplit(url)
        if parsed.username is not None:
            add("url_userinfo", 15, "URL includes user information before its real host", url)
            break
    if any(url_host(url) in iocs["ips"] for url in iocs["urls"]):
        add("ip_url", 10, "Link uses an IP address instead of a domain", "IP-based URL")
    if any("xn--" in d for d in iocs["domains"]):
        add("idn_domain", 5, "Internationalized domain; check for visual impersonation", "Punycode hostname")
    headers = headers or {}
    sender = {a.rsplit("@", 1)[-1].lower() for _, a in getaddresses(headers.get("From", [])) if "@" in a}
    reply = {a.rsplit("@", 1)[-1].lower() for _, a in getaddresses(headers.get("Reply-To", [])) if "@" in a}
    if sender and reply and sender != reply:
        add("reply_to_mismatch", 10, "From and Reply-To domains differ; legitimate services also do this",
            ", ".join(sorted(sender)) + " / " + ", ".join(sorted(reply)))
    risky = [a["filename"] for a in attachments or [] if
             Path(a["filename"]).suffix.lower() in {".exe", ".js", ".vbs", ".scr", ".lnk", ".iso", ".docm", ".xlsm"}]
    if risky:
        add("risky_attachment", 20, "Attachment type can carry executable content", ", ".join(risky))
    score = min(100, sum(f["weight"] for f in findings))
    verdict = "HIGH RISK" if score >= 60 else "MEDIUM RISK" if score >= 40 else "LOW SIGNAL"
    actions = ["Validate the sender and request through a known, separate channel.",
               "Review each indicator in context before blocking; recipients and mail relays can be legitimate."]
    if score >= 40:
        actions.insert(0, "Preserve the original message, avoid interaction, and escalate for analyst review.")
    return {"score": score, "verdict": verdict, "findings": findings, "actions": actions,
            "note": "Heuristic triage score, not a probability. Low signal and zero detections do not establish safety."}


def analyze_bytes(raw, *, filename="sample.eml", client=None):
    parsed = parse_email(raw)
    iocs = extract_iocs(parsed["text"])
    domains = {d: client.lookup("domain", d) if client else {"status": "skipped", "reason": "Offline mode"}
               for d in iocs["domains"]}
    ips = {ip: {"status": "skipped", "reason": "Non-public IP address"} if is_internal_ip(ip)
           else client.lookup("ip", ip) if client else {"status": "skipped", "reason": "Offline mode"}
           for ip in iocs["ips"]}
    results = list(domains.values()) + list(ips.values())
    checked = sum(r["status"] == "ok" for r in results)
    warnings = parsed["warnings"] + [
        "Authentication-Results headers are reported claims, not independently verified SPF/DKIM/DMARC results.",
        "Attachment contents are hashed but not executed, unpacked, or malware-scanned.",
    ]
    if checked < len(results):
        warnings.append("Reputation coverage is incomplete; unchecked or unknown indicators are not safe verdicts.")
    return {"schema_version": 1, "source": {"filename": filename,
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)},
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "mode": "enrichment_requested" if client and client.enabled else "offline",
            "iocs": iocs, "headers": parsed["headers"], "attachments": parsed["attachments"],
            "domain_results": domains, "ip_results": ips,
            "coverage": {"checked": checked, "total": len(results)},
            "assessment": _heuristic_assessment(parsed["text"], iocs, domains, ips,
                                                 parsed["headers"], parsed["attachments"]),
            "warnings": warnings}


def generate_report(result):
    assessment = result["assessment"]
    lines = ["PHISH ANALYZE | TRIAGE REPORT", "=" * 55,
             f"Sample: {result['source']['filename']}", f"SHA-256: {result['source']['sha256']}",
             f"Analyzed (UTC): {result['analyzed_at']}",
             f"Verdict: {assessment['verdict']} | Score: {assessment['score']}/100",
             f"Reputation coverage: {result['coverage']['checked']}/{result['coverage']['total']}",
             assessment["note"], "", "FINDINGS"]
    for finding in assessment["findings"]:
        lines.append(f"+{finding['weight']} {finding['summary']}: {defang(finding['evidence'])}")
    if not assessment["findings"]:
        lines.append("No configured heuristic matched.")
    for kind, indicators in result["iocs"].items():
        lines.extend(["", kind.upper() + " (defanged)"] + [defang(v) for v in indicators])
    lines.extend(["", "REPUTATION"])
    for domain, data in result["domain_results"].items():
        lines.append(f"{defang(domain)}: {verdict_domain(domain, data)} | {json.dumps(data)}")
    for ip, data in result["ip_results"].items():
        lines.append(f"{defang(ip)}: {json.dumps(data)}")
    lines.extend(["", "HEADERS (reported, unverified)"])
    for name, values in result["headers"].items():
        lines.extend(f"{name}: {defang(v)}" for v in values)
    lines.extend(["", "ATTACHMENTS (metadata only)"])
    lines.extend(defang(json.dumps(a)) for a in result["attachments"])
    lines.extend(["", "NEXT ACTIONS"] + assessment["actions"])
    lines.extend(["", "LIMITATIONS"] + result["warnings"])
    return "\n".join(lines) + "\n"


def analyze_file(filepath, report_path, *, client=None, output_format="text"):
    source, destination = Path(filepath), Path(report_path)
    if source.resolve() == destination.resolve() or (destination.exists() and source.samefile(destination)):
        raise ValueError("Report path must not overwrite the input file.")
    with source.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    result = analyze_bytes(raw, filename=source.name, client=client)
    report = json.dumps(result, indent=2, ensure_ascii=False) + "\n" if output_format == "json" else generate_report(result)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")
    print(f"{source.name}: {result['assessment']['verdict']} ({result['assessment']['score']}/100) -> {destination}")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Passive email triage. Offline unless --enrich is selected.")
    parser.add_argument("email_file", nargs="?", help="One .txt/.eml file; default: input/ batch")
    parser.add_argument("report_path", nargs="?", help="Output file or directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--enrich", action="store_true", help="Send public domains/IPs to reputation providers")
    mode.add_argument("--offline", action="store_true", help="No external requests (default)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--input-dir", type=Path, default=INPUT_DIR, help="Batch input directory (default: input/)")
    parser.add_argument("--output-dir", type=Path, default=REPORTS_DIR, help="Report directory (default: reports/)")
    parser.add_argument("--max-lookups", type=int, default=25, help="Request budget across the batch, including retries")
    args = parser.parse_args(argv)
    if args.max_lookups < 0 or args.max_lookups > 500:
        parser.error("--max-lookups must be between 0 and 500")
    suffix = ".json" if args.format == "json" else ".txt"
    if args.email_file:
        files = [Path(args.email_file)]
        if not files[0].is_file() or files[0].suffix.lower() not in {".txt", ".eml"}:
            parser.error("Input must be an existing .txt or .eml file")
    else:
        files = sorted(p for p in args.input_dir.glob("*") if p.is_file() and p.suffix.lower() in {".txt", ".eml"})
        if not files:
            parser.error(f"No .txt or .eml files found in {args.input_dir}. Supply a file or use --input-dir.")
    if args.enrich:
        load_dotenv(ENV_FILE)
    client = IntelClient(enabled=args.enrich, max_lookups=args.max_lookups)
    failed = False
    try:
        for source in files:
            name = (source.stem if args.email_file else source.name) + "_report" + suffix
            destination = args.output_dir / name
            if args.report_path:
                destination = Path(args.report_path)
                if destination.is_dir() or args.report_path.endswith(("/", "\\")):
                    destination /= name
            try:
                analyze_file(source, destination, client=client, output_format=args.format)
            except (OSError, ValueError) as error:
                print(f"Could not analyze {source.name}: {error}")
                failed = True
    finally:
        client.close()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
