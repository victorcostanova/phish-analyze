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

from .email_parser import MAX_INPUT_BYTES, defang, is_internal_ip, parse_email, url_host
from .threat_intel import IntelClient
from .paths import ENV_FILE, INPUT_DIR, REPORTS_DIR
from .evidence import SCORING_SOURCES, collect_evidence

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


def _heuristic_assessment(text, iocs, domain_results, ip_results, headers=None, attachments=None, links=None):
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
    mismatches = [link for link in links or [] if link["status"] == "mismatch"]
    if mismatches:
        add("link_domain_mismatch", 25,
            "Displayed link domain differs from its destination; verify whether tracking is legitimate",
            "; ".join(f"{link['location']}: {link['displayed_host']} -> {link['target_host']}"
                      for link in mismatches[:3]))
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
    if verdict == "HIGH RISK":
        action_title = "Stop interaction. Report this message now."
        action_summary = "High-risk indicators require urgent review. Treat this message as potential phishing until verified."
        actions = [
            "Do not click links, open attachments, reply, share passwords or verification codes, or approve unexpected MFA prompts.",
            "Report the message to your security team immediately using your organization's phishing-reporting channel. Preserve the original email and this report.",
            "If you already entered credentials or approved an MFA request, tell your security team immediately. Use the official service through a known address to secure the account and revoke sessions with their guidance.",
            "If you opened or ran an attachment, stop interacting with it and report the affected device. Follow your organization's incident-response instructions.",
            "Confirm the request through a contact or website you already trust. Do not use phone numbers, reply addresses, or links supplied in this message.",
        ]
    elif verdict == "MEDIUM RISK":
        action_title = "Pause and verify before taking action."
        action_summary = "Suspicious indicators need investigation. Keep links and attachments unopened while you verify the request."
        actions = [
            "Do not reply, follow links, open attachments, or provide credentials until the message has been reviewed.",
            "Contact the claimed sender through a previously known number or address, not contact details supplied in the email.",
            "Send the original email and this report to your security team for review. Highlight the suspicious links, sender differences, or attachment findings.",
            "If you already shared information or opened an attachment, report what happened promptly so the team can assess exposure.",
        ]
    else:
        action_title = "Stay cautious with unexpected requests."
        action_summary = "Few configured signals were found. This is not confirmation that the message is safe."
        actions = [
            "Verify unexpected requests through a known, separate contact channel before taking action.",
            "Use the service's official website or app rather than an unexpected email link when signing in.",
            "If the message still seems unusual, report it for review; missing reputation data and a low score do not establish safety.",
        ]
    return {"score": score, "verdict": verdict, "findings": findings, "actions": actions,
            "action_title": action_title, "action_summary": action_summary,
            "note": "Heuristic triage score, not a probability. Low signal and zero detections do not establish safety."}


def analyze_bytes(raw, *, filename="sample.eml", client=None):
    parsed = parse_email(raw)
    iocs, indicator_sources, scoring_iocs, links = collect_evidence(parsed)

    def lookup(kind, value, eligible):
        if value not in eligible:
            return {"status": "skipped", "reason": "Context-only indicator; not used for risk scoring"}
        if kind == "ip" and is_internal_ip(value):
            return {"status": "skipped", "reason": "Non-public IP address"}
        return client.lookup(kind, value) if client else {"status": "skipped", "reason": "Offline mode"}

    domains = {d: lookup("domain", d, scoring_iocs["domains"]) for d in iocs["domains"]}
    ips = {ip: lookup("ip", ip, scoring_iocs["ips"]) for ip in iocs["ips"]}
    results = list(domains.values()) + list(ips.values())
    checked = sum(r["status"] == "ok" for r in results)
    warnings = parsed["warnings"] + [
        "Authentication-Results headers are reported claims, not independently verified SPF/DKIM/DMARC results.",
        "Attachment contents are hashed but not executed, unpacked, or malware-scanned.",
        "Recipient, relay, authentication and displayed-link-only indicators are context, not risk evidence.",
        "Link comparison uses parsed HTML text and a bundled suffix list; CSS visibility, redirects and ownership are not verified.",
    ]
    if checked < len(results):
        warnings.append("Reputation coverage is incomplete; unchecked or unknown indicators are not safe verdicts.")
    scoring_text = "\n".join(s["text"] for s in parsed["segments"]
                             if s["source"] in SCORING_SOURCES | {"link_text"})
    return {"schema_version": 2, "source": {"filename": filename,
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)},
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "mode": "enrichment_requested" if client and client.enabled else "offline",
            "iocs": iocs, "headers": parsed["headers"], "attachments": parsed["attachments"],
            "indicator_sources": indicator_sources, "scoring_iocs": scoring_iocs, "links": links,
            "domain_results": domains, "ip_results": ips,
            "coverage": {"checked": checked, "total": len(results)},
            "assessment": _heuristic_assessment(scoring_text, scoring_iocs, domains, ips,
                                                 parsed["headers"], parsed["attachments"], links),
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
        lines.extend(["", kind.upper() + " (defanged)"])
        for value in indicators:
            context = "risk-review candidate" if value in result["scoring_iocs"][kind] else "context only"
            lines.append(f"{defang(value)} [{context}]")
            for origin in result["indicator_sources"][kind][value]:
                lines.append(f"  Source: {origin['label']} | {origin['location']}")
    lines.extend(["", "LINK COMPARISON (no navigation)"])
    for link in result["links"]:
        lines.extend([f"{link['location']}: {link['status']}",
                      f"  Displayed: {defang(link['text'])}",
                      f"  Destination: {defang(link['href'])}", f"  {link['reason']}"])
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
    lines.extend(["", "NEXT ACTIONS", assessment["action_title"], assessment["action_summary"]]
                 + assessment["actions"])
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
