"""Indicator provenance and passive HTML-link comparison. No network access."""

import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

from .email_parser import MAX_INDICATORS, extract_iocs, normalize_text, url_host

# Use the dependency's bundled PSL, including private hosting suffixes. Never
# fetch a suffix list or create a cache file during message analysis.
SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                               include_psl_private_domains=True)
SCORING_SOURCES = {"header_from", "header_sender", "header_reply_to", "header_return_path",
                   "header_subject", "body_plain", "body_html", "link_target", "html_resource"}
SOURCE_LABELS = {
    "header_from": "Sender (From)", "header_sender": "Sending agent (Sender)",
    "header_to": "Recipient (To)", "header_cc": "Recipient (Cc)",
    "header_bcc": "Recipient (Bcc)", "header_reply_to": "Reply address (Reply-To)",
    "header_return_path": "Envelope sender (Return-Path)", "header_subject": "Subject",
    "header_received": "Mail relay (Received)", "header_date": "Message date",
    "header_message_id": "Message identifier", "header_authentication_results": "Authentication claim",
    "body_plain": "Plain-text body", "body_html": "HTML body text",
    "link_text": "Displayed link text", "link_target": "Actual link target",
    "html_resource": "HTML resource or form target",
}


def http_target(value):
    """Return only a usable absolute HTTP(S) target; do not invent a base URL."""
    value = normalize_text(value.strip())
    # Browsers and urllib can disagree about backslashes and embedded control
    # characters. Do not label these ambiguous targets as matching/safe hosts.
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if value.startswith("//"):
        value = "https:" + value
    try:
        parsed = urlsplit(value)
        host = url_host(value)
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return None
        parsed.port  # Reject invalid ports before treating this as a target.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+", host, flags=re.I):
                return None
    except ValueError:
        return None
    return value


def site_identity(host):
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        result = SUFFIXES(host)
        # Unknown suffixes are compared as exact hostnames, never by last-two-label guessing.
        return result.top_domain_under_public_suffix or host


def displayed_host(label):
    """Compare labels that are entirely a URL/hostname, not arbitrary brand text."""
    label = normalize_text(label.strip())
    if not label or re.search(r"\s", label):
        return None
    value = label if re.match(r"https?://", label, re.I) else "https://" + label
    if not http_target(value):
        return None
    parsed = urlsplit(value)
    if parsed.username is not None:
        return None
    host = url_host(value)
    # Accept Unicode/punycode hosts and IP literals, but not labels like 'Continue'.
    if "." not in host and ":" not in host:
        return None
    return host


def inspect_links(anchors):
    results = []
    for anchor in anchors:
        target = http_target(anchor["href"])
        actual = url_host(target) if target else None
        displayed = displayed_host(anchor["text"])
        if not target:
            status = "not_compared"
            reason = "Relative, missing, invalid or non-HTTP target; no navigation or base-URL resolution performed."
        elif not displayed:
            status = "not_compared"
            reason = "Label does not consist of a URL or hostname."
        elif actual == displayed:
            status = "same_host"
            reason = "Displayed and destination hostnames match; this does not establish safety."
        elif site_identity(actual) == site_identity(displayed):
            status = "same_site"
            reason = "Hostnames differ within the same registrable domain; ownership and safety are unverified."
        else:
            status = "mismatch"
            reason = "Displayed domain differs from the actual destination; tracking links can also cause this."
        results.append({"location": anchor["location"], "text": anchor["text"],
                        "href": anchor["href"], "displayed_host": displayed,
                        "target_host": actual, "status": status, "reason": reason})
    return results


def collect_evidence(parsed):
    sources = {kind: {} for kind in ("urls", "domains", "ips", "emails")}
    unique_count, references = 0, 0
    for segment in parsed["segments"]:
        text = segment["text"]
        if segment["source"] in {"link_target", "html_resource"}:
            text = http_target(text) or ""
        for kind, values in extract_iocs(text).items():
            for value in values:
                if value not in sources[kind]:
                    sources[kind][value] = []
                    unique_count += 1
                    if unique_count > MAX_INDICATORS:
                        raise ValueError("Sample exceeds the 500 indicator limit.")
                origin = {"source": segment["source"],
                          "label": SOURCE_LABELS.get(segment["source"], segment["source"]),
                          "location": segment["location"]}
                if origin not in sources[kind][value]:
                    sources[kind][value].append(origin)
                    references += 1
                    if references > 5000:
                        raise ValueError("Sample exceeds the 5000 indicator source limit.")
    iocs = {kind: sorted(values) for kind, values in sources.items()}
    scoring_iocs = {kind: [value for value in values if any(
        s["source"] in SCORING_SOURCES for s in sources[kind][value])] for kind, values in iocs.items()}
    return iocs, sources, scoring_iocs, inspect_links(parsed["links"])
