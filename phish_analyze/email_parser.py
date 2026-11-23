"""Bounded email parsing and passive indicator extraction; never follows links."""

import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 1024 * 1024
MAX_PARTS = 100
MAX_INDICATORS = 500
MAX_HTML_LINKS = 500
MAX_SEGMENTS = 2000
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?![\w.-])", re.I
)
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.I)
EMAIL_RE = re.compile(r"[\w.%+\-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}", re.I)
FILE_EXTS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx",
             "xls", "xlsx", "html", "htm", "exe", "zip", "js", "css"}


def normalize_text(text):
    """Refang common analyst notation without altering case-sensitive evidence."""
    replacements = {"[at]": "@", "(at)": "@", "[dot]": ".", "(dot)": ".",
                    "[.]": ".", "(.)": ".", "[://]": "://", "[:]": ":"}
    for old, new in replacements.items():
        text = re.sub(re.escape(old), lambda _: new, text, flags=re.I)
    return re.sub(r"\bhxxp(s?)\b", lambda m: "http" + m[1].lower(), text, flags=re.I)


def defang(value):
    return re.sub(r"https?://", lambda m: "hxxps://" if m[0].lower().startswith("https") else "hxxp://",
                  str(value).replace(".", "[.]"), flags=re.I)


def is_internal_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return not address.is_global or address.is_multicast
    except ValueError:
        return False


def url_host(url):
    try:
        host = urlsplit(url).hostname
        return host.encode("idna").decode("ascii").lower().rstrip(".") if host else None
    except (ValueError, UnicodeError):
        return None


class EmailHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.anchors = []
        self.anchor = None
        self.hidden_depth = 0

    def handle_data(self, data):
        if self.hidden_depth:
            return
        if self.anchor is not None:
            self.anchor["label_parts"].append(data)
        else:
            self.text.append(data)

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden_depth += 1
        if self.hidden_depth:
            return
        if tag == "a":
            self._finish_anchor()
            self.anchor = {"href": dict(attrs).get("href") or "", "label_parts": []}
        if tag == "br":
            self.handle_data(" ")
        for key, value in attrs:
            if key in {"href", "src", "action"} and value and not (tag == "a" and key == "href"):
                self.links.append(value)
                self._check_limit()

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1
        if not self.hidden_depth and tag == "a":
            self._finish_anchor()

    def _check_limit(self):
        if len(self.links) + len(self.anchors) > MAX_HTML_LINKS:
            raise ValueError("Email exceeds the 500 HTML link limit.")

    def _finish_anchor(self):
        if self.anchor is not None:
            self.anchors.append({"href": self.anchor["href"],
                                 "text": "".join(self.anchor["label_parts"]).strip()})
            self.anchor = None
            self._check_limit()

    def close(self):
        super().close()
        self._finish_anchor()


def parse_email(raw):
    if not raw.strip():
        raise ValueError("Provide a non-empty email or text sample.")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Sample exceeds the 1 MiB input limit.")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except RecursionError as error:
        raise ValueError("Email nesting exceeds the parser's supported depth.") from error
    headers = {name: [str(v) for v in message.get_all(name, [])]
               for name in ("From", "Sender", "To", "Cc", "Bcc", "Reply-To", "Return-Path", "Subject",
                            "Date", "Message-ID", "Authentication-Results", "Received")}
    text_parts = []
    attachments = []
    warnings = []
    segments, links = [], []
    html_link_count = 0

    def segment(source, location, text):
        if len(segments) >= MAX_SEGMENTS:
            raise ValueError("Email exceeds the 2000 evidence segment limit.")
        segments.append({"source": source, "location": location, "text": normalize_text(text)})

    for name, values in headers.items():
        for occurrence, value in enumerate(values, 1):
            segment("header_" + name.lower().replace("-", "_"), f"{name} #{occurrence}", value)
    pending = [message]
    index = 0
    while pending:
        part = pending.pop()
        if index >= MAX_PARTS:
            raise ValueError("Email exceeds the 100 MIME part limit.")
        index += 1
        if part.defects:
            warnings.append("Malformed MIME content encountered; extraction may be incomplete.")
        if part.is_multipart() and (part.get_filename() or part.get_content_disposition() == "attachment"):
            attachments.append({"filename": part.get_filename() or "unnamed",
                                "content_type": part.get_content_type(), "size_bytes": None,
                                "sha256": None, "part_index": index})
            warnings.append("Attached multipart messages were not inspected or hashed.")
            continue
        if part.is_multipart():
            pending.extend(reversed(part.get_payload()))
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_filename() or part.get_content_disposition() == "attachment":
            attachments.append({"filename": part.get_filename() or "unnamed",
                                "content_type": part.get_content_type(),
                                "size_bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(), "part_index": index})
        elif part.get_content_type() in {"text/plain", "text/html"}:
            try:
                content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                content = payload.decode("utf-8", errors="replace")
                warnings.append("Unknown character encoding; decoded as UTF-8 with replacement.")
            if part.get_content_type() == "text/html":
                html = EmailHTML()
                html.feed(content)
                html.close()
                html_link_count += len(html.anchors) + len(html.links)
                if html_link_count > MAX_HTML_LINKS:
                    raise ValueError("Email exceeds the 500 HTML link limit.")
                segment("body_html", f"MIME part {index}: HTML text", "\n".join(html.text))
                for anchor_index, anchor in enumerate(html.anchors, 1):
                    location = f"MIME part {index}: link {anchor_index}"
                    links.append({**anchor, "location": location})
                    segment("link_text", location + " label", anchor["text"])
                    segment("link_target", location + " href", anchor["href"])
                for resource_index, resource in enumerate(html.links, 1):
                    segment("html_resource", f"MIME part {index}: resource {resource_index}", resource)
                content = "\n".join(html.text + html.links +
                                    [a["text"] + "\n" + a["href"] for a in html.anchors])
            else:
                segment("body_plain", f"MIME part {index}: plain text", content)
            text_parts.append(content)
    # Avoid interpreting MIME boundary strings and attachment bytes as indicators.
    evidence = "\n".join(v for values in headers.values() for v in values)
    evidence += "\n" + "\n".join(text_parts)
    if not any(headers.values()) and not message.get("Content-Type") and not message.get("MIME-Version"):
        # Bare URLs such as https://host/path look like RFC header fields.
        evidence = raw.decode("utf-8", errors="replace")
        segments = []
        segment("body_plain", "Plain text input", evidence)
    return {"text": normalize_text(evidence), "headers": headers,
            "attachments": attachments, "warnings": sorted(set(warnings)),
            "segments": segments, "links": links}


def extract_iocs(text):
    text = normalize_text(text)
    urls, domains, ips = set(), set(), set()
    for match in URL_RE.finditer(text):
        value = match[0].rstrip(".,;!?'\"")
        while value.endswith(")") and value.count(")") > value.count("("):
            value = value[:-1]
        if value.lower().startswith("www."):
            value = "http://" + value
        host = url_host(value)
        if not host:
            continue
        urls.add(value)
        try:
            ips.add(str(ipaddress.ip_address(host)))
        except ValueError:
            if DOMAIN_RE.fullmatch(host):
                domains.add(host)
    # Remove whole URLs before searching for bare domains: a path such as
    # /verification.google is not evidence of a separate contacted domain.
    remainder = URL_RE.sub(" ", text)
    emails = set(EMAIL_RE.findall(remainder))
    for address in emails:
        domains.add(address.rsplit("@", 1)[1].lower())
    for match in DOMAIN_RE.finditer(remainder):
        domain = match[0].lower()
        if domain.rsplit(".", 1)[-1] not in FILE_EXTS:
            domains.add(domain)
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w:])[0-9a-fA-F:]*:[0-9a-fA-F:.]+", text)
    for candidate in candidates:
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass
    result = {"urls": sorted(urls), "domains": sorted(domains),
              "ips": sorted(ips), "emails": sorted(emails)}
    if sum(map(len, result.values())) > MAX_INDICATORS:
        raise ValueError("Sample exceeds the 500 indicator limit.")
    return result
