import hashlib
import io
import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from phish_analyze.analyzer import analyze_bytes, analyze_file, main, verdict_domain
from phish_analyze.web.app import app
from phish_analyze.web.rate_limit import AnalysisRateLimiter
from phish_analyze.email_parser import MAX_INPUT_BYTES, defang, extract_iocs, is_internal_ip, normalize_text, parse_email
from phish_analyze.threat_intel import IntelClient

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


class ParsingTests(unittest.TestCase):
    def test_defang_uppercase_scheme_and_ipv6(self):
        self.assertEqual(defang("HTTPS://[::1]/AbC"), "hxxps://[::1]/AbC")

    def test_refanging_preserves_url_case_and_real_host(self):
        text = "hxxps[://]Microsoft.com@evil[.]example/Reset?token=AbC"
        iocs = extract_iocs(normalize_text(text))
        self.assertEqual(iocs["urls"], ["https://Microsoft.com@evil.example/Reset?token=AbC"])
        self.assertEqual(iocs["domains"], ["evil.example"])

    def test_bare_url_is_not_swallowed_as_header(self):
        result = analyze_bytes(b"https://Example.com/Reset?token=AbC")
        self.assertEqual(result["iocs"]["urls"], ["https://Example.com/Reset?token=AbC"])

    def test_url_path_not_extra_domain_and_no_duplicate_www(self):
        iocs = extract_iocs("https://www.example.org/verification.google")
        self.assertEqual(iocs["domains"], ["www.example.org"])
        self.assertEqual(len(iocs["urls"]), 1)

    def test_ipv6_and_multicast_excluded_from_enrichment(self):
        iocs = extract_iocs("http://[2001:db8::1]/ 8.8.8.8 999.999.999.999")
        self.assertEqual(iocs["ips"], ["2001:db8::1", "8.8.8.8"])
        for ip in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "ff02::1", "::1"]:
            self.assertTrue(is_internal_ip(ip), ip)

    def test_mime_decoding_and_attachment_hash(self):
        message = EmailMessage()
        message["From"] = "Alice <alice@example.org>"
        message.set_content("Visit https://example.org/Reset?token=AbC", cte="base64")
        message.add_alternative('<a href="https://evil.example/Login?a=1&amp;b=2">Account</a>', subtype="html", cte="quoted-printable")
        payload = b"harmless fixture, not executable"
        message.add_attachment(payload, maintype="application", subtype="octet-stream", filename="invoice.exe")
        result = analyze_bytes(message.as_bytes())
        self.assertIn("https://example.org/Reset?token=AbC", result["iocs"]["urls"])
        self.assertIn("https://evil.example/Login?a=1&b=2", result["iocs"]["urls"])
        self.assertEqual(result["attachments"][0]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertIn("risky_attachment", [f["rule"] for f in result["assessment"]["findings"]])

    def test_attachment_contents_are_not_scanned_as_email_body(self):
        message = EmailMessage()
        message.set_content("Hello there")
        message.add_attachment(b"https://not-evidence.example", maintype="text", subtype="plain", filename="notes.txt")
        self.assertEqual(analyze_bytes(message.as_bytes())["iocs"]["urls"], [])

    def test_attached_message_does_not_mix_into_parent(self):
        parent, child = EmailMessage(), EmailMessage()
        parent.set_content("Hello")
        child.set_content("https://nested.example")
        parent.add_attachment(child, filename="forwarded.eml")
        result = analyze_bytes(parent.as_bytes())
        self.assertEqual(result["iocs"]["urls"], [])
        self.assertIsNone(result["attachments"][0]["sha256"])

    def test_malformed_url_does_not_crash(self):
        self.assertEqual(extract_iocs("https://[bad-host/path")["urls"], [])

    def test_limits_and_empty_input(self):
        for raw in [b"", b" " * 10, b"x" * (MAX_INPUT_BYTES + 1)]:
            with self.assertRaises(ValueError):
                parse_email(raw)
        with self.assertRaises(ValueError):
            extract_iocs(" ".join(f"d{i}.example" for i in range(501)))

    def test_mime_part_limit(self):
        message = EmailMessage()
        message.set_content("Hello")
        for _ in range(100):
            message.add_attachment(b"x", maintype="application", subtype="octet-stream", filename="a.bin")
        with self.assertRaisesRegex(ValueError, "MIME part limit"):
            parse_email(message.as_bytes())

    def test_unverified_auth_headers_do_not_prove_safety(self):
        result = analyze_bytes(b"Authentication-Results: attacker; spf=pass; dkim=pass\n\npassword verify urgent")
        self.assertEqual(result["assessment"]["score"], 15)
        self.assertIn("not independently verified", result["warnings"][0])

    def test_trusted_domain_does_not_override_malicious_findings(self):
        client = Mock(enabled=True)
        client.lookup.return_value = {"status": "ok", "malicious": 10, "suspicious": 0}
        result = analyze_bytes(b"https://microsoft.com/", client=client)
        self.assertEqual(result["assessment"]["verdict"], "HIGH RISK")
        self.assertEqual(verdict_domain("microsoft.com", client.lookup.return_value), "MALICIOUS REPUTATION")

    def test_json_and_input_overwrite_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "email.txt"
            source.write_bytes(b"Hello https://example.org")
            with self.assertRaises(ValueError):
                analyze_file(source, source)
            target = Path(folder) / "report.json"
            analyze_file(source, target, output_format="json")
            self.assertEqual(json.loads(target.read_text())["schema_version"], 2)

    def test_offline_cli_never_calls_network(self):
        with tempfile.TemporaryDirectory() as folder, patch("requests.Session.request") as network:
            self.assertEqual(main([str(SAMPLES_DIR / "s03.txt"), str(Path(folder) / "report.txt"), "--offline"]), 0)
            network.assert_not_called()


class IntelTests(unittest.TestCase):
    def client(self, responses=(), budget=25):
        session, sleep = Mock(), Mock()
        session.get.side_effect = responses
        client = IntelClient(enabled=True, session=session, clock=lambda: 100, sleep=sleep, max_lookups=budget)
        client.keys = {"vt": "test-key", "abuse": "test-key"}
        return client, session, sleep

    def response(self, status=200, payload=None):
        return Mock(status_code=status, json=Mock(return_value=payload))

    def vt(self):
        return self.response(payload={"data": {"attributes": {"last_analysis_stats":
            {"malicious": 0, "suspicious": 0, "undetected": 1, "harmless": 10}}}})

    def test_cache_and_pacing_only_between_actual_requests(self):
        client, session, sleep = self.client([self.vt(), self.vt()])
        client.lookup("domain", "google.com")
        sleep.assert_not_called()
        client.lookup("domain", "google.com")
        self.assertEqual(session.get.call_count, 1)
        client.lookup("domain", "microsoft.com")
        self.assertAlmostEqual(sleep.call_args.args[0], 15.1)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_missing_keys_reserved_indicators_no_network_or_sleep(self):
        client, session, sleep = self.client()
        for kind, value in [("domain", "mail.example.org"), ("ip", "127.0.0.1"), ("ip", "ff02::1")]:
            self.assertEqual(client.lookup(kind, value)["status"], "skipped")
        client.keys["vt"] = None
        self.assertEqual(client.lookup("domain", "google.com")["status"], "skipped")
        session.get.assert_not_called()
        sleep.assert_not_called()

    def test_429_disables_provider_for_remaining_batch(self):
        client, session, _ = self.client([self.response(429)])
        for domain in ("google.com", "microsoft.com"):
            self.assertEqual(client.lookup("domain", domain)["status"], "error")
        self.assertEqual(session.get.call_count, 1)

    def test_auth_failures_do_not_retry_or_expose_credentials(self):
        for status in (401, 403):
            client, session, _ = self.client([self.response(status)])
            result = client.lookup("domain", "google.com")
            self.assertEqual(result["status"], "error")
            self.assertNotIn("test-key", str(result))
            client.lookup("domain", "microsoft.com")
            self.assertEqual(session.get.call_count, 1)

    def test_abuse_response_and_invalid_score(self):
        for score, expected in [(80, "ok"), (101, "error")]:
            client, _, _ = self.client([self.response(payload={"data": {
                "abuseConfidenceScore": score, "totalReports": 5, "countryCode": "US"}})])
            self.assertEqual(client.lookup("ip", "8.8.8.8")["status"], expected)

    def test_zero_stats_remain_unknown(self):
        payload = {"data": {"attributes": {"last_analysis_stats":
            {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}}}}
        client, _, _ = self.client([self.response(payload=payload)])
        self.assertEqual(client.lookup("domain", "google.com")["status"], "no_data")

    def test_no_data_is_cached(self):
        client, session, _ = self.client([self.response(404)])
        for _ in range(2):
            self.assertEqual(client.lookup("domain", "google.com")["status"], "no_data")
        self.assertEqual(session.get.call_count, 1)

    def test_transient_failure_recovers_and_obeys_budget(self):
        client, session, _ = self.client([requests.Timeout(), self.vt()])
        self.assertEqual(client.lookup("domain", "google.com")["status"], "ok")
        self.assertEqual(session.get.call_count, 2)
        client, session, _ = self.client([self.response(503)], budget=1)
        self.assertEqual(client.lookup("domain", "google.com")["status"], "skipped")
        self.assertEqual(session.get.call_count, 1)

    def test_bad_schema_and_errors_are_not_cached(self):
        for payload in [None, [], {}, {"data": {"attributes": {"last_analysis_stats": {}}}}]:
            client, session, _ = self.client([self.response(payload=payload), self.vt()])
            self.assertEqual(client.lookup("domain", "google.com")["status"], "error")
            self.assertEqual(client.lookup("domain", "google.com")["status"], "ok")


class WebTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.extensions["analysis_rate_limiter"] = AnalysisRateLimiter()
        self.web = app.test_client()

    def test_home_demo_and_health(self):
        for route in ["/", "/healthz", "/static/style.css"]:
            with self.web.get(route) as response:
                self.assertEqual(response.status_code, 200)
        with patch("requests.Session.request") as network:
            response = self.web.post("/", data={"action": "demo"})
            self.assertIn(b"HIGH RISK", response.data)
            network.assert_not_called()

    def test_xss_is_escaped_and_csp_present(self):
        response = self.web.post("/", data={"email_text": '<script>alert(1)</script> https://example.org'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<script>", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_export_json_and_file_upload(self):
        response = self.web.post("/", data={"action": "json", "email_file":
            (io.BytesIO(b"Subject: Hello\n\nhttps://example.org/AbC"), "test.eml")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["source"]["filename"], "test.eml")
        self.assertEqual(response.json["iocs"]["urls"], ["https://example.org/AbC"])
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_empty_wrong_extension_and_oversized(self):
        self.assertEqual(self.web.post("/", data={"email_text": ""}).status_code, 400)
        self.assertEqual(self.web.post("/", data={"email_file": (io.BytesIO(b"Hi"), "bad.exe")}).status_code, 400)
        # A raw oversized request avoids Werkzeug's test-upload spool files.
        with self.web.post("/", data=b"x" * (MAX_INPUT_BYTES + 70000),
                           content_type="multipart/form-data; boundary=oversized") as response:
            self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
