import unittest
from email.message import EmailMessage
from unittest.mock import Mock, patch

from phish_analyze.analyzer import analyze_bytes, generate_report


def html_email(body, **headers):
    message = EmailMessage()
    for name, value in headers.items():
        message[name] = value
    message.set_content(body, subtype="html")
    return message.as_bytes()


class EvidenceTests(unittest.TestCase):
    def test_sources_keep_all_occurrences_and_deduplicate_indicators(self):
        raw = html_email('<a href="https://same.example/Login">Continue</a>',
                         From="sender@same.example", To="victim@same.example")
        result = analyze_bytes(raw)
        self.assertEqual(result["iocs"]["domains"], ["same.example"])
        sources = result["indicator_sources"]["domains"]["same.example"]
        self.assertEqual({s["source"] for s in sources}, {"header_from", "header_to", "link_target"})
        self.assertIn("same.example", result["scoring_iocs"]["domains"])

    def test_recipient_and_relay_context_does_not_score_or_enrich(self):
        raw = (b"From: sender@example.org\nTo: person@micros0ft-urgent.com\n"
               b"Cc: admin@paypal-danger.com\nBcc: user@google-alert.com\n"
               b"Received: from relay.example.net [8.8.8.8]\n"
               b"Authentication-Results: gateway.example.net; spf=pass\n\nHello there")
        client = Mock(enabled=True)
        client.lookup.return_value = {"status": "no_data"}
        result = analyze_bytes(raw, client=client)
        self.assertEqual(result["assessment"]["score"], 0)
        client.lookup.assert_called_once_with("domain", "example.org")
        self.assertIn("8.8.8.8", result["iocs"]["ips"])
        self.assertEqual(result["ip_results"]["8.8.8.8"]["status"], "skipped")
        self.assertNotIn("micros0ft-urgent.com", result["scoring_iocs"]["domains"])

    def test_displayed_only_domain_is_context_not_lookup_target(self):
        raw = html_email('<a href="https://destination.example/">https://paypal-fake.com</a>')
        client = Mock(enabled=True)
        client.lookup.return_value = {"status": "no_data"}
        result = analyze_bytes(raw, client=client)
        client.lookup.assert_called_once_with("domain", "destination.example")
        self.assertEqual(result["assessment"]["score"], 25)
        self.assertEqual(result["indicator_sources"]["domains"]["paypal-fake.com"][0]["source"], "link_text")

    def test_nested_label_mismatch_preserves_url_token(self):
        raw = html_email('<a href="https://evil.example/Reset?token=AbC&amp;x=2"><span>https://</span><b>paypal.com</b></a>')
        result = analyze_bytes(raw)
        link = result["links"][0]
        self.assertEqual(link["text"], "https://paypal.com")
        self.assertEqual(link["href"], "https://evil.example/Reset?token=AbC&x=2")
        self.assertEqual(link["status"], "mismatch")
        self.assertIn("link_domain_mismatch", [f["rule"] for f in result["assessment"]["findings"]])
        report = generate_report(result)
        self.assertIn("Displayed link text", report)
        self.assertIn("Actual link target", report)
        self.assertIn("hxxps://evil[.]example/Reset?token=AbC&x=2", report)

    def test_host_comparison_edge_cases(self):
        cases = [
            ("https://PAYPAL.com/", "https://paypal.com./Login", "same_host"),
            ("paypal.com", "https://www.paypal.com/Login", "same_site"),
            ("bank.co.uk", "https://login.bank.co.uk/Login", "same_site"),
            ("bank.co.uk", "https://evil.co.uk/Login", "mismatch"),
            ("alice.github.io", "https://bob.github.io/", "mismatch"),
            ("paypal.com", "https://paypal.com.attacker.example/", "mismatch"),
            ("paypal.com", "https://paypal.com@evil.example/", "mismatch"),
            ("https://paypal.com", "//evil.example/Login", "mismatch"),
            ("https://paypal.com", "/Login", "not_compared"),
            ("https://paypal.com", "javascript:alert(1)", "not_compared"),
            ("https://paypal.com", "https://[broken", "not_compared"),
            ("https://paypal.com", "https://evil.example:invalid", "not_compared"),
            ("https://paypal.com", "https://evil.example\\@paypal.com", "not_compared"),
            ("https://paypal.com", "https://pay\tpal.com", "not_compared"),
            ("https://paypal.com", "https://pay pal.com", "not_compared"),
            ("Continue", "https://evil.example/", "not_compared"),
            ("Go to paypal.com", "https://evil.example/", "not_compared"),
            ("8.8.8.8", "https://1.1.1.1/", "mismatch"),
            ("https://[2001:db8::1]", "https://[2001:db8::1]/", "same_host"),
            ("https://b\u00fccher.de", "https://xn--bcher-kva.de/", "same_host"),
            ("hxxps://paypal[.]com", "https://evil.example/", "mismatch"),
        ]
        with patch("requests.Session.request", side_effect=AssertionError("Unexpected network request")):
            for label, target, expected in cases:
                with self.subTest(label=label, target=target):
                    result = analyze_bytes(html_email(f'<a href="{target}">{label}</a>'))
                    self.assertEqual(result["links"][0]["status"], expected)

    def test_repeated_mismatches_score_once(self):
        result = analyze_bytes(html_email('<a href="https://evil.example/">paypal.com</a>' * 5))
        self.assertEqual(len(result["links"]), 5)
        self.assertEqual(result["assessment"]["score"], 25)

    def test_plain_text_does_not_invent_anchor_comparisons(self):
        result = analyze_bytes(b"See https://paypal.com and https://evil.example")
        self.assertEqual(result["links"], [])
        self.assertTrue(all(o["source"] == "body_plain" for o in result["indicator_sources"]["urls"]["https://paypal.com"]))

    def test_encoded_html_parts_keep_locations(self):
        message = EmailMessage()
        message.set_content("Hello https://example.org", cte="base64")
        message.add_alternative('<a href="https://evil.example">paypal.com</a>', subtype="html", cte="quoted-printable")
        result = analyze_bytes(message.as_bytes())
        self.assertIn("MIME part 3", result["links"][0]["location"])
        self.assertEqual(result["indicator_sources"]["urls"]["https://example.org"][0]["source"], "body_plain")

    def test_hidden_script_not_used_as_visible_label(self):
        result = analyze_bytes(html_email('<a href="https://example.org"><script>paypal.com</script>Continue</a>'))
        self.assertEqual(result["links"][0]["text"], "Continue")
        self.assertEqual(result["links"][0]["status"], "not_compared")

    def test_link_limit_rejects_pathological_html(self):
        with self.assertRaisesRegex(ValueError, "HTML link limit"):
            analyze_bytes(html_email('<a href="https://example.org">example.org</a>' * 501))

    def test_resource_limit_applies_across_mime_parts(self):
        message = EmailMessage()
        message.set_content("Hello")
        for _ in range(2):
            message.add_alternative('<img src="https://example.org/pixel">' * 251, subtype="html")
        with self.assertRaisesRegex(ValueError, "HTML link limit"):
            analyze_bytes(message.as_bytes())

    def test_web_link_evidence_is_escaped(self):
        from phish_analyze.web.app import app
        from phish_analyze.web.rate_limit import AnalysisRateLimiter
        import io

        original = app.extensions["analysis_rate_limiter"]
        app.extensions["analysis_rate_limiter"] = AnalysisRateLimiter()
        try:
            raw = html_email('<a href="https://evil.example/">&lt;img src=x onerror=alert(1)&gt;</a>')
            response = app.test_client().post("/", data={"email_file": (io.BytesIO(raw), "test.eml")})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b"<img src=x", response.data)
            self.assertIn(b"&lt;img src=x", response.data)
        finally:
            app.extensions["analysis_rate_limiter"] = original


if __name__ == "__main__":
    unittest.main()
