import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from phish_analyze.web.app import app
from phish_analyze.web.rate_limit import AnalysisRateLimiter


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.limiter = AnalysisRateLimiter(limit=2, clock=lambda: self.now)
        self.previous = app.extensions["analysis_rate_limiter"]
        app.extensions["analysis_rate_limiter"] = self.limiter
        self.web = app.test_client()

    def tearDown(self):
        app.extensions["analysis_rate_limiter"] = self.previous

    def test_sliding_window_and_retry_after(self):
        self.assertEqual(self.limiter.admit(), 0)
        self.now = 110
        self.assertEqual(self.limiter.admit(), 0)
        self.assertEqual(self.limiter.admit(), 50)
        self.now = 160
        self.assertEqual(self.limiter.admit(), 0)
        self.assertEqual(self.limiter.admit(), 10)

    def test_concurrent_calls_cannot_overrun_budget(self):
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(lambda _: self.limiter.admit(), range(30)))
        self.assertEqual(results.count(0), 2)

    def test_rejection_before_analysis_and_forwarded_headers_cannot_bypass(self):
        self.web.post("/", data={"action": "demo"})
        self.web.post("/", data={"action": "demo"})
        with patch("phish_analyze.web.app.analyze_bytes") as analyze:
            response = self.web.post("/", data=b"x" * 2000000,
                                     headers={"X-Forwarded-For": "1.2.3.4", "Forwarded": "for=8.8.8.8"})
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers["Retry-After"], "60")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIn("Content-Security-Policy", response.headers)
            analyze.assert_not_called()
        self.now += 60
        self.assertEqual(self.web.post("/", data={"action": "demo"}).status_code, 200)

    def test_exports_and_invalid_requests_share_budget(self):
        self.assertEqual(self.web.post("/", data={"action": "json", "email_text": "Hello"}).status_code, 200)
        self.assertEqual(self.web.post("/", data={"email_text": ""}).status_code, 400)
        self.assertEqual(self.web.post("/", data={"action": "text", "email_text": "Hello"}).status_code, 429)

    def test_get_health_and_assets_do_not_consume_budget(self):
        for _ in range(4):
            self.assertEqual(self.web.get("/").status_code, 200)
            self.assertEqual(self.web.get("/healthz").status_code, 200)
            with self.web.get("/static/style.css") as response:
                self.assertEqual(response.status_code, 200)
        self.assertEqual(self.limiter.admit(), 0)

    def test_invalid_configuration_rejected(self):
        for limit in (0, -1, 1001):
            with self.assertRaises(ValueError):
                AnalysisRateLimiter(limit=limit)


if __name__ == "__main__":
    unittest.main()
