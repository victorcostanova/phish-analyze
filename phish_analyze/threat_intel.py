"""Optional reputation lookups. One client owns a sequential batch and its quota."""

import os
import time
from urllib.parse import quote

import requests

from .email_parser import DOMAIN_RE, is_internal_ip

RESERVED_DOMAINS = {"example.com", "example.net", "example.org", "localhost",
                    "local", "internal", "test", "invalid", "example", "onion"}


def reserved_domain(domain):
    return any(domain == item or domain.endswith("." + item) for item in RESERVED_DOMAINS)


class IntelClient:
    """Success cache and request pacing are scoped to this CLI run.

    Do not share across threads/workers. Public web analysis is offline.
    """

    def __init__(self, *, enabled=False, max_lookups=25, session=None,
                 clock=time.monotonic, sleep=time.sleep):
        self.enabled = enabled
        self.remaining = max_lookups
        self.session = session if session is not None else requests.Session()
        self.clock, self.sleep = clock, sleep
        self.keys = {"vt": os.getenv("VIRUSTOTAL_API_KEY"),
                     "abuse": os.getenv("ABUSEIPDB_API_KEY")}
        self.next_request = {"vt": 0, "abuse": 0}
        self.disabled = {}
        self.cache = {}

    def close(self):
        self.session.close()

    def _request(self, provider, url, **kwargs):
        for attempt in range(2):
            if self.remaining <= 0:
                return {"status": "skipped", "reason": "Lookup budget reached"}
            delay = max(0, self.next_request[provider] - self.clock())
            if delay:
                self.sleep(delay)
            self.remaining -= 1
            self.next_request[provider] = self.clock() + (15.1 if provider == "vt" else 1.0)
            try:
                response = self.session.get(url, timeout=(3.05, 10),
                                            allow_redirects=False, **kwargs)
                if response.status_code in {401, 403, 429}:
                    reason = "Provider quota reached" if response.status_code == 429 else "Provider rejected API credentials"
                    self.disabled[provider] = reason
                    return {"status": "error", "error": reason}
                if response.status_code == 404:
                    return {"status": "no_data"}
                if response.status_code >= 500 and attempt == 0:
                    self.sleep(2)
                    continue
                if response.status_code != 200:
                    return {"status": "error", "error": f"Provider returned HTTP {response.status_code}"}
                return response.json()
            except requests.RequestException:
                if attempt == 0:
                    self.sleep(2)
                    continue
                return {"status": "error", "error": "Provider request failed or timed out"}
            except ValueError:
                return {"status": "error", "error": "Provider returned invalid JSON"}

    def lookup(self, kind, indicator):
        provider = "vt" if kind == "domain" else "abuse"
        if not self.enabled:
            return {"status": "skipped", "reason": "Offline mode"}
        if kind == "domain" and (not DOMAIN_RE.fullmatch(indicator) or reserved_domain(indicator)):
            return {"status": "skipped", "reason": "Reserved or invalid domain"}
        if kind == "ip" and is_internal_ip(indicator):
            return {"status": "skipped", "reason": "Non-public IP address"}
        if not self.keys[provider]:
            return {"status": "skipped", "reason": "API key not configured"}
        if provider in self.disabled:
            return {"status": "error", "error": self.disabled[provider]}
        cache_key = (kind, indicator)
        if cache_key in self.cache:
            return dict(self.cache[cache_key])
        if kind == "domain":
            raw = self._request(provider,
                "https://www.virustotal.com/api/v3/domains/" + quote(indicator, safe=""),
                headers={"x-apikey": self.keys[provider]})
        else:
            raw = self._request(provider, "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.keys[provider], "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90})
        try:
            if not isinstance(raw, dict):
                raise ValueError("Invalid provider object")
            if "status" in raw:
                if raw["status"] == "no_data" and len(self.cache) < 2048:
                    self.cache[cache_key] = raw
                return raw
            if kind == "domain":
                stats = raw["data"]["attributes"]["last_analysis_stats"]
                result = {k: self._count(stats[k]) for k in
                          ("malicious", "suspicious", "harmless", "undetected")}
                result["status"] = "ok" if sum(result.values()) else "no_data"
            else:
                data = raw["data"]
                score = self._count(data["abuseConfidenceScore"])
                if score > 100:
                    raise ValueError("Invalid confidence score")
                result = {"status": "ok", "abuse_score": score,
                          "total_reports": self._count(data["totalReports"]),
                          "country": data.get("countryCode"), "isp": data.get("isp")}
        except (KeyError, TypeError, ValueError):
            return {"status": "error", "error": "Provider response schema was invalid"}
        if len(self.cache) < 2048:
            self.cache[cache_key] = result
        return dict(result)

    @staticmethod
    def _count(value):
        if type(value) is not int or value < 0:
            raise ValueError("Invalid count")
        return value
