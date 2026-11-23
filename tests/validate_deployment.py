"""Validate the actual deployment ZIP in isolation over HTTP.

Run with the clean environment's Python. Linux uses the deployment's Gunicorn
entry point; Windows uses a temporary WSGI test server because Gunicorn requires
Unix. No Azure resources or external reputation services are contacted.
"""

import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "deploy/azure/packages/phish-analyze.zip"


def main():
    expected = set(runpy.run_path(str(ROOT / "deploy/azure/package_azure.py"))["FILES"])
    temporary = (ROOT / "tests/temporary").resolve()
    if not temporary.is_relative_to(ROOT):
        raise RuntimeError("Validation directory must remain inside the project.")
    temporary.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="deployment-check-", dir=temporary) as directory:
        target = Path(directory).resolve()
        if not target.is_relative_to(temporary):
            raise RuntimeError("Unexpected extraction destination.")
        with ZipFile(ARCHIVE) as archive:
            names = archive.namelist()
            assert set(names) == expected and len(names) == len(expected), "Unexpected ZIP contents"
            assert archive.testzip() is None, "ZIP integrity failure"
            for name in names:
                assert archive.read(name) == (ROOT / name).read_bytes(), f"Stale packaged file: {name}"
                assert (target / name).resolve().is_relative_to(target), "Unsafe ZIP member"
            archive.extractall(target)
        env = dict(os.environ)
        for name in ("PYTHONPATH", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"):
            env.pop(name, None)
        env["ANALYSIS_RATE_LIMIT"] = "4"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # Select an unused loopback port. The server child binds immediately after.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if os.name == "nt":
            command = [sys.executable, "-B", "-c",
                       "from wsgiref.simple_server import make_server; "
                       "from phish_analyze.web.app import app; "
                       f"make_server('127.0.0.1', {port}, app).serve_forever()"]
            server_name = "Windows WSGI test server"
        else:
            command = [sys.executable, "-B", "-m", "gunicorn", "--bind",
                       f"127.0.0.1:{port}", "--workers=1", "--timeout=60",
                       "phish_analyze.web.app:app"]
            server_name = "Gunicorn (Linux/Unix)"
        opener = build_opener(ProxyHandler({}))
        base = f"http://127.0.0.1:{port}"

        def request(path="/", data=None, headers=None):
            try:
                response = opener.open(Request(base + path, data=data, headers=headers or {}), timeout=5)
            except HTTPError as error:
                response = error
            with response:
                return response.status, response.read(), response.headers

        with (target / "server.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, cwd=target, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("Server exited: " + (target / "server.log").read_text())
                    try:
                        assert request("/healthz")[0] == 200
                        break
                    except (URLError, TimeoutError):
                        if time.monotonic() > deadline:
                            raise RuntimeError("Server did not become ready")
                        time.sleep(0.1)
                status, body, headers = request()
                assert status == 200 and b"4 submissions per minute" in body
                assert headers["Cache-Control"] == "no-store"
                assert "default-src 'none'" in headers["Content-Security-Policy"]
                assert request("/static/style.css")[0] == 200
                form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                status, body, _ = request(data=b"action=demo", headers=form_headers)
                assert status == 200 and b"HIGH RISK" in body and b"Actual link target" in body
                assert b"Mismatch" in body and b"85<span>" in body
                sample = (b"From: sender@example.org\nTo: user@recipient.example\n"
                          b"Content-Type: text/html\n\n"
                          b'<a href="https://evil.example/Reset?token=AbC">https://paypal.com</a>')
                boundary = "phish-validation-boundary"
                upload = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\njson\r\n"
                          f"--{boundary}\r\nContent-Disposition: form-data; name=\"email_file\"; filename=\"check.eml\"\r\n"
                          "Content-Type: message/rfc822\r\n\r\n").encode() + sample + f"\r\n--{boundary}--\r\n".encode()
                status, body, headers = request(data=upload, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
                result = json.loads(body)
                assert status == 200 and result["schema_version"] == 2
                assert result["links"][0]["status"] == "mismatch"
                assert result["indicator_sources"]["domains"]["recipient.example"][0]["source"] == "header_to"
                assert "recipient.example" not in result["scoring_iocs"]["domains"]
                assert "attachment" in headers["Content-Disposition"]
                status, body, _ = request(data=b"action=text&email_text=Hello", headers=form_headers)
                assert status == 200 and b"TRIAGE REPORT" in body
                assert request(data=b"action=json&email_text=Hello", headers=form_headers)[0] == 200
                status, _, headers = request(data=b"action=demo", headers={**form_headers, "X-Forwarded-For": "1.2.3.4"})
                assert status == 429 and 1 <= int(headers["Retry-After"]) <= 60
                assert request("/healthz")[0] == 200
                assert not (target / "tests").exists() and not (target / ".env").exists()
                assert not list(target.rglob("*.eml")), "Uploaded email was persisted"
                print(f"PASS: {len(expected)} current runtime files; {server_name}; HTTP upload, "
                      "provenance, link mismatch, exports, assets, headers and rate limit.")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
