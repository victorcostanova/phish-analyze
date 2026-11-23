"""Stateless, offline demo. Gunicorn entry point: phish_analyze.web.app:app."""

import io
import json
import os
from pathlib import Path

from flask import Flask, Request, Response, render_template, request

from ..analyzer import analyze_bytes, generate_report
from ..email_parser import MAX_INPUT_BYTES, defang
from .rate_limit import AnalysisRateLimiter


class MemoryRequest(Request):
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        # Flask normally spools large uploads to disk. Keep this bounded demo in memory.
        return io.BytesIO()


app = Flask(__name__)
app.request_class = MemoryRequest
app.config.update(MAX_CONTENT_LENGTH=MAX_INPUT_BYTES + 65536,
                  MAX_FORM_MEMORY_SIZE=MAX_INPUT_BYTES + 65536, MAX_FORM_PARTS=10)
app.jinja_env.filters["defang"] = defang
app.extensions["analysis_rate_limiter"] = AnalysisRateLimiter(
    limit=int(os.getenv("ANALYSIS_RATE_LIMIT", "30")))

DEMO = """From: Microsoft Security <notice@micros0ft-support.example>
To: analyst@example.org
Reply-To: help@response.example.net
Subject: Urgent: verify your account
Content-Type: text/html; charset=utf-8

<p>Your account is suspended. Verify your password immediately:</p>
<a href="https://microsoft.com@micros0ft-support.example/Reset?token=AbC">https://microsoft.com</a>
"""


@app.before_request
def limit_analysis_requests():
    # Reject before request.form/files parses an upload. All analysis, demo and
    # export submissions share the budget; forwarded IP headers cannot bypass it.
    if request.method == "POST" and request.path == "/":
        retry_after = app.extensions["analysis_rate_limiter"].admit()
        if retry_after:
            response = app.make_response((render_template(
                "index.html", text="", result=None,
                error=f"Analysis limit reached. Try again in {retry_after} seconds."), 429))
            response.headers["Retry-After"] = str(retry_after)
            return response


@app.context_processor
def rate_limit_context():
    return {"analysis_limit": app.extensions["analysis_rate_limiter"].limit}


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.route("/", methods=["GET", "POST"])
def index():
    text, result, error = "", None, None
    status = 200
    if request.method == "POST":
        action = request.form.get("action", "analyze")
        text = request.form.get("email_text", "")
        upload = request.files.get("email_file")
        try:
            if action == "demo":
                text, filename = DEMO, "training-demo.eml"
                raw = text.encode("utf-8")
            elif upload and upload.filename:
                filename = Path(upload.filename.replace("\\", "/")).name
                if Path(filename).suffix.lower() not in {".eml", ".txt"}:
                    raise ValueError("Choose a .eml or .txt file.")
                raw = upload.stream.read(MAX_INPUT_BYTES + 1)
                # Keep the form free of decoded binary or attachment data after uploads.
                text = ""
            else:
                filename, raw = "pasted-email.txt", text.encode("utf-8")
            result = analyze_bytes(raw, filename=filename)
            if action in {"json", "text"}:
                is_json = action == "json"
                body = json.dumps(result, indent=2, ensure_ascii=False) if is_json else generate_report(result)
                response = Response(body, mimetype="application/json" if is_json else "text/plain")
                response.headers["Content-Disposition"] = f'attachment; filename="phish-report.{"json" if is_json else "txt"}"'
                return response
        except ValueError as exc:
            error, status = str(exc), 400
    return render_template("index.html", text=text, result=result, error=error), status


@app.errorhandler(413)
def too_large(error):
    return render_template("index.html", text="", result=None,
                           error="Request too large. Choose a sample under 1 MiB."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
