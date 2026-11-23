# Phish Analyze

**Author: Victor Costa Nova**

A passive email-triage tool with a command-line interface, a Flask website,
indicator extraction, header inspection, attachment hashes, and text/JSON reports.

This version traces each indicator to its message location and compares displayed
HTML link domains with their actual targets. The web demo limits processing to
30 submissions per minute across all visitors.

## Project structure

```text
phish-analyze/
|-- phish_analyze/             # Application source code
|   |-- __init__.py           # Declares the Python package
|   |-- __main__.py           # Command-line entry point
|   |-- analyzer.py           # Analysis, scoring, and reporting
|   |-- email_parser.py       # Email parsing and indicator extraction
|   |-- evidence.py           # Indicator origins and disguised-link detection
|   |-- threat_intel.py       # Optional reputation API integration
|   |-- paths.py              # Input, output, and configuration paths
|   `-- web/                  # Flask web interface
|       |-- __init__.py       # Declares the web package
|       |-- __main__.py       # Local server entry point
|       |-- app.py            # Routes and request handling
|       |-- rate_limit.py     # Thread-safe admission limit for the public demo
|       |-- templates/        # HTML pages
|       `-- static/           # CSS styles
|-- input/                    # Your .txt and .eml files to analyze
|-- reports/                  # Reports from everyday use
|-- deploy/azure/             # Azure deployment preparation
|   |-- package_azure.py      # Creates the deployment ZIP
|   `-- packages/             # Generated ZIP, ignored by Git
|-- docs/                     # Detailed documentation
|   |-- USAGE.md              # Features, options, and limitations
|   |-- AZURE.md              # Deployment instructions
|   `-- ROADMAP.md            # Future improvements and interview walkthrough
|-- tests/                    # Optional material; removable after validation
|   |-- automated/            # Regression tests
|   |-- validate_deployment.py # Isolated HTTP checks against the deployment ZIP
|   |-- samples/              # Sample email messages
|   |-- reports/              # Historical and validation results
|   `-- temporary/            # Caches and previous validation artifacts
|-- .github/workflows/        # GitHub automation
|-- .venv/                    # Local Python environment and dependencies
|-- .env                      # Your API keys, ignored by Git
|-- .gitignore                # Files excluded from version control
`-- requirements.txt          # Application dependencies
```

## What the Python support files do

`.venv/` is a virtual environment created by Python tooling. It isolates this
project's dependencies from other projects. On Windows it contains:

- `Scripts/`: the Python executable, command-line tools, and activation scripts.
  `activate.bat` activates the environment in Command Prompt; `Activate.ps1`
  does so in PowerShell. `activate_this.py` supports activation inside an
  existing Python process and is not used by this application's normal commands.
- `Lib/site-packages/`: installed third-party libraries, including Flask,
  Requests, python-dotenv, and their dependencies.
- `pyvenv.cfg`: information about the Python installation used by the environment.
- Tool-generated files such as `.gitignore`, `.lock`, and `CACHEDIR.TAG`.

Activation is optional when using `.venv\Scripts\python.exe` directly. The
application does not own the library files inside `.venv/`; reinstall dependencies
from `requirements.txt` when recreating the environment. The environment is
ignored by Git and excluded from the deployment ZIP.

`__init__.py` marks a directory as a regular Python package. These files only
need descriptive text here; they do not need executable statements. Keeping
package markers makes the package structure explicit.

`__main__.py` is executable: Python runs it when you use `python -m` with the
package name. The top-level file calls the analyzer, while the file under `web/`
starts the local server. Both support the commands below and are retained.

The hidden `.git/` directory stores repository history.

## Run the application

Run these commands from the repository root:

```powershell
# Initial setup if the environment does not exist yet
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

# Web interface: open http://127.0.0.1:8000
.venv\Scripts\python.exe -m phish_analyze.web

# Analyze all messages placed in input/
.venv\Scripts\python.exe -m phish_analyze --offline

# Analyze one file and write JSON to reports/
.venv\Scripts\python.exe -m phish_analyze input/message.eml --format json
```

`input/` starts empty. You can also supply a file from another directory, select
an input folder with `--input-dir`, or choose a report folder with `--output-dir`.
The old `python analyzer.py` and `python app.py` commands have been replaced by
the module commands above.

Analysis is **offline by default**. For external lookups, configure `.env` in the
project root and use `--enrich`. The application does not visit extracted links
or execute attachments. A low score does not establish that a message is safe.

## Tests and disposable files

All test material lives in [`tests/`](tests/README.md). Removing this directory
does not affect analysis of your own messages, the web application, or deployment
packaging. The built-in web example continues to work.

```powershell
.venv\Scripts\python.exe -B -m unittest discover -s tests/automated -v
.venv\Scripts\python.exe -B -m phish_analyze --offline --input-dir tests/samples --output-dir tests/reports/generated
```

## Deployment and documentation

Generate an up-to-date Azure package:

```powershell
.venv\Scripts\python.exe deploy/azure/package_azure.py
.venv\Scripts\python.exe -B tests/validate_deployment.py
```

The result is `deploy/azure/packages/phish-analyze.zip`. It excludes credentials,
tests, input messages, and reports. The Gunicorn entry point is
`phish_analyze.web.app:app`.

The deployment check extracts the ZIP into a temporary directory, starts a local
server, and tests uploads, evidence, report exports, security headers, and HTTP
429 responses. It uses Gunicorn on Linux and a WSGI test server on Windows. Its
temporary directory and server are cleaned up automatically. GitHub Actions
includes this check on Linux; running it locally on Windows does not validate
Gunicorn or an actual Azure deployment.

## Evidence and rate-limit behavior

- Each indicator includes its sources: sender, recipient, reply address, mail
  relay, body, displayed link text, target URL, or HTML resource. These are parsed
  locations, not authenticated identities.
- Recipient, relay, authentication-header, and displayed-link-only indicators
  remain visible as context. They do not trigger reputation lookups or indicator
  risk rules unless also found in an eligible location.
- HTML links receive `same_host`, `same_site`, `mismatch`, or `not_compared`.
  Comparisons use an offline bundled Public Suffix List, including private hosting
  suffixes. Tracking services can cause legitimate mismatches. Relative URLs,
  ambiguous targets, and labels without a recognizable hostname are not compared.
- A mismatch adds 25 points once per message. Same-site results never establish
  safety. No redirects are followed and CSS visibility is not evaluated.
- JSON reports now use `schema_version: 2`, preserving `iocs` and adding
  `indicator_sources`, `scoring_iocs`, and `links`. Attachment metadata includes
  its MIME part index. Text and web reports show defanged evidence.
- All analysis, sample, and export POSTs share a sliding 60-second budget. The
  default is 30; set the **process environment variable** `ANALYSIS_RATE_LIMIT`
  (1..1000) before startup to change it. The web server does not load `.env`.
  Rejected requests receive HTTP 429 and `Retry-After` before their uploads are
  parsed. GET requests and `/healthz` do not consume the budget.

Deploy this in-memory limiter with **one Gunicorn worker and one instance**.
Threads share the budget, but separate processes do not. Restarting the process
resets it. Multiple instances need a shared limiter or an ingress service. It is
a demo resource limit, not a DDoS protection service or a per-user fair-use system.

- [Usage and limitations](docs/USAGE.md)
- [Azure deployment](docs/AZURE.md)
- [Future improvements and interview walkthrough](docs/ROADMAP.md)
