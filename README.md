# Phish Analyze

**Author: Victor Costa Nova**

A passive email-triage tool with a command-line interface, a Flask website,
indicator extraction, header inspection, attachment hashes, and text/JSON reports.

## Project structure

```text
phish-analyze/
|-- phish_analyze/             # Application source code
|   |-- __init__.py           # Declares the Python package
|   |-- __main__.py           # Command-line entry point
|   |-- analyzer.py           # Analysis, scoring, and reporting
|   |-- email_parser.py       # Email parsing and indicator extraction
|   |-- threat_intel.py       # Optional reputation API integration
|   |-- paths.py              # Input, output, and configuration paths
|   `-- web/                  # Flask web interface
|       |-- __init__.py       # Declares the web package
|       |-- __main__.py       # Local server entry point
|       |-- app.py            # Routes and request handling
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
```

The result is `deploy/azure/packages/phish-analyze.zip`. It excludes credentials,
tests, input messages, and reports. The Gunicorn entry point is
`phish_analyze.web.app:app`.

- [Usage and limitations](docs/USAGE.md)
- [Azure deployment](docs/AZURE.md)
- [Future improvements and interview walkthrough](docs/ROADMAP.md)
