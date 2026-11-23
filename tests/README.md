# Test and validation files

This directory contains files that are not required to run the application.
You can remove it without affecting analysis of your own messages, the web
interface, or Azure packaging.

| Directory | Contents |
| --- | --- |
| `automated/` | Python regression tests |
| `samples/` | Eight demonstration messages |
| `reports/` | Historical sample reports |
| `reports/generated/` | Reports generated during recent checks |
| `temporary/previous_run/` | Baseline comparison report and an old deployment ZIP |
| `temporary/python_cache/` | Previous Python execution cache |
| `temporary/uv_cache/` | Dependency installation cache |
| `temporary/package_validation/` | Extracted deployment package used for isolated validation |
| `temporary/clean_env_v2/` | Fresh dependency environment used to validate version 2 |

`validate_deployment.py` verifies the current deployment ZIP over HTTP. It creates
and removes its own temporary extraction directory, and always stops its server.

The ZIP under `temporary/previous_run/` is historical. Generate the current
release with `python deploy/azure/package_azure.py`.

Run checks from the project root:

```powershell
.venv\Scripts\python.exe -B -m unittest discover -s tests/automated -v
.venv\Scripts\python.exe -B -m phish_analyze --offline --input-dir tests/samples --output-dir tests/reports/generated
.venv\Scripts\python.exe -B deploy/azure/package_azure.py
.venv\Scripts\python.exe -B tests/validate_deployment.py
```

If you remove this directory, optional test steps in GitHub Actions are skipped.
The application does not import files from here. `.venv/` stays in the project
root because it contains the dependencies used to run the application.
