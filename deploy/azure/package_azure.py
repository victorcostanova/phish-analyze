"""Package only reviewed runtime files; never upload the whole working directory."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    "requirements.txt",
    "phish_analyze/__init__.py", "phish_analyze/__main__.py",
    "phish_analyze/paths.py", "phish_analyze/analyzer.py",
    "phish_analyze/email_parser.py", "phish_analyze/threat_intel.py",
    "phish_analyze/evidence.py", "phish_analyze/web/rate_limit.py",
    "phish_analyze/web/__init__.py", "phish_analyze/web/__main__.py",
    "phish_analyze/web/app.py", "phish_analyze/web/templates/index.html",
    "phish_analyze/web/static/style.css",
)


def main():
    for name in FILES:
        if not (ROOT / name).is_file():
            raise SystemExit(f"Missing runtime file: {name}")
    target = ROOT / "deploy" / "azure" / "packages" / "phish-analyze.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(target, "w", compression=ZIP_DEFLATED) as archive:
        for name in FILES:
            archive.write(ROOT / name, arcname=name)
    print(f"Created {target} with {len(FILES)} runtime files.")
    print("Excluded: .env, input, reports, tests, Git metadata, virtual environments.")


if __name__ == "__main__":
    main()
