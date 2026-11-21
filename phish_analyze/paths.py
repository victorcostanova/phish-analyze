"""Project paths independent of the current working directory."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = PROJECT_ROOT / "input"
REPORTS_DIR = PROJECT_ROOT / "reports"
ENV_FILE = PROJECT_ROOT / ".env"
