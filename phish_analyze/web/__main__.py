"""Run the local web interface with: python -m phish_analyze.web."""

from .app import app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
