# Messages to analyze

Place your `.txt` or `.eml` files here and run this command from the project root:

```powershell
.venv\Scripts\python.exe -m phish_analyze --offline
```

Reports are written to `reports/`. Files in this directory are ignored by Git,
except for this guide. Demonstration messages live in `tests/samples/`.
