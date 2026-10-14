# Phishing Analyzer — IOC Extraction & Threat Intelligence Tool

**Author: Victor Costa Nova**

A Python-based command-line tool that automates phishing email analysis by extracting
Indicators of Compromise (IOCs) and querying them against real threat intelligence APIs.
Built as part of a personal cybersecurity portfolio to simulate SOC analyst workflows.

## What It Does

- Parses phishing email samples (.txt / .eml) and extracts:
  - Malicious URLs
  - Suspicious domains
  - IP addresses
  - Sender/recipient email addresses
- Queries extracted domains against **VirusTotal**
- Queries extracted IPs against **AbuseIPDB**
- Generates a structured threat report per sample, saved to the `reports/` folder

## Sample Output

```plaintext
=======================================================
PHISHING ANALYSIS REPORT

Sample  : s03.txt
  Verdict : HIGH RISK (score: 100)
  URLs    : 2
  Domains : 4
  IPs     : 1
  Emails  : 3

[ CONCLUSION ]

  Key signals:
  - Domain flagged suspicious by VirusTotal: login-microsoft-secure.tk
  - Domain flagged malicious by 4 VirusTotal engines: micros0ft-account.com
  - IP has high abuse score (100%) on AbuseIPDB: 107.189.1.175
  - Social-engineering language present (6 keyword hits)
  - Possible brand-impersonation domain: login-microsoft-secure.tk
  - Possible brand-impersonation domain: micros0ft-account-verify.net
  - Possible brand-impersonation domain: micros0ft-account.com

  Recommended actions:
  - Do not click links or open attachments
  - Quarantine the message and report as phishing
  - Block listed domains/IPs in email/web controls (if confirmed malicious)

[ DOMAIN ANALYSIS — VirusTotal ]

  Domain  : login-microsoft-secure.tk
  Verdict : 🟡 SUSPICIOUS
  Malicious  : 0 engines
  Suspicious : 2 engines
  Harmless   : 54 engines

  Domain  : micros0ft-account-verify.net
  Verdict : 🟢 CLEAN
  Malicious  : 0 engines
  Suspicious : 0 engines
  Harmless   : 0 engines

  Domain  : micros0ft-account.com
  Verdict : 🔴 MALICIOUS
  Malicious  : 4 engines
  Suspicious : 1 engines
  Harmless   : 51 engines

  Domain  : outlook.com
  Verdict : 🟢 TRUSTED (known legitimate)
  Malicious  : 1 engines
  Suspicious : 0 engines
  Harmless   : 64 engines

[ IP ANALYSIS — AbuseIPDB ]

  IP      : 107.189.1.175
  Verdict : 🔴 MALICIOUS
  Abuse Score   : 100%
  Total Reports : 139
  Country       : CH
  ISP           : BuyVM

[ SENDER / RECIPIENT EMAILS ]

  no-reply@micros0ft-account.com
  victim@outlook.com
  account-security@micros0ft-account.com
```

Reputation counts and verdicts can change as VirusTotal and AbuseIPDB data is updated.

## Project Structure

```plaintext
phishing-analyzer/
├── samples/          # Phishing email samples (.txt / .eml)
├── reports/          # Generated analysis reports
├── analyzer.py       # Main script
├── requirements.txt  # Dependencies
├── .env              # API keys (never committed)
└── .gitignore        # Excludes .env and cache files
```

## Key Concepts Demonstrated

- **IOC Extraction** — automated identification of threat indicators from unstructured text
- **Threat Intelligence Integration** — real-time reputation checks via industry-standard APIs
- **Rate Limit Handling** — respects API constraints with controlled request timing
- **Private IP Filtering** — skips RFC 1918 addresses to avoid unnecessary API calls
- **Structured Reporting** — output mirrors real SOC incident documentation format

## Setup & Usage

**1. Clone the repository**

```bash
git clone https://github.com/victorcostanova/phish-analyze.git
cd phish-analyze
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Add your API keys**

Create a `.env` file in the root folder:

## Project Structure

```plaintext
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Free API keys available at:

- https://www.virustotal.com
- https://www.abuseipdb.com

**4. Add email samples**

Place `.txt` or `.eml` phishing email files in the `samples/` folder.

**5. Run the analyzer**

```bash
# Analyze all .txt and .eml files in samples/
python3 analyzer.py

# Analyze one file; save to reports/s05_report.txt by default
python3 analyzer.py samples/s05.txt

# Analyze one file and choose the output directory; filename is generated automatically
python3 analyzer.py samples/s05.txt reports/
```

Reports for a batch run are saved automatically to the `reports/` folder. For a
single-file run, the optional second argument can be an output directory (the
report filename is generated automatically) or an explicit report file path.
The output directory is created automatically if needed.
