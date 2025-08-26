# Automated Bug Bounty Recon Tool

## Overview / Theory
Automated Bug Bounty Recon Tool is a **Python-based ethical hacking project** for full-spectrum reconnaissance. It demonstrates CEH v13 practical skills and can be used for **educational or authorized penetration testing**.  

**Capabilities include:**
- Domain/IP resolution: Automatically detect IPs from a domain.
- Subdomain enumeration using Subfinder.
- Open port scanning using Nmap.
- Directory discovery using default or custom wordlists.
- SSL/TLS certificate inspection.
- HTTP headers collection.
- CMS detection (WordPress, Joomla, Drupal, etc.).
- Basic vulnerability checks (XSS, SQLi, LFI).
- Admin page discovery and email leak detection.
- Automated timestamped report generation.
- Optional screenshots of URLs using Selenium.

**Skills Demonstrated:**
- Python scripting and automation.
- Network reconnaissance.
- IP & port scanning.
- Directory brute-forcing.
- SSL/TLS & HTTP header analysis.
- CMS fingerprinting.
- Basic vulnerability scanning.
- Professional report generation.

**Important:** For **educational purposes only**. Unauthorized testing on systems you don’t own is illegal.

---

## Features
- Domain/IP Resolution
- Subdomain Enumeration
- Port Scanning
- Directory / Endpoint Checking
- SSL/TLS Info
- HTTP Headers Collection
- CMS Detection
- Basic Vulnerability Checks (XSS, SQLi, LFI)
- Admin Pages & Exposed Emails
- Automated Reporting
- Optional Screenshots (requires ChromeDriver/GeckoDriver)

---

# Usage
Run the tool:
python3 recon_tool.py -d example.com

Optional flags:
-w → Use custom wordlist:
python3 recon_tool.py -d example.com -w /usr/share/wordlists/

---

Output

Reports are saved in the reports/ folder and include:
Domain/IP resolution
Subdomains discovered
Open ports and services
Open directories/endpoints
SSL/TLS info
HTTP headers
CMS detection
Basic vulnerabilities (XSS, SQLi, LFI)
Admin pages & exposed emails
Screenshots (if enabled)
Example report: example.com_recon_report_20250826_2200.txt

...

License
This project is licensed under the MIT License. See LICENSE for details.

...

Disclaimer
This tool is intended solely for educational purposes or authorized penetration testing. Do not use it on systems you do not own or have explicit permission to test. Unauthorized usage may be illegal.

... 


## Installation
Clone the repository:
```bash
git clone https://github.com/pratikkhairnar160/Automated-Bug-Bounty-Recon-Tool.git
cd Automated-Bug-Bounty-Recon-Tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
