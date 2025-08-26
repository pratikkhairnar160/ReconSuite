# Automated Bug Bounty Recon Tool

## Overview
Automated Bug Bounty Recon Tool is a **Python-based ethical hacking project** for full-spectrum reconnaissance, including: domain/IP resolution, subdomain enumeration, open port scanning, directory discovery, SSL inspection, HTTP headers collection, CMS detection, and basic vulnerability checks. It generates **professional reports** and demonstrates **CEH v13 skills** in reconnaissance, scanning, and vulnerability assessment.  
**For educational and authorized testing only.**

## Features
- **Domain/IP Resolution:** Automatically detects target IPs from domain.  
- **Subdomain Enumeration:** Finds subdomains using Subfinder.  
- **Port Scanning:** Detects open ports and services via Nmap.  
- **Directory/Endpoint Checking:** Identifies open directories using default John wordlist or custom wordlists.  
- **SSL/TLS Info:** Fetches certificate details for the target.  
- **HTTP Headers Collection:** Retrieves HTTP headers for all subdomains.  
- **CMS Detection:** Detects WordPress, Joomla, Drupal, etc.  
- **Basic Vulnerability Checks:** XSS, SQLi, LFI scanning on accessible endpoints.  
- **Admin Page Discovery & Email Leak Detection:** Finds common admin pages and exposed emails.  
- **Automated Reporting:** Generates timestamped text reports in `reports/` folder.  
- **Optional Screenshots:** Captures screenshots of URLs using Selenium (requires ChromeDriver/GeckoDriver).  

## Installation
Clone the repository:
```bash
git clone https://github.com/pratikkhairnar160/Automated-Bug-Bounty-Recon-Tool.git
cd Automated-Bug-Bounty-Recon-Tool
Create and activate virtual environment:

python3 -m venv venv
source venv/bin/activate


Install required Python libraries:

pip install -r requirements.txt


Ensure the following tools are installed:

Subfinder

Nmap

(Optional for screenshots) ChromeDriver or GeckoDriver

Usage

Run the tool:

python3 recon_tool.py -d example.com


Optional flags:

-w → Use custom wordlist:

python3 recon_tool.py -d example.com -w /usr/share/wordlists/john.lst

Output

Reports are saved in reports/ folder and include:

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

Folder Structure
Automated-Bug-Bounty-Recon-Tool/
├── recon_tool.py
├── README.md
├── requirements.txt
├── reports/
└── wordlists/

Skills Demonstrated

Python scripting and automation

Subdomain enumeration & network reconnaissance

IP & port scanning

Directory brute-forcing

SSL/TLS and HTTP header analysis

CMS fingerprinting

Basic vulnerability scanning

Report generation and documentation

CEH v13 practical knowledge in ethical hacking

License

This project is licensed under the MIT License. See LICENSE for details.

Disclaimer

This tool is intended solely for educational purposes or authorized penetration testing. Do not use it on systems you do not own or have explicit permission to test. Unauthorized usage may be illegal.
