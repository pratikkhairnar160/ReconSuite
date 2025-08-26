Automated Bug Bounty Recon Tool

Overview

Automated Bug Bounty Recon Tool is a Python-based ethical hacking project for subdomain enumeration, port scanning, and directory checks. It generates professional reports and demonstrates CEH v13 skills in reconnaissance, scanning, and vulnerability assessment. For educational and authorized testing only.

Features

Subdomain Enumeration: Finds subdomains for a target domain using Sublist3r.

Port Scanning: Scans target IPs to detect open ports and services via Nmap.

Directory/Endpoint Checking: Identifies open directories using custom wordlists.

Automated Reporting: Generates text reports summarizing all findings.

Installation

Clone the repository:

https://github.com/pratikkhairnar160/Automated-Bug-Bounty-Recon-Tool.git

cd Automated-Bug-Bounty-Recon-Tool


Install required Python libraries:

pip install -r requirements.txt


Ensure the following tools are installed:

Sublist3r

Nmap

Usage

Run the tool with:

python recon_tool.py -d example.com -i 192.168.1.10 -u http://example.com


-d → Domain for subdomain enumeration

-i → Target IP for port scanning

-u → Target URL for directory checking

Output

Reports are saved in the reports/ folder.

Includes:

Subdomains discovered

Open ports and services

Open directories/endpoints

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

Port scanning & service enumeration

Directory brute-forcing using wordlists

Report generation and documentation

CEH v13 practical knowledge in ethical hacking

License

This project is licensed under the MIT License. See LICENSE for details.

Disclaimer

This tool is intended solely for educational purposes or authorized penetration testing. Do not use it on systems you do not own or have explicit permission to test. Unauthorized usage may be illegal.
