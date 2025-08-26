#!/usr/bin/env python3
import argparse
import subprocess
import nmap
import requests
import os
from datetime import datetime

# -------------------------------
# Functions
# -------------------------------

def subdomain_enum(domain):
    """Enumerate subdomains using Sublist3r (must be installed)"""
    print(f"[+] Enumerating subdomains for {domain}...")
    os.makedirs("reports", exist_ok=True)
    output_file = f"reports/{domain}_subdomains.txt"
    try:
        subprocess.run(["sublist3r", "-d", domain, "-o", output_file], check=True)
        print(f"[+] Subdomains saved to {output_file}")
    except Exception as e:
        print(f"[-] Sublist3r error: {e}")
        return []
    with open(output_file, "r") as f:
        subdomains = [line.strip() for line in f.readlines()]
    return subdomains

def port_scan(ip):
    """Scan common ports using Nmap"""
    if not ip:
        return []
    print(f"[+] Scanning ports for {ip}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1000')
    except Exception as e:
        print(f"[-] Nmap scan error: {e}")
        return []
    open_ports = []
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            ports = nm[ip][proto].keys()
            open_ports.extend(list(ports))
    print(f"[+] Open ports: {open_ports}")
    return open_ports

def check_directories(url, wordlist="wordlists/common_dirs.txt"):
    """Check for open directories"""
    if not url:
        return []
    print(f"[+] Checking directories on {url}...")
    found_dirs = []
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist {wordlist} not found")
        return found_dirs
    with open(wordlist, "r") as f:
        for line in f:
            test_url = f"{url.rstrip('/')}/{line.strip()}"
            try:
                r = requests.get(test_url, timeout=3)
                if r.status_code == 200:
                    print(f"[+] Found directory: {test_url}")
                    found_dirs.append(test_url)
            except requests.RequestException:
                continue
    return found_dirs

def generate_report(domain, subdomains, ports, directories):
    """Generate a simple text report"""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/{domain}_recon_report_{timestamp}.txt"
    with open(report_file, "w") as f:
        f.write(f"Bug Bounty Recon Report\nDomain: {domain}\n\n")
        f.write("Subdomains:\n")
        for s in subdomains:
            f.write(f" - {s}\n")
        f.write("\nOpen Ports:\n")
        for p in ports:
            f.write(f" - {p}\n")
        f.write("\nOpen Directories:\n")
        for d in directories:
            f.write(f" - {d}\n")
    print(f"[+] Report generated: {report_file}")

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Bug Bounty Recon Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-i", "--ip", required=False, help="Target IP for port scanning")
    parser.add_argument("-u", "--url", required=False, help="Target URL for directory checking")
    args = parser.parse_args()

    subdomains = subdomain_enum(args.domain)
    ports = port_scan(args.ip)
    directories = check_directories(args.url)

    generate_report(args.domain, subdomains, ports, directories)

