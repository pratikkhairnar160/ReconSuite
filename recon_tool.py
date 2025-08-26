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
    """Enumerate subdomains using Subfinder"""
    print(f"[+] Enumerating subdomains for {domain} using Subfinder...")
    os.makedirs("reports", exist_ok=True)
    output_file = f"reports/{domain}_subdomains.txt"

    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=True
        )
        subdomains = result.stdout.splitlines()
        if subdomains:
            with open(output_file, "w") as f:
                for s in subdomains:
                    f.write(f"{s}\n")
            print(f"[+] Found {len(subdomains)} subdomains. Saved to {output_file}")
        else:
            print("[-] No subdomains found.")
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"[-] Subfinder failed: {e.stderr}")
        return []
    except FileNotFoundError:
        print("[-] Subfinder not found. Make sure it is in your PATH.")
        return []

def port_scan(ip):
    """Scan common ports using Nmap"""
    if not ip:
        print("[*] No IP provided, skipping port scan.")
        return []

    print(f"[+] Scanning ports for {ip}...")
    nm = nmap.PortScanner()
    open_ports = []

    try:
        nm.scan(ip, '1-1024')
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                open_ports.extend(list(ports))
        print(f"[+] Open ports: {open_ports}")
    except Exception as e:
        print(f"[-] Nmap scan error: {e}")

    return open_ports

def check_directories(url, wordlist=None):
    """Check for open directories"""
    if not url:
        print("[*] No URL provided, skipping directory check.")
        return []

    # Use default Kali wordlist if none provided
    if not wordlist:
        wordlist = "/usr/share/wordlists/john.txt"

    if not os.path.exists(wordlist):
        print(f"[-] Wordlist {wordlist} not found, skipping directory check.")
        return []

    print(f"[+] Checking directories on {url} using wordlist {wordlist}...")
    found_dirs = []

    with open(wordlist, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            test_url = f"{url.rstrip('/')}/{line}"
            try:
                r = requests.get(test_url, timeout=3)
                if r.status_code == 200:
                    print(f"[+] Found directory: {test_url}")
                    found_dirs.append(test_url)
            except requests.RequestException:
                continue

    print(f"[+] Found {len(found_dirs)} directories.")
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
    parser.add_argument("-w", "--wordlist", required=False, help="Custom wordlist for directory checking")
    args = parser.parse_args()

    print("[*] Starting recon tool...")

    subdomains = subdomain_enum(args.domain)
    ports = port_scan(args.ip)
    directories = check_directories(args.url, args.wordlist)

    generate_report(args.domain, subdomains, ports, directories)

    print("[*] Recon tool finished.")
