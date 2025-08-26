#!/usr/bin/env python3
import argparse
import subprocess
import nmap
import requests
import os
from datetime import datetime
import shutil
import sys

# -------------------------------
# Functions
# -------------------------------

def check_tool(tool_name):
    """Check if a binary is in PATH"""
    path = shutil.which(tool_name)
    if path:
        print(f"[+] {tool_name} found at {path}")
        return True
    else:
        print(f"[-] {tool_name} not found in PATH. Install it before proceeding.")
        return False

def subdomain_enum(domain):
    """Enumerate subdomains using Subfinder"""
    if not check_tool("subfinder"):
        return []

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
            print(f"[+] Found {len(subdomains)} subdomains:")
            for s in subdomains:
                print(f"    - {s}")
            with open(output_file, "w") as f:
                for s in subdomains:
                    f.write(f"{s}\n")
            print(f"[+] Subdomains saved to {output_file}")
        else:
            print("[-] No subdomains found.")
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"[-] Subfinder error:\n{e.stderr}")
        return []
    except Exception as e:
        print(f"[-] Subfinder unexpected error: {e}")
        return []

def port_scan(ip):
    """Scan common ports using Nmap"""
    if not ip:
        print("[*] No IP provided, skipping port scan.")
        return []

    if not check_tool("nmap"):
        return []

    print(f"[+] Scanning ports for {ip} with Nmap...")
    nm = nmap.PortScanner()
    open_ports = []

    try:
        nm.scan(ip, '1-1024')
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                open_ports.extend(list(ports))
        print(f"[+] Open ports: {open_ports if open_ports else 'None found'}")
    except Exception as e:
        print(f"[-] Nmap scan error: {e}")

    return open_ports

def check_directories(url, wordlist=None):
    """Check for open directories"""
    if not url:
        print("[*] No URL provided, skipping directory check.")
        return []

    # Default John wordlist if none provided
    if not wordlist:
        wordlist = "/usr/share/wordlists/john.lst"

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
                r = requests.get(test_url, timeout=5)
                print(f"[*] Testing {test_url} -> Status: {r.status_code}")
                if r.status_code == 200:
                    print(f"[+] Found directory: {test_url}")
                    found_dirs.append(test_url)
            except requests.RequestException as e:
                print(f"[-] Request error for {test_url}: {e}")
                continue

    print(f"[+] Total directories found: {len(found_dirs)}")
    return found_dirs

def generate_report(domain, subdomains, ports, directories):
    """Generate a simple text report"""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/{domain}_recon_report_{timestamp}.txt"

    try:
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
        print(f"[+] Report successfully generated: {report_file}")
    except Exception as e:
        print(f"[-] Failed to write report: {e}")

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

    print("[*] Starting recon tool...\n")

    try:
        subdomains = subdomain_enum(args.domain)
        ports = port_scan(args.ip)
        directories = check_directories(args.url, args.wordlist)
        generate_report(args.domain, subdomains, ports, directories)
        print("\n[*] Recon tool finished successfully.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted execution.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)
