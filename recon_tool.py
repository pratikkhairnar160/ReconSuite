#!/usr/bin/env python3
import argparse
import subprocess
import nmap
import requests
import os
from datetime import datetime
import socket
import shutil
import sys
import ssl
import urllib3
import re
from urllib.parse import urlparse

# Optional screenshot
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SCREENSHOT_ENABLED = True
except ImportError:
    SCREENSHOT_ENABLED = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------------
# Helper Functions
# -------------------------------
def check_tool(tool_name):
    path = shutil.which(tool_name)
    if path:
        print(f"[+] {tool_name} found at {path}")
        return True
    else:
        print(f"[-] {tool_name} not found. Please install it.")
        return False

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] {domain} resolved to IP: {ip}")
        return ip
    except Exception as e:
        print(f"[-] Failed to resolve {domain}: {e}")
        return None

def subdomain_enum(domain):
    if not check_tool("subfinder"):
        return []

    print(f"[+] Enumerating subdomains for {domain}...")
    os.makedirs("reports", exist_ok=True)
    output_file = f"reports/{domain}_subdomains.txt"
    subdomains = []

    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, check=True
        )
        subdomains = result.stdout.splitlines()
        if subdomains:
            print(f"[+] Found {len(subdomains)} subdomains")
            with open(output_file, "w") as f:
                for s in subdomains:
                    f.write(f"{s}\n")
            print(f"[+] Subdomains saved to {output_file}")
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"[-] Subfinder error:\n{e.stderr}")
        return []
    except Exception as e:
        print(f"[-] Subfinder unexpected error: {e}")
        return []

def port_scan(ip):
    if not ip:
        return []

    if not check_tool("nmap"):
        return []

    print(f"[+] Scanning ports for {ip} (fast scan 1-1024)...")
    nm = nmap.PortScanner()
    open_ports = []

    try:
        nm.scan(ip, '1-1024', arguments='-T4 --open')  # Only open ports
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                open_ports.extend(list(ports))
        print(f"[+] Open ports for {ip}: {open_ports if open_ports else 'None found'}")
    except Exception as e:
        print(f"[-] Nmap scan error for {ip}: {e}")

    return open_ports

def check_directories(url, wordlist=None):
    if not url:
        return []

    if not wordlist:
        wordlist = "/usr/share/wordlists/common_dirs.txt"

    if not os.path.exists(wordlist):
        print(f"[-] Wordlist {wordlist} not found. Skipping directory scan.")
        return []

    print(f"[+] Checking directories on {url} using {wordlist}...")
    found_dirs = []

    with open(wordlist, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            test_url = f"{url.rstrip('/')}/{line}"
            try:
                r = requests.get(test_url, timeout=3, verify=False)
                if r.status_code == 200:
                    print(f"[+] Found directory: {test_url}")
                    found_dirs.append(test_url)
            except requests.RequestException:
                continue
    return found_dirs

def fetch_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                expire = cert['notAfter']
                print(f"[+] SSL certificate found for {domain} (expires: {expire})")
                return {"issuer": issuer, "expiry": expire}
    except Exception:
        print(f"[-] No SSL certificate for {domain}")
        return "No SSL"

def fetch_http_headers(url):
    try:
        r = requests.get(url, timeout=3, verify=False)
        headers = r.headers
        print(f"[+] Fetched headers for {url}")
        return dict(headers)
    except Exception:
        return {}

def detect_cms(url):
    cms = "Not Detected"
    try:
        r = requests.get(url, timeout=3, verify=False)
        html = r.text.lower()
        if "wp-content" in html: cms = "WordPress"
        elif "joomla" in html: cms = "Joomla"
        elif "drupal" in html: cms = "Drupal"
        print(f"[+] CMS detected for {url}: {cms}")
    except:
        pass
    return cms

def take_screenshot(url, output_dir="reports"):
    if not SCREENSHOT_ENABLED:
        return None
    os.makedirs(output_dir, exist_ok=True)
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        screenshot_file = f"{output_dir}/{urlparse(url).netloc}_screenshot.png"
        driver.save_screenshot(screenshot_file)
        print(f"[+] Screenshot saved: {screenshot_file}")
        return screenshot_file
    except Exception as e:
        print(f"[-] Screenshot failed for {url}: {e}")
        return None
    finally:
        driver.quit()

# -------------------------------
# Vulnerability Scanners
# -------------------------------
def basic_xss_scan(urls):
    print("[*] Starting XSS scan...")
    payload = "<script>alert(1)</script>"
    vulnerable = []
    for url in urls:
        if "?" in url:
            try:
                r = requests.get(url + payload, timeout=3, verify=False)
                if payload in r.text:
                    print(f"[!] XSS found: {url}")
                    vulnerable.append(url)
            except:
                continue
    return vulnerable

def basic_sqli_scan(urls):
    print("[*] Starting SQLi scan...")
    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
    vulnerable = []
    for url in urls:
        for p in payloads:
            try:
                r = requests.get(url + p, timeout=3, verify=False)
                errors = ["sql syntax", "mysql", "syntax error", "unclosed quotation"]
                if any(e in r.text.lower() for e in errors):
                    print(f"[!] Possible SQLi: {url}")
                    vulnerable.append(url)
            except:
                continue
    return vulnerable

def basic_lfi_scan(urls):
    print("[*] Starting LFI scan...")
    payloads = ["../../../../etc/passwd", "/etc/passwd"]
    vulnerable = []
    for url in urls:
        for p in payloads:
            try:
                r = requests.get(url + p, timeout=3, verify=False)
                if "root:" in r.text:
                    print(f"[!] LFI found: {url}")
                    vulnerable.append(url)
            except:
                continue
    return vulnerable

def email_leak_scan(urls):
    print("[*] Scanning for exposed emails...")
    emails = set()
    regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    for url in urls:
        try:
            r = requests.get(url, timeout=3, verify=False)
            found = re.findall(regex, r.text)
            emails.update(found)
        except:
            continue
    return list(emails)

def admin_page_scan(urls):
    print("[*] Scanning for admin pages...")
    admin_pages = ["admin", "administrator", "login", "wp-admin", "cms"]
    found_pages = []
    for url in urls:
        for page in admin_pages:
            test_url = f"{url.rstrip('/')}/{page}"
            try:
                r = requests.get(test_url, timeout=3, verify=False)
                if r.status_code == 200:
                    print(f"[+] Admin page found: {test_url}")
                    found_pages.append(test_url)
            except:
                continue
    return found_pages

# -------------------------------
# Reporting
# -------------------------------
def generate_report(domain, results):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/{domain}_recon_{timestamp}.txt"

    with open(report_file, "w") as f:
        f.write(f"Ultimate Bug Bounty Recon Report\nDomain: {domain}\nGenerated: {timestamp}\n\n")
        for key, value in results.items():
            f.write(f"{key}:\n")
            if isinstance(value, list):
                for item in value:
                    f.write(f" - {item}\n")
            elif isinstance(value, dict):
                for k, v in value.items():
                    f.write(f" {k}: {v}\n")
            else:
                f.write(f" - {value}\n")
            f.write("\n")
    print(f"[+] Full report saved to {report_file}")

# -------------------------------
# Main Execution
# -------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ultimate Bug Bounty Recon Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for directories")
    args = parser.parse_args()

    print("[*] Starting Ultimate Bug Bounty Recon Tool...\n")

    try:
        results = {}
        domain_ip = resolve_ip(args.domain)
        results["Domain IP"] = domain_ip if domain_ip else "Failed"

        subdomains = subdomain_enum(args.domain)
        results["Subdomains"] = subdomains

        # Ports
        ports_dict = {}
        if domain_ip:
            ports_dict[domain_ip] = port_scan(domain_ip)
        for sub in subdomains:
            sub_ip = resolve_ip(sub)
            if sub_ip:
                ports_dict[sub_ip] = port_scan(sub_ip)
        results["Open Ports"] = ports_dict

        # Directories
        all_targets = [args.domain] + subdomains
        directories_dict = {}
        for t in all_targets:
            url = f"http://{t}"
            directories_dict[url] = check_directories(url, args.wordlist)
        results["Directories"] = directories_dict

        # SSL
        results["SSL Info"] = fetch_ssl_info(args.domain)

        # HTTP headers
        http_dict = {}
        for t in all_targets:
            url = f"http://{t}"
            http_dict[url] = fetch_http_headers(url)
        results["HTTP Headers"] = http_dict

        # CMS detection
        cms_dict = {}
        for t in all_targets:
            url = f"http://{t}"
            cms_dict[url] = detect_cms(url)
        results["CMS"] = cms_dict

        # Optional screenshot
        if SCREENSHOT_ENABLED:
            screenshot_dict = {}
            for t in all_targets:
                url = f"http://{t}"
                screenshot_dict[url] = take_screenshot(url)
            results["Screenshots"] = screenshot_dict

        # Vulnerability Scans
        vuln_dict = {}
        urls_to_test = [f"http://{d}" for d in all_targets]
        vuln_dict["XSS"] = basic_xss_scan(urls_to_test)
        vuln_dict["SQLi"] = basic_sqli_scan(urls_to_test)
        vuln_dict["LFI"] = basic_lfi_scan(urls_to_test)
        vuln_dict["Exposed Emails"] = email_leak_scan(urls_to_test)
        vuln_dict["Admin Pages"] = admin_page_scan(urls_to_test)
        results["Vulnerabilities"] = vuln_dict

        # Generate report
        generate_report(args.domain, results)

        print("\n[*] Recon Tool Finished Successfully!")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
