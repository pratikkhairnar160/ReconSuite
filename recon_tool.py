#!/usr/bin/env python3
# Ultimate Bug Bounty Recon Tool (Fast + Threaded)
# Author: Pratik Khairnar
# Fully Updated: Subdomains, Ports, Directories, SSL, CMS, Vulns, Emails, Screenshots
# Note: Educational / authorized testing only.

import argparse
import os
import re
import sys
import ssl
import socket
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional: Selenium screenshots
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SCREENSHOT_ENABLED = True
except Exception:
    SCREENSHOT_ENABLED = False

requests.packages.urllib3.disable_warnings()

SECLISTS_COMMON_DIRS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
DEFAULT_WORDLIST = "wordlists/common_dirs.txt"

# -------------------------------
# Console helpers
# -------------------------------
def info(msg): print(f"[+] {msg}")
def warn(msg): print(f"[-] {msg}")
def note(msg): print(f"[*] {msg}")

# -------------------------------
# Environment checks
# -------------------------------
def check_tool(name):
    path = shutil.which(name)
    if path:
        info(f"{name} found at {path}")
        return True
    warn(f"{name} not found. Please install it.")
    return False

# -------------------------------
# Wordlist setup
# -------------------------------
def ensure_wordlist(path=DEFAULT_WORDLIST):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return path
    try:
        note(f"Downloading default directory wordlist to {path} ...")
        r = requests.get(SECLISTS_COMMON_DIRS_URL, timeout=15)
        r.raise_for_status()
        with open(path, "wb") as f:
            f.write(r.content)
        info("Wordlist downloaded.")
    except Exception as e:
        warn(f"Failed to download wordlist: {e}")
        with open(path, "w") as f:
            f.write("\n".join([
                "admin", "login", "administrator", "wp-admin", "cms",
                "dashboard", "config", "uploads", "images", "assets",
                "css", "js", "includes", "cgi-bin", "backup", "test",
                "dev", "staging", "api", "robots.txt", "sitemap.xml"
            ]))
        info("Wrote a small fallback wordlist.")
    return path

# -------------------------------
# DNS / IP resolution
# -------------------------------
def resolve_ip(host):
    try:
        ip = socket.gethostbyname(host)
        info(f"{host} resolved to IP: {ip}")
        return ip
    except Exception as e:
        warn(f"Failed to resolve {host}: {e}")
        return None

# -------------------------------
# Subdomain enumeration
# -------------------------------
def subdomain_enum(domain):
    if not check_tool("subfinder"):
        return []
    note(f"Enumerating subdomains for {domain} ...")
    try:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, check=True
        )
        subs = [s.strip() for s in out.stdout.splitlines() if s.strip()]
        info(f"Found {len(subs)} subdomains")
        os.makedirs("reports", exist_ok=True)
        with open(f"reports/{domain}_subdomains.txt", "w") as f:
            f.write("\n".join(subs))
        return subs
    except Exception as e:
        warn(f"Subdomain enumeration failed: {e}")
        return []

# -------------------------------
# Port scanning (nmap)
# -------------------------------
def port_scan(ip):
    if not ip: return []
    if not check_tool("nmap"): return []

    note(f"Scanning ports for {ip} ...")
    try:
        out = subprocess.run(
            ["nmap", "-sS", "-Pn", "-T4", "--top-ports", "1000", ip],
            capture_output=True, text=True, check=True
        ).stdout
        open_ports = []
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                port = int(line.split("/tcp")[0].strip())
                open_ports.append(port)
        info(f"Open ports for {ip}: {open_ports if open_ports else 'None'}")
        return open_ports
    except Exception as e:
        warn(f"Port scan failed: {e}")
        return []

# -------------------------------
# HTTP helpers
# -------------------------------
SESSION = requests.Session()
SESSION.verify = False
SESSION.headers.update({"User-Agent": "ReconTool/1.0 (+https://github.com/pratikkhairnar160)"})

def head_or_get(url, timeout=5):
    try:
        return SESSION.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

# -------------------------------
# Directory brute force
# -------------------------------
def load_wordlist(path):
    entries = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or " " in s or s.startswith("!"):
                continue
            entries.append(s)
    return entries

def dir_bruteforce(base_url, wordlist_path, threads=20):
    note(f"Checking directories on {base_url} with {threads} threads ...")
    found = []

    def probe(path):
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            r = SESSION.get(url, timeout=2)
            if r.status_code in (200, 204, 301, 302, 401, 403):
                info(f"Found: {url} [{r.status_code}]")
                return url
        except Exception:
            pass
        return None

    paths = load_wordlist(wordlist_path)
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [exe.submit(probe, p) for p in paths]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
    return found

# -------------------------------
# SSL certificate info
# -------------------------------
def fetch_ssl_info(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info(f"SSL certificate found for {host}")
                return {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "notBefore": cert['notBefore'],
                    "notAfter": cert['notAfter']
                }
    except Exception:
        warn(f"No SSL certificate for {host}")
        return None

# -------------------------------
# HTTP headers
# -------------------------------
def fetch_http_headers(url):
    r = head_or_get(url, timeout=5)
    if r is None:
        warn(f"Failed to fetch headers for {url}")
        return {}
    info(f"Fetched headers for {url}")
    return dict(r.headers)

# -------------------------------
# CMS detection
# -------------------------------
def detect_cms(url):
    r = head_or_get(url, timeout=5)
    if r is None:
        return "Unknown"
    html = r.text.lower()
    if "wp-content" in html or "wordpress" in html:
        cms = "WordPress"
    elif "drupal" in html:
        cms = "Drupal"
    elif "joomla" in html:
        cms = "Joomla"
    else:
        cms = "Unknown"
    info(f"CMS detected for {url}: {cms}")
    return cms

# -------------------------------
# Vuln scanners: XSS/SQLi/LFI
# -------------------------------
def vuln_scan(base_urls, threads=20):
    note("Starting basic vuln checks (XSS/SQLi/LFI) ...")
    findings = []
    tests = []
    for base in base_urls:
        test_url = base if '?' in base else base.rstrip('/') + '/?q='
        tests.append(("XSS", test_url, '<script>alert(1)</script>'))
        tests.append(("SQLi", test_url, "' OR '1'='1"))
        tests.append(("LFI", test_url, '../../../../etc/passwd'))

    def run_test(vtype, test_url, payload):
        try:
            r = SESSION.get(test_url + payload, timeout=3)
            body = r.text.lower()
            if vtype == "XSS" and payload.lower() in body:
                msg = f"[!] Potential XSS at {test_url}"
                info(msg)
                return msg
            if vtype == "SQLi" and any(e in body for e in ["sql syntax", "mysql", "syntax error", "unclosed quotation"]):
                msg = f"[!] Possible SQLi at {test_url}"
                info(msg)
                return msg
            if vtype == "LFI" and "root:" in body:
                msg = f"[!] LFI at {test_url}"
                info(msg)
                return msg
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [exe.submit(run_test, v, u, p) for (v, u, p) in tests]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                findings.append(res)
    return findings

# -------------------------------
# Admin page scan
# -------------------------------
def admin_scan(base_urls, threads=20):
    note("Scanning for common admin pages ...")
    paths = ["admin", "administrator", "login", "wp-admin", "cms", "dashboard", "admin/login"]
    found = []
    def probe(base, path):
        url = f"{base.rstrip('/')}/{path}"
        try:
            r = SESSION.get(url, timeout=2)
            if r.status_code in (200, 301, 302, 401, 403):
                info(f"Admin page? {url} [{r.status_code}]")
                return url
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [exe.submit(probe, b, p) for b in base_urls for p in paths]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
    return found

# -------------------------------
# Email leak scan
# -------------------------------
def email_scan(base_urls, threads=20):
    note("Scanning for exposed emails ...")
    emails = set()
    regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    def scrape(url):
        try:
            r = SESSION.get(url, timeout=3)
            return re.findall(regex, r.text)
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [exe.submit(scrape, u) for u in base_urls]
        for fut in as_completed(futures):
            for e in fut.result():
                emails.add(e)
    if emails:
        info(f"Emails found: {len(emails)}")
    return sorted(emails)

# -------------------------------
# Optional screenshot
# -------------------------------
def take_screenshot(url, outdir="reports"):
    if not SCREENSHOT_ENABLED:
        return None
    os.makedirs(outdir, exist_ok=True)
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    try:
        driver = webdriver.Chrome(options=options)
    except Exception as e:
        warn(f"Selenium/Chrome issue: {e}")
        return None
    try:
        driver.set_page_load_timeout(10)
        driver.get(url)
        fn = f"{outdir}/{urlparse(url).netloc}_screenshot.png"
        driver.save_screenshot(fn)
        info(f"Screenshot saved: {fn}")
        return fn
    except Exception as e:
        warn(f"Screenshot failed for {url}: {e}")
        return None
    finally:
        driver.quit()

# -------------------------------
# Reporting
# -------------------------------
def generate_report(domain, results):
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = f"reports/{domain}_recon_report_{ts}.txt"
    with open(report, "w") as f:
        f.write(f"Ultimate Bug Bounty Recon Report\nDomain: {domain}\nGenerated: {ts}\n\n")
        for section, value in results.items():
            f.write(f"{section}:\n")
            if isinstance(value, dict):
                for k, v in value.items():
                    f.write(f"  {k}: {v}\n")
            elif isinstance(value, list):
                for item in value:
                    f.write(f"  - {item}\n")
            else:
                f.write(f"  {value}\n")
            f.write("\n")
    info(f"Full report saved to {report}")

# -------------------------------
# Main
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="Ultimate Pro Bug Bounty Recon & Vuln Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Custom directory wordlist (default auto)")
    parser.add_argument("--threads", type=int, default=20, help="Threads for HTTP tasks (default 20)")
    parser.add_argument("--https", action="store_true", help="Also test https:// URLs where applicable")
    parser.add_argument("--no-screenshots", action="store_true", help="Disable screenshots (if Selenium present)")
    args = parser.parse_args()

    note("Starting Ultimate Pro Recon Tool...\n")

    wordlist = ensure_wordlist(args.wordlist or DEFAULT_WORDLIST)

    results = {}

    ip = resolve_ip(args.domain)
    results["Domain IP"] = ip or "Failed"

    subs = subdomain_enum(args.domain)
    results["Subdomains"] = subs

    ports = {}
    targets_for_ports = set()
    if ip:
        targets_for_ports.add(ip)
    for s in subs:
        sip = resolve_ip(s)
        if sip:
            targets_for_ports.add(sip)

    for target_ip in sorted(targets_for_ports):
        ports[target_ip] = port_scan(target_ip)
    results["Open Ports"] = ports

    hosts = [args.domain] + subs
    base_urls = [f"http://{h}" for h in hosts]
    if args.https:
        base_urls += [f"https://{h}" for h in hosts]

    directories = {}
    for h in hosts:
        for scheme in (["http"] + (["https"] if args.https else [])):
            base = f"{scheme}://{h}"
            directories[base] = dir_bruteforce(base, wordlist, threads=args.threads)
    results["Directories"] = directories

    results["SSL Info"] = fetch_ssl_info(args.domain)

    headers = {}
    for b in base_urls:
        headers[b] = fetch_http_headers(b)
    results["HTTP Headers"] = headers

    cms = {}
    for b in base_urls:
        cms[b] = detect_cms(b)
    results["CMS"] = cms

    results["Vulnerabilities"] = vuln_scan(base_urls, threads=args.threads)
    results["Admin Pages"] = admin_scan(base_urls, threads=args.threads)
    results["Exposed Emails"] = email_scan(base_urls, threads=args.threads)

    if SCREENSHOT_ENABLED and not args.no_screenshots:
        shots = {}
        for b in base_urls:
            shots[b] = take_screenshot(b)
        results["Screenshots"] = shots

    generate_report(args.domain, results)
    note("\nRecon Completed Successfully!")

if __name__ ==
