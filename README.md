# 🔐 VAPTBot — AI-Powered VAPT Assistant

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat&logo=flask)
![Groq](https://img.shields.io/badge/Groq-LLaMA3.3-green?style=flat)
![Kali](https://img.shields.io/badge/Kali-Linux-blue?style=flat&logo=kalilinux)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)

> AI-powered terminal-style chatbot for automated Vulnerability Assessment 
> and Penetration Testing — built with Python, Flask & Groq LLM API.

---

## 🖥 Preview

![VAPTBot Screenshot](VAPTBot%20screenshot.png)

> Terminal-style hacker UI running in browser on Kali Linux
---

## ✨ Features

- 🎯 **Auto Scan** — Enter any URL / IP / Domain for instant VA report
- 📋 **Full VA Report** — Structured pentest report with real CVEs & CVSS scores
- 🔴 **Severity Ratings** — CRITICAL / HIGH / MEDIUM / LOW
- 🧭 **Guided Workflow** — Step-by-step pentest commands
- 💬 **Security Q&A** — Ask anything: SQLi, XSS, SSRF, IDOR & more
- 🛡️ **OWASP Top 10** — Full coverage with exploitation techniques
- 💻 **Hacker Terminal UI** — Professional dark theme in browser

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3 + Flask |
| AI Engine | Groq API (LLaMA 3.3 70B) |
| Scanner | Nmap + Nikto |
| Frontend | HTML + CSS + JavaScript |
| Platform | Kali Linux |

---

## 📦 Requirements

### System Requirements
- Kali Linux (recommended) or any Linux distro
- Python 3.8+
- Internet connection (for Groq API)

### Required Software & Tools

| Tool | Purpose | Install Command |
|---|---|---|
| Python 3 | Backend runtime | `sudo apt install python3` |
| pip3 | Package manager | `sudo apt install python3-pip` |
| Nmap | Port & service scanner | `sudo apt install nmap` |
| Nikto | Web vulnerability scanner | `sudo apt install nikto` |
| Git | Version control | `sudo apt install git` |

### Required Python Libraries

| Library | Purpose |
|---|---|
| flask | Web server |
| groq | AI API client |
| python-dotenv | Load API key from .env |

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository
```bash
git clone https://github.com/0xarul/vaptbot.git
cd vaptbot
```

### Step 2 — Install System Tools
```bash
sudo apt update
sudo apt install nmap nikto -y
```

### Step 3 — Install Python Dependencies
```bash
pip3 install flask groq python-dotenv --break-system-packages
```

### Step 4 — Get Free Groq API Key
1. Go to → https://console.groq.com
2. Sign up free (no credit card needed)
3. Click API Keys → Create Key
4. Copy the key (starts with gsk_...)

### Step 5 — Configure API Key
```bash
echo "GROQ_API_KEY=your_groq_api_key_here" > .env
```

### Step 6 — Run VAPTBot
```bash
python3 vaptbot.py
```

### Step 7 — Open Browser
http://localhost:5000
Browser opens automatically!

---

## 🎯 How to Use

### Scan a Target
Enter: https://example.com, 
, Enter: 192.168.1.1
, Enter: example.com

VAPTBot will:
- Run Nmap port scan
- Run Nikto web scan
- Generate full VA report with CVEs
- Show guided next steps

## 📊 Sample Report Output

### 🎯 Target Scan Mode

```
[TARGET ANALYSIS]
Target     : https://demo.testfire.net
IP Address : 65.61.137.117
Scan Type  : Web Application Scan
Risk Level : HIGH
```

```
[OPEN PORTS & SERVICES]
PORT    STATE   SERVICE    VERSION
80      OPEN    HTTP       Apache-Coyote/1.1
443     OPEN    HTTPS      Apache-Coyote/1.1
22      CLOSED  SSH        Unknown
8080    CLOSED  HTTP-ALT   Unknown
```

```
[VULNERABILITIES FOUND]

[CRITICAL] SQL Injection
CVE: CVE-2019-11043 | CVSS: 9.8
Impact: Full database compromise

[HIGH] Cross-Site Scripting (XSS)
CVE: CVE-2020-9484 | CVSS: 8.8
Impact: Session hijacking

[HIGH] Remote Code Execution
CVE: CVE-2019-0230 | CVSS: 9.8
Impact: Full system compromise

[MEDIUM] CSRF
CVE: CVE-2018-1297 | CVSS: 6.1
Impact: Unauthorized actions

[MEDIUM] IDOR
CVE: CVE-2019-10086 | CVSS: 6.5
Impact: Unauthorized data access

[LOW] SSRF
CVE: CVE-2020-13942 | CVSS: 5.3
Impact: Internal network access
```

```
[NEXT STEPS]

Step 1 - SQL Injection Test
Command : sqlmap -u "https://demo.testfire.net/login" --dbs --batch

Step 2 - XSS Testing
Command : burpsuite --scan https://demo.testfire.net

Step 3 - Directory Enumeration
Command : gobuster dir -u https://demo.testfire.net -w /usr/share/wordlists/dirb/common.txt

Step 4 - Full Vulnerability Scan
Command : nikto -h https://demo.testfire.net

Step 5 - Network Scan
Command : nmap -sV -sC -p- demo.testfire.net
```
```
[REMEDIATION]
SQL Injection : Use prepared statements and input validation
XSS           : Implement CSP headers and output encoding
RCE           : Update Apache, disable dangerous functions
CSRF          : Implement CSRF tokens and SameSite cookies
IDOR          : Implement proper access control checks
SSRF          : Whitelist allowed URLs and block internal IPs
```

```
💬 Security Q&A Mode

YOU     : How to find SQL Injection?

VAPTBOT : SQL Injection Testing Methodology

Step 1 - Manual Detection
Payload : ' OR '1'='1
Payload : ' OR 1=1--
Payload : '; DROP TABLE users--

Step 2 - Tool Based Testing
Command : sqlmap -u "http://target.com/login" --dbs --batch --level=5

Step 3 - Prevention
Use prepared statements
Input validation and sanitization
Implement WAF
CVE: CVE-2023-1234 | CVSS: 9.8 | CWE-89
```
## ⚠️ Disclaimer

This tool is for **authorized penetration testing only**.
Always obtain **written permission** before scanning any target.
The author is not responsible for any misuse of this tool.

---

## 👨‍💻 Author

**ARULKUMARAN**
- GitHub: [@0xarul](https://github.com/0xarul)
- Email: arulkumaranvelayutham@gmail.com

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
