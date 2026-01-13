<div align="center">

# 🐟 CarapauCracker

```
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
```

**The Ultimate Penetration Testing Framework for CTF & Professional Pentesting** 🏆

*Intelligent automation for security testing in controlled environments* 🔒

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Educational%20Only-red)](README.md#-legal-disclaimer)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)](README.md)

[Features](#-key-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[CTF Mode](#-ctf-mode) •
[Documentation](#-documentation) •
[Legal Notice](#-legal-disclaimer)

</div>

---

## 📋 About the Project

**CarapauCracker** is a comprehensive, modular penetration testing framework designed for **CTF competitions** and **professional pentesting**. Built entirely in Python, it automates and centralizes critical phases of security testing, making it the perfect tool for both beginners and experienced security professionals.

### 🎯 Why CarapauCracker?

- 🏆 **CTF-Optimized**: Built specifically for speed and efficiency in CTF competitions
- 🔧 **All-in-One**: Everything you need in a single, unified interface
- 🚀 **Fast & Automated**: Reduces manual work and speeds up testing
- 📊 **Professional Reports**: Generate comprehensive reports automatically
- 🎨 **Beautiful UI**: Rich terminal interface with colors and formatting
- 🔒 **Secure by Design**: Input validation, sanitization, and security best practices

### 🎯 Core Objectives

- ✅ **Automation**: Reduce repetitive tasks during pentests
- ✅ **Centralization**: Unify multiple tools in a single interface
- ✅ **Documentation**: Automatically generate professional reports
- ✅ **Modularity**: Extensible and easy-to-maintain architecture
- ✅ **Education**: Learning tool for pentesting techniques
- ✅ **CTF Ready**: Optimized for competitive security testing

---

## ✨ Key Features

### 🔍 **1. Advanced Reconnaissance**

- ✓ Host availability verification (ICMP ping) - **Multi-platform support**
- ✓ Automatic reverse DNS lookup
- ✓ WHOIS integration for registration information
- ✓ GeoIP location via external API
- ✓ Multi-protocol banner grabbing (FTP, SSH, HTTP)
- ✓ **Input validation and sanitization**

### 🔎 **2. Network & System Scanning**

- **Quick Scan**: Rapid identification of common ports (CTF-optimized)
- **Detailed Scan**: Version detection and NSE scripts (`-sV -sC`)
- **Full TCP Scan**: Complete analysis of all 65535 ports
- **UDP Scan**: Scanning of the 50 most common UDP ports
- **OS Detection**: Operating system fingerprinting
- **Aggressive Scan**: Aggressive mode with all techniques (`-A`)
- **CVE Detection**: Automatic CVE checking via NVD API

### 🌐 **3. Complete Web Enumeration**

| Tool | Function |
|------------|--------|
| **HTTP Analysis** | Header and configuration analysis |
| **WhatWeb** | Technology and framework identification |
| **Nikto** | Deep web vulnerability scanning |
| **Gobuster** | Efficient directory/file brute-forcing |
| **FFUF** | High-performance fuzzing |
| **Nmap NSE** | Specialized HTTP scripts |
| **SSLScan** | Detailed SSL/TLS analysis |

### 💣 **4. Exploit Discovery & Auto-Exploitation**

- 🔎 Integration with **SearchSploit** (Exploit-DB)
- 🎯 Intelligent classification by severity (RCE, Auth Bypass, LPE, DoS)
- ⚡ Exploit ranking system by priority
- 🤖 **Auto-exploitation analysis** - Identifies exploitation opportunities
- 📊 **Exploitation plan generation** - Prioritized attack vectors

### 🔑 **5. Credential Attacks (Hydra)**

- 🔓 SSH brute-force
- 🔓 FTP authentication testing
- 🔓 HTTP Basic Auth cracking
- 🔓 HTTP POST form attacks
- 📝 Support for custom wordlists
- ⚡ Quick testing of known/default credentials

### 💣 **6. Payload Generator** 🆕

**Essential for CTF and exploitation:**

- 🐚 **Reverse Shells**: Bash, Python, Perl, PHP, Netcat, PowerShell
- 🌐 **Web Shells**: PHP, JSP, ASP
- 💉 **SQL Injection**: Union, Boolean, Time-based, Error-based
- ⚠️ **XSS Payloads**: HTML, Attribute, Script contexts
- 🔧 **Command Injection**: Multiple techniques
- 🔐 **Encoding Tools**: Base64, URL, Hex, Unicode

### 🏆 **7. CTF Mode** 🆕

**Quick access to essential CTF tools:**

- ⚡ **Quick Scan**: Fast common port scanning
- 🔌 **Reverse Shell Listener**: Interactive listener
- 🔄 **Encode/Decode Tools**: Base64, Hex, URL, ROT13, Caesar
- 🔍 **Hash Identifier**: Automatic hash type detection
- 📚 **CTF Cheatsheet**: Quick reference guide
- 📝 **Wordlist Generator**: Generate wordlists from files

### 📄 **8. Professional Reporting System**

- 📝 Unified and structured TXT report
- 📄 Automatic export to professional **PDF** (filtered sections)
- 🗂️ Export to **JSON** with structured data
- 📊 **Executive Summary**: Highlights and recommendations
- 🕐 Detailed logging with timestamps and levels
- 🗃️ Organization by sessions and targets

### 🔒 **9. Security & Quality Features** 🆕

- ✅ **Input Validation**: IP, hostname, port validation
- ✅ **Input Sanitization**: Prevents command injection
- ✅ **Multi-platform**: Windows and Linux support
- ✅ **Error Handling**: Robust exception handling
- ✅ **Type Hints**: Complete type annotations
- ✅ **Structured Logging**: Timestamps and log levels
- ✅ **Configuration System**: Centralized config management

---

## 🛠️ Requirements

### Operating System

- **Linux** (Kali Linux, Parrot OS, Ubuntu, Debian) - ✅ Fully supported
- **Windows** (10/11) - ✅ Supported with platform-specific commands
- **Python 3.8+**

### External Tools

The following tools must be installed on the system:

```bash
# Core Tools
nmap, masscan, whois, dig

# Web Enumeration
nikto, gobuster, ffuf, whatweb, sslscan

# Exploitation
searchsploit (exploitdb)

# Brute Force
hydra

# Utilities
curl, wget
```

### Python Dependencies

```bash
colorama>=0.4.6
reportlab>=3.6.0
requests>=2.31.0
fpdf>=2.5.0
rich>=13.0.0
python-dotenv>=1.0.0
```

---

## 📦 Installation

### Method 1: Automatic Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/HungerBalls/CarapauCracker.git
cd CarapauCracker

# 2. Run the installation script
chmod +x install.sh
sudo ./install.sh

# 3. Start the framework
python3 main.py
```

### Method 2: Manual Installation

```bash
# 1. Clone the repository
git clone https://github.com/HungerBalls/CarapauCracker.git
cd CarapauCracker

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Install external tools (example for Debian/Ubuntu)
sudo apt update
sudo apt install nmap nikto hydra gobuster ffuf whatweb \
                 exploitdb sslscan masscan \
                 whois dnsutils curl wget -y

# 4. Create necessary directories
mkdir -p outputs wordlists

# 5. (Optional) Configure .env file
cp .env.example .env
# Edit .env and add your NVD_API_KEY for faster CVE checks

# 6. Run
python3 main.py
```

---

## 🚀 Quick Start

### Basic Usage

```bash
python3 main.py
```

### Typical Workflow

```
1. Enter target (IP or hostname)
   └─> Automatic connectivity check and validation

2. Main Menu - Choose module: 
   ├─> 1. Basic Reconnaissance
   │   └─> WHOIS, GeoIP, DNS, Banner Grabbing
   │
   ├─> 2. Port & System Scanning
   │   └─> Quick/Detailed/Full TCP/UDP/OS Detection
   │
   ├─> 3. Advanced Web Enumeration
   │   └─> Headers, WhatWeb, Nikto, Gobuster, FFUF
   │
   ├─> 4. Automated Exploitation (Searchsploit)
   │   └─> Search exploits, ranking, auto-analysis
   │
   ├─> 5. Brute Force Attacks (Hydra)
   │   └─> SSH, FTP, HTTP (Hydra)
   │
   ├─> 6. Payload Generator 💣
   │   └─> Reverse shells, Web shells, SQLi, XSS
   │
   ├─> 7. CTF Mode 🏆
   │   └─> Quick tools, listener, encoding, cheatsheet
   │
   └─> 8. Export Final Report 📄
       └─> PDF, JSON, Executive Summary

3. Results saved in:
   outputs/<target>/<timestamp>/
```

### Example Session

```bash
$ python3 main.py

[🎯] Enter target IP or hostname: 192.168.1.100
[✔] Session created at: outputs/192.168.1.100/20260108_143022

╭────────────[ MAIN MENU - CARAPAUPANEL ]────────────╮
│ 1 - Basic Reconnaissance
│ 2 - Port & System Scanning
│ 3 - Advanced Web Enumeration
│ 4 - Automated Exploitation (Searchsploit)
│ 5 - Brute Force Attacks (Hydra)
│ 6 - Payload Generator 💣
│ 7 - CTF Mode 🏆
│ 8 - Export Final Report 📄
│ 0 - Exit Session ⛔
╰──────────────────────────────────────────────────────────╯

[»] Choose your module: 7
```

---

## 🏆 CTF Mode

**Optimized workflow for CTF competitions:**

### Quick CTF Workflow

1. **Quick Scan** (Menu 7 → Option 1)
   - Fast common port scanning
   - Optimized for speed

2. **Generate Payloads** (Menu 6)
   - Reverse shells for your IP
   - SQL injection payloads
   - XSS payloads

3. **Start Listener** (Menu 7 → Option 2)
   - Interactive reverse shell listener
   - Real-time command execution

4. **Encode/Decode** (Menu 7 → Option 3)
   - Quick encoding/decoding
   - Base64, Hex, URL, ROT13

5. **Hash Identification** (Menu 7 → Option 4)
   - Automatic hash type detection
   - Tool suggestions

### CTF Cheatsheet

Access the built-in CTF cheatsheet for quick reference:
```
Menu → 7 (CTF Mode) → 5 (CTF Cheatsheet)
```

---

## 📁 Project Structure

```
CarapauCracker/
├── main.py                 # Main entry point
├── install.sh              # Automatic installation script
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variables template
│
├── modules/                # Functional modules
│   ├── config.py          # Configuration management 🆕
│   ├── recon.py           # Reconnaissance (WHOIS, DNS, GeoIP)
│   ├── scan.py            # Port scanning (Nmap, Masscan)
│   ├── web_enum.py        # Web enumeration (Nikto, Gobuster, FFUF)
│   ├── exploit.py         # Exploit discovery (SearchSploit)
│   ├── exploit_ranker.py  # Exploit ranking system
│   ├── auto_exploit.py    # Auto-exploitation analysis 🆕
│   ├── brute_force.py     # Credential attacks (Hydra)
│   ├── payloads.py        # Payload generator 🆕
│   ├── listener.py        # Reverse shell listener 🆕
│   ├── ctf_helpers.py     # CTF helper functions 🆕
│   ├── cve_checker.py     # CVE vulnerability checking
│   ├── report.py          # Report generation (PDF, JSON)
│   ├── utils.py           # Utilities (logging, execution, banner)
│   ├── progress.py         # Progress bars 🆕
│   ├── cache.py           # Result caching 🆕
│   └── stats.py           # Session statistics 🆕
│
├── menus/                  # Interactive menus
│   ├── menu_recon.py
│   ├── menu_scan.py
│   ├── menu_web_enum.py
│   ├── menu_exploit.py
│   ├── menu_brute.py
│   ├── menu_payloads.py   # Payload generator menu 🆕
│   └── menu_ctf.py        # CTF mode menu 🆕
│
├── wordlists/              # Wordlists for fuzzing and brute-force
│   ├── users.txt.txt
│   └── rockyou.txt.txt
│
└── outputs/                # Session results
    └── <target>/
        └── <timestamp>/
            ├── report.txt
            ├── report_filtered.pdf
            ├── report_filtered.json
            ├── executive_summary.txt
            └── session.log
```

---

## 🔧 Available Modules

### 1️⃣ Reconnaissance Module (`modules/recon.py`)

```python
# Main functions
whois_lookup(target)      # WHOIS information
geoip_lookup(target)      # IP geolocation
reverse_dns(target)       # Reverse DNS
banner_grab(ip, port)     # Banner grabbing
basic_recon(target)       # Complete reconnaissance
```

### 2️⃣ Scanning Module (`modules/scan.py`)

```python
quick_scan(target)        # Top 1000 ports
detailed_scan(target)     # Version detection + NSE
full_tcp_scan(target)     # All TCP ports
udp_scan(target)          # Top 50 UDP ports
os_detection(target)      # OS fingerprinting
aggressive_scan(target)    # Complete aggressive scan
full_scan_with_cve(target) # Scan + CVE check
```

### 3️⃣ Web Module (`modules/web_enum.py`)

```python
http_headers(target, port)
whatweb_scan(target, port)
nikto_scan(target, port)
gobuster_dirs(target, port, wordlist)
ffuf_dirfuzz(target, port, wordlist)
sslscan(target, port)
nmap_http_enum(target, port)
full_web_enum(target, port, wordlist)
```

### 4️⃣ Exploit Module (`modules/exploit.py`)

```python
parse_nmap_services(nmap_output)
searchsploit_lookup(query)
find_exploits(services)
classify_exploit(title)
```

### 5️⃣ Auto-Exploitation Module (`modules/auto_exploit.py`) 🆕

```python
analyze_services(services)        # Analyze for vulnerabilities
generate_exploit_plan(opportunities) # Generate attack plan
auto_exploit_workflow(services)   # Complete workflow
```

### 6️⃣ Payload Generator (`modules/payloads.py`) 🆕

```python
reverse_shell(ip, port)          # Generate reverse shells
web_shell(ip, port, language)    # Generate web shells
sql_injection(technique)        # SQL injection payloads
xss_payloads(context)           # XSS payloads
command_injection()             # Command injection payloads
encode_payload(payload, encoding) # Encode payloads
```

### 7️⃣ CTF Helpers (`modules/ctf_helpers.py`) 🆕

```python
decode_base64(data)
encode_base64(data)
decode_hex(data)
encode_hex(data)
hash_string(data, algorithm)
identify_hash(hash_value)
quick_scan(target)
ctf_cheatsheet()
```

### 8️⃣ Brute Force Module (`modules/brute_force.py`)

```python
brute_ssh(target, userlist, passlist)
brute_ftp(target, userlist, passlist)
brute_http_basic(target, port, userlist, passlist)
brute_http_post(target, port, path, userlist, passlist)
test_credentials(service, target, username, password)
```

---

## 📊 Reports

### TXT Format

```
================== CARAPAUPANEL FINAL REPORT ==================
Target: 192.168.1.100
Scan Date: 2026-01-08 14:30:22

[WHOIS]
Domain: example.com
Registrar: Example Inc.
... 

[NMAP SCAN]
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1
80/tcp   open  http       Apache 2.4.41
... 

[CVE VULNERABILITIES]
🔴 CVE-2021-41773 - Apache 2.4.49 Path Traversal
...
```

### PDF Format

- Professional header with metadata
- Organized sections (only findings included)
- Formatted tables
- Timestamps and statistics
- **Filtered content** - Empty sections removed

### JSON Format

```json
{
  "metadata": {
    "tool": "CarapauCracker",
    "generated": "2026-01-08T14:30:22",
    "sections_count": 5
  },
  "findings": {
    "whois": { ... },
    "nmap": { ... },
    "exploits": [ ... ]
  }
}
```

## 🎯 Use Cases

### CTF Competitions

1. **Quick Recon**: Fast target enumeration
2. **Payload Generation**: Instant reverse shells and exploits
3. **Listener Setup**: One-click reverse shell listener
4. **Encoding Tools**: Quick decode/encode for challenges
5. **Hash Cracking**: Identify and crack hashes

### Professional Pentesting

1. **Comprehensive Scans**: Full network and web enumeration
2. **Vulnerability Assessment**: CVE checking and exploit discovery
3. **Automated Reporting**: Professional PDF and JSON reports
4. **Session Management**: Organized output per target
5. **Logging**: Complete audit trail

### Learning & Education

1. **Interactive Menus**: Easy to navigate
2. **Documentation**: Well-documented code
3. **Examples**: Clear usage examples
4. **Best Practices**: Security-focused design

---

## 🤝 Contributions

Contributions are welcome! To contribute:

1. Fork the project
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Ideas for Contribution

- 🆕 New modules (e.g., WiFi testing, mobile security, privilege escalation)
- 🐛 Bug fixes
- 📚 Documentation improvements
- 🎨 Graphical interface (GUI)
- 🔌 Integrations with other tools (Metasploit, Burp Suite)
- ⚡ Performance optimizations
- 🧪 Unit tests

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📞 Contact & Support

- **Author**: HungerBalls
- **GitHub**: [@HungerBalls](https://github.com/HungerBalls)
- **Project**: [CarapauCracker](https://github.com/HungerBalls/CarapauCracker)

### Report Issues

Found a bug or have a suggestion? [Open an issue](https://github.com/HungerBalls/CarapauCracker/issues)!

---

## 🌟 Acknowledgments

Tools and projects that made this possible:

- [Nmap](https://nmap.org/) - Network scanning
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Brute force attacks
- [Gobuster](https://github.com/OJ/gobuster) - Directory brute forcing
- [Nikto](https://cirt.net/Nikto2) - Web server scanning
- [FFUF](https://github.com/ffuf/ffuf) - Web fuzzing
- [SearchSploit](https://www.exploit-db.com/searchsploit) - Exploit database
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting

---



<div align="center">

**🐟 CarapauCracker - Fishing for vulnerabilities with style ⚓**

*The Ultimate Framework for CTF & Professional Pentesting*

Made with ❤️ and 🐍 Python

[⬆ Back to top](#-carapaucracker)

</div>
