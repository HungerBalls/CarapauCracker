<div align="center">

# 🐟 CarapauCracker

```
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
```

**Modular Penetration Testing Framework in Python**

*Intelligent automation for security testing in controlled environments* 🔒

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Educational%20Only-red)](README.md#-legal-disclaimer)

[Features](#-key-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Modules](#-available-modules) •
[Documentation](#-project-structure) •
[Legal Notice](#-legal-disclaimer)

</div>

---

## 📋 About the Project

**CarapauCracker** is a modular pentesting framework developed entirely in Python that automates and centralizes critical phases of penetration testing in controlled laboratory environments.

Created for cybersecurity professionals, researchers, and ethical hacking enthusiasts, this tool offers an intuitive CLI interface that integrates the industry's most recognized tools into a unified platform.

### 🎯 Objectives

- ✅ **Automation**: Reduce repetitive tasks during pentests
- ✅ **Centralization**: Unify multiple tools in a single interface
- ✅ **Documentation**: Automatically generate professional reports
- ✅ **Modularity**: Extensible and easy-to-maintain architecture
- ✅ **Education**: Learning tool for pentesting techniques

---

## ✨ Key Features

### 🔍 **1. Advanced Reconnaissance**

- ✓ Host availability verification (ICMP ping)
- ✓ Automatic reverse DNS lookup
- ✓ WHOIS integration for registration information
- ✓ GeoIP location via external API
- ✓ Multi-protocol banner grabbing (FTP, SSH, HTTP)

### 🔎 **2. Network & System Scanning**

- **Quick Scan**: Rapid identification of common ports
- **Detailed Scan**: Version detection and NSE scripts (`-sV -sC`)
- **Full TCP Scan**: Complete analysis of all 65535 ports
- **UDP Scan**: Scanning of the 50 most common UDP ports
- **OS Detection**: Operating system fingerprinting
- **Aggressive Scan**: Aggressive mode with all techniques (`-A`)

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

### 💣 **4. Exploit Discovery**

- 🔎 Integration with **SearchSploit** (Exploit-DB)
- 🎯 Intelligent classification by severity (RCE, Auth Bypass, LPE, DoS)
- ⚡ Exploit ranking system by priority

### 🔑 **5. Credential Attacks (Hydra)**

- 🔓 SSH brute-force
- 🔓 FTP authentication testing
- 🔓 HTTP Basic Auth cracking
- 🔓 HTTP POST form attacks
- 📝 Support for custom wordlists
- ⚡ Quick testing of known/default credentials

### 📄 **6. Reporting System**

- 📝 Unified and structured TXT report
- 📄 Automatic export to professional **PDF**
- 🗂️ Export to **JSON** with structured data
- 🕐 Detailed logging with timestamps
- 🗃️ Organization by sessions and targets

---

## 🛠️ Requirements

### Operating System

- **Linux** (Kali Linux, Parrot OS, Ubuntu, Debian)
- **Python 3.8+**

### External Tools

The following tools must be installed on the system:

```bash
# Core Tools
nmap, masscan, whois, dig

# Web Enumeration
nikto, gobuster, ffuf, whatweb, sslscan

# Exploitation
searchsploit

# Brute Force
hydra

# Utilities
curl, wget
```

### Python Dependencies

```bash
colorama
requests
fpdf
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

# 5. Run
python3 main.py
```

---

## 🚀 Usage

### Quick Start

```bash
python3 main.py
```

### Typical Workflow

```
1. Enter target (IP or hostname)
   └─> Automatic connectivity check

2. Main Menu - Choose module: 
   ├─> 1. Basic Reconnaissance
   │   └─> WHOIS, GeoIP, DNS, Banner Grabbing
   │
   ├─> 2. Port Scanning
   │   └─> Quick/Detailed/Full TCP/UDP/OS Detection
   │
   ├─> 3. Web Enumeration
   │   └─> Headers, WhatWeb, Nikto, Gobuster, FFUF
   │
   ├─> 4. Exploitation
   │   └─> SearchSploit
   │
   ├─> 5. Brute Force
   │   └─> SSH, FTP, HTTP (Hydra)
   │
   └─> 6. Export Report
       └─> PDF, JSON, TXT

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
│ 6 - Export Final Report 📄
│ 0 - Exit Session ⛔
╰──────────────────────────────────────────────────────────╯

[»] Choose your module: 1
```

---

## 📁 Project Structure

```
CarapauCracker/
├── main.py                 # Main entry point
├── install.sh              # Automatic installation script
├── requirements.txt        # Python dependencies
│
├── modules/                # Functional modules
│   ├── recon.py           # Reconnaissance (WHOIS, DNS, GeoIP)
│   ├── scan.py            # Port scanning (Nmap, Masscan)
│   ├── web_enum.py        # Web enumeration (Nikto, Gobuster, FFUF)
│   ├── exploit.py         # Exploit discovery (SearchSploit)
│   ├── brute_force.py     # Credential attacks (Hydra)
│   ├── report.py          # Report generation (PDF, JSON)
│   └── utils.py           # Utilities (logging, execution, banner)
│
├── menus/                  # Interactive menus
│   ├── menu_recon.py
│   ├── menu_scan.py
│   ├── menu_web_enum.py
│   ├── menu_exploit.py
│   └── menu_brute.py
│
├── wordlists/              # Wordlists for fuzzing and brute-force
│   ├── common.txt
│   ├── users.txt
│   └── rockyou.txt
│
└── outputs/                # Session results
    └── <target>/
        └── <timestamp>/
            ├── report.txt
            ├── report.pdf
            ├── report.json
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
aggressive_scan(target)   # Complete aggressive scan
```

### 3️⃣ Web Module (`modules/web_enum.py`)

```python
http_headers(target, port)
whatweb_scan(target, port)
nikto_scan(target, port)
gobuster_dirs(target, port, wordlist)
ffuf_dirfuzz(target, port, wordlist)
sslscan(target, port)
```

### 4️⃣ Exploit Module (`modules/exploit.py`)

```python
searchsploit_search(service, version)
rank_exploits(exploits)
```

### 5️⃣ Brute Force Module (`modules/brute_force.py`)

```python
brute_ssh(target, userlist, passlist)
brute_ftp(target, userlist, passlist)
brute_http_basic(target, port, userlist, passlist)
brute_http_post(target, port, path, userlist, passlist)
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
```

### PDF Format

- Professional header with logo
- Organized sections
- Formatted tables
- Timestamps and metadata

### JSON Format

```json
{
  "target": "192.168.1.100",
  "timestamp": "2026-01-08T14:30:22",
  "sections": {
    "whois": { ... },
    "nmap": { ... },
    "exploits": [ ... ]
  }
}
```


## 🤝 Contributions

Contributions are welcome! To contribute:

1. Fork the project
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Ideas for Contribution

- 🆕 New modules (e.g., WiFi testing, mobile security)
- 🐛 Bug fixes
- 📚 Documentation improvements
- 🎨 Graphical interface (GUI)
- 🔌 Integrations with other tools

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


<div align="center">

**🐟 CarapauCracker - Fishing for vulnerabilities with style ⚓**

Made with ❤️ and 🐍 Python

[⬆ Back to top](#-carapaucracker)

</div>
