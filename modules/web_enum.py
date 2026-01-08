# web_enum.py — CarapauCracker v2
from modules.utils import run_command_live, append_section, log
from colorama import Fore


# ================================================================
# 🌐 BASE EXECUTION
# ================================================================
def run_web_tool(cmd: list, title: str, report_path, log_file=None):
    """
    Execute any web command and show output in real-time.
    """
    try:
        log(Fore.CYAN + f"\n[🌐] {title} running: {' '.join(cmd)}", log_file)
        output = run_command_live(cmd, log_file)
        if output:
            append_section(report_path, title, output)
            log(Fore.GREEN + f"[✔] {title} completed.\n", log_file)
        else:
            log(Fore.YELLOW + f"[⚠] {title} produced no output.\n", log_file)
        return output
    except Exception as e:
        error_msg = f"Error running {title}: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return ""


# ================================================================
# 🔹 WEB ENUMERATION FUNCTIONS
# ================================================================
def http_headers(ip: str, port: int, report_path, log_file=None):
    """Retrieve HTTP headers from target"""
    url = f"http://{ip}:{port}"
    return run_web_tool(["curl", "-I", "-s", url], f"HTTP Headers ({url})", report_path, log_file)


def robots_txt(ip: str, port: int, report_path, log_file=None):
    """Fetch robots.txt file"""
    url = f"http://{ip}:{port}/robots.txt"
    return run_web_tool(["curl", "-s", url], f"robots.txt ({url})", report_path, log_file)


def http_methods(ip: str, port: int, report_path, log_file=None):
    """Check HTTP methods supported"""
    url = f"http://{ip}:{port}"
    return run_web_tool(["curl", "-X", "OPTIONS", "-i", "-s", url], f"HTTP Methods ({url})", report_path, log_file)


def whatweb_scan(ip: str, port: int, report_path, log_file=None):
    """WhatWeb technology detection scan"""
    url = f"http://{ip}:{port}"
    return run_web_tool(["whatweb", "--color=never", url], f"WhatWeb Technology Scan ({url})", report_path, log_file)


def nikto_scan(ip: str, port: int, report_path, log_file=None):
    """Nikto vulnerability scanner"""
    url = f"http://{ip}:{port}"
    return run_web_tool(["nikto", "-h", url], f"Nikto Vulnerability Scan ({url})", report_path, log_file)


def gobuster_dirs(ip: str, port: int, wordlist: str, report_path, log_file=None):
    """GoBuster directory/file brute-forcing"""
    url = f"http://{ip}:{port}"
    return run_web_tool(
        ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "50"],
        f"GoBuster Directory Scan ({url})",
        report_path,
        log_file
    )


def ffuf_dirfuzz(ip: str, port: int, wordlist: str, report_path, log_file=None):
    """FFUF high-performance fuzzing"""
    url = f"http://{ip}:{port}/FUZZ"
    return run_web_tool(
        ["ffuf", "-w", wordlist, "-u", url, "-mc", "200,204,301,302,403", "-t", "30"],
        f"FFUF Fuzzing ({url})",
        report_path,
        log_file
    )


def sslscan(ip: str, port: int, report_path, log_file=None):
    """SSLScan for SSL/TLS analysis"""
    return run_web_tool(["sslscan", f"{ip}:{port}"], f"SSLScan ({ip}:{port})", report_path, log_file)


def wpscan_scan(ip: str, port: int, report_path, log_file=None):
    """WPScan for WordPress security scanning"""
    url = f"http://{ip}:{port}"
    return run_web_tool(["wpscan", "--url", url, "--no-update"], f"WPScan WordPress Scan ({url})", report_path, log_file)


def nmap_http_enum(ip: str, port: int, report_path, log_file=None):
    """Nmap HTTP enumeration scripts"""
    scripts = "http-enum,http-title,http-methods,http-server-header,http-robots.txt"
    cmd = ["nmap", "-sV", "-Pn", "-n", "-p", str(port), "--script", scripts, ip]
    return run_web_tool(cmd, f"Nmap HTTP Script Scan ({ip}:{port})", report_path, log_file)


# ================================================================
# 🔹 RUN COMPLETE ENUMERATION
# ================================================================
def full_web_enum(ip: str, port: int, wordlist: str, report_path, log_file=None):
    """
    Complete web enumeration:
    - HTTP Headers
    - Robots.txt
    - HTTP Methods
    - WhatWeb
    - Gobuster
    - Nikto
    - Nmap scripts
    - SSLScan
    """
    try:
        log(Fore.CYAN + f"\n[🚀] Starting complete web enumeration on {ip}:{port}", log_file)

        http_headers(ip, port, report_path, log_file)
        robots_txt(ip, port, report_path, log_file)
        http_methods(ip, port, report_path, log_file)
        whatweb_scan(ip, port, report_path, log_file)
        gobuster_dirs(ip, port, wordlist, report_path, log_file)
        nikto_scan(ip, port, report_path, log_file)
        nmap_http_enum(ip, port, report_path, log_file)
        sslscan(ip, 443, report_path, log_file)

        log(Fore.GREEN + f"[✔] Complete web enumeration finished for {ip}:{port}", log_file)
    except Exception as e:
        error_msg = f"Error in full web enumeration: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
