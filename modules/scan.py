# scan.py — CarapauCracker v3
import re
from typing import List, Dict, Optional
from pathlib import Path
from modules.utils import run_command_live, append_section, log
from modules.config import SCAN_CONFIG, validate_ip, sanitize_input
from colorama import Fore
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# ================================================================
# 🔍 INTEGRATED AND VISUAL NMAP SCAN
# ================================================================

def run_nmap(ip: str, args: List[str], title: str, report_path: Path, log_file: Optional[Path] = None, timeout: Optional[int] = None) -> str:
    """
    Generic function to run Nmap with live output + logging + report
    
    Args:
        ip: Target IP address
        args: Nmap arguments as list
        title: Scan title for logging
        report_path: Path to report file
        log_file: Optional log file path
        timeout: Optional timeout in seconds
    
    Returns:
        Nmap output as string
    """
    # Validate IP
    if not validate_ip(ip):
        log(Fore.RED + f"[✘] Invalid IP address: {ip}", log_file)
        return ""
    
    # Sanitize arguments
    args = [sanitize_input(str(arg)) for arg in args if arg]
    
    try:
        log(Fore.CYAN + f"\n[🧪] {title} in progress...", log_file)
        log(Fore.MAGENTA + f"    ➤ Command: nmap {' '.join(args)} {ip}\n", log_file)

        # Use timeout from config if not provided
        if timeout is None:
            timeout = SCAN_CONFIG.get("nmap_timeout", 300)

        # Execute command and show in real-time
        output = run_command_live(["nmap"] + args + [ip], log_file, timeout=timeout)

        if output:
            append_section(report_path, title, output)
            log(Fore.GREEN + f"[✔] {title} completed.\n", log_file)
        else:
            log(Fore.YELLOW + f"[⚠] {title} produced no output.\n", log_file)
        
        return output
    except Exception as e:
        error_msg = f"Error running {title}: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file, level="ERROR")
        return ""


# ================================================================
# 🔹 QUICK AND DETAILED SCANS
# ================================================================

def display_scan_results(services):
    """Display scan results in a Rich table"""
    console = Console()
    table = Table(title="🔍 Port Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Version", style="white")
    
    for svc in services:
        table.add_row(f"{svc['port']}/tcp", "open", svc['service'], svc['version'])
    
    console.print(table)


def extract_services_from_output(nmap_output: str) -> List[Dict[str, str]]:
    """
    Extract services with port, service name and version from nmap output
    
    Args:
        nmap_output: Raw Nmap output string
    
    Returns:
        List of service dictionaries with 'port', 'service', and 'version' keys
    """
    services = []
    try:
        for line in nmap_output.splitlines():
            match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if match:
                services.append({
                    'port': match.group(1),
                    'service': match.group(2),
                    'version': match.group(3).strip()
                })
        return services
    except Exception as e:
        log(Fore.RED + f"[✘] Error extracting services: {e}", None, level="ERROR")
        return []


def nmap_quick(ip: str, report_path, log_file=None) -> str:
    """Quick scan to discover open ports"""
    return run_nmap(ip, ["-T4", "--open"], "Nmap Quick Scan", report_path, log_file)


def extract_open_tcp_ports(nmap_output: str) -> list:
    """Extract open TCP ports from nmap output"""
    try:
        ports = []
        for line in nmap_output.splitlines():
            match = re.match(r"^(\d+)/tcp\s+open", line)
            if match:
                ports.append(match.group(1))
        return ports
    except Exception as e:
        print(Fore.RED + f"[✘] Error extracting ports: {e}")
        return []


def nmap_detailed(ip: str, ports: list, report_path, log_file=None) -> str:
    """
    Detailed scan (-sV -sC)
    If no open ports, run full intelligent scan (-sV -sC -T4)
    """
    try:
        if not ports:
            msg = "[!] No open TCP ports found in Quick Scan. Running full detailed scan (-sV -sC)."
            log(Fore.YELLOW + msg, log_file)
            append_section(report_path, "Nmap Detailed Scan", msg)
            args = ["-sV", "-sC", "-T4"]
        else:
            port_str = ",".join(ports)
            args = ["-sV", "-sC", "-p", port_str]

        output = run_nmap(ip, args, "Nmap Detailed Scan", report_path, log_file)
        
        # Extract services and display in table
        services = extract_services_from_output(output)
        if services:
            display_scan_results(services)
        
        return output
    except Exception as e:
        error_msg = f"Error in detailed scan: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return ""


def nmap_os_detection(ip: str, report_path, log_file=None) -> str:
    """Operating System Detection"""
    return run_nmap(ip, ["-O"], "Nmap OS Detection", report_path, log_file)


def nmap_full_tcp(ip: str, report_path, log_file=None) -> str:
    """Complete scan of all TCP ports"""
    return run_nmap(ip, ["-p-", "-T4", "--open"], "Nmap Full TCP Scan", report_path, log_file)


def nmap_udp_scan(ip: str, report_path, log_file=None) -> str:
    """UDP scan (limited by default to top 50 ports)"""
    return run_nmap(ip, ["-sU", "--top-ports", "50", "--open"], "Nmap UDP Scan", report_path, log_file)


def nmap_aggressive(ip: str, report_path, log_file=None) -> str:
    """Aggressive scan (-A): OS + version + script + traceroute"""
    return run_nmap(ip, ["-A"], "Nmap Aggressive Scan", report_path, log_file)


def nmap_all_formats(ip: str, output_path: str, report_path, log_file=None) -> str:
    """Generate output in all formats (nmap, xml, grepable)"""
    return run_nmap(ip, ["-sC", "-sV", "-oA", output_path], "Nmap Output All Formats", report_path, log_file)


# ================================================================
# 🔹 AUTOMATIC WORKFLOW — RUN ALL
# ================================================================

def full_scan_with_cve(ip: str, report_path, log_file=None):
    """
    Complete scanning workflow with CVE checking:
    1. Quick Scan
    2. Detailed Scan (-sV -sC)
    3. CVE Vulnerability Check
    """
    try:
        from modules.cve_checker import auto_cve_scan
        
        log(Fore.CYAN + f"\n[🚀] Starting complete scan with CVE check on {ip}", log_file)

        quick = nmap_quick(ip, report_path, log_file)
        open_ports = extract_open_tcp_ports(quick)

        output = nmap_detailed(ip, open_ports, report_path, log_file)
        
        # Extract services and run CVE check
        services = extract_services_from_output(output)
        if services:
            log(Fore.CYAN + "\n[🔍] Running CVE vulnerability check...", log_file)
            cves = auto_cve_scan(services, report_path, log_file)
            log(Fore.GREEN + f"[✔] CVE check completed. Found {len(cves)} vulnerabilities.\n", log_file)
        
        log(Fore.GREEN + f"[✔] Complete scanning finished for {ip}\n", log_file)
        return open_ports
    except Exception as e:
        error_msg = f"Error in full scan with CVE: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return []


def full_scan_workflow(ip: str, report_path, log_file=None):
    """
    Complete scanning workflow:
    1. Quick Scan
    2. Detailed Scan (-sV -sC)
    3. OS Detection
    4. Aggressive Scan
    """
    try:
        log(Fore.CYAN + f"\n[🚀] Starting complete scan on {ip}", log_file)

        quick = nmap_quick(ip, report_path, log_file)
        open_ports = extract_open_tcp_ports(quick)

        nmap_detailed(ip, open_ports, report_path, log_file)
        nmap_os_detection(ip, report_path, log_file)
        nmap_aggressive(ip, report_path, log_file)

        log(Fore.GREEN + f"[✔] Complete scanning finished for {ip}\n", log_file)
        return open_ports
    except Exception as e:
        error_msg = f"Error in full scan workflow: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return []

