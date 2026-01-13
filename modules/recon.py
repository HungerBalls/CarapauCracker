# recon.py — CarapauCracker v3
import socket
import subprocess
import requests
from typing import Dict, Optional
from pathlib import Path
from modules.utils import log, run_command_live, append_section
from modules.config import GEOIP_API_URL, GEOIP_TIMEOUT, validate_ip, sanitize_input
from colorama import Fore

# ================================================================
# 🔍 AUTOMATED BASIC RECONNAISSANCE
# ================================================================

def reverse_dns(ip: str, log_file: Optional[Path] = None) -> Dict[str, any]:
    """
    Perform reverse DNS lookup on target IP
    
    Args:
        ip: IP address to lookup
        log_file: Optional log file path
    
    Returns:
        Dictionary with hostname and aliases
    """
    # Validate IP
    if not validate_ip(ip):
        log(Fore.RED + f"[✘] Invalid IP address: {ip}", log_file)
        return {"hostname": "N/A", "aliases": []}
    
    log(f"[i] Performing reverse DNS lookup on {ip}...", log_file)
    result = {}
    try:
        socket.setdefaulttimeout(5)
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result["hostname"] = hostname
        result["aliases"] = list(aliases) if aliases else []
        log(Fore.GREEN + f"[✔] Hostname found: {hostname}", log_file)
    except socket.herror:
        result["hostname"] = "N/A"
        result["aliases"] = []
        log(Fore.YELLOW + "[⚠] Reverse DNS failed (no PTR record).", log_file)
    except socket.timeout:
        result["hostname"] = "N/A"
        result["aliases"] = []
        log(Fore.YELLOW + "[⚠] Reverse DNS timeout.", log_file)
    except Exception as e:
        result["hostname"] = "N/A"
        result["aliases"] = []
        log(Fore.RED + f"[✘] Reverse DNS error: {e}", log_file, level="ERROR")
    finally:
        socket.setdefaulttimeout(None)
    return result


def whois_lookup(ip: str, log_file=None) -> str:
    """Run WHOIS lookup for target"""
    log(f"[i] Running WHOIS for {ip}...", log_file)
    try:
        output = run_command_live(["whois", ip], log_file)
        if output:
            return output
        else:
            log(Fore.YELLOW + "[⚠] WHOIS returned no data.", log_file)
            return "WHOIS lookup returned no data"
    except FileNotFoundError:
        error_msg = "WHOIS command not found. Install with: sudo apt install whois"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return error_msg
    except Exception as e:
        error_msg = f"WHOIS lookup failed: {e}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return error_msg


def geoip_lookup(ip: str, log_file: Optional[Path] = None) -> Dict[str, str]:
    """
    Perform GEO-IP lookup using ip-api.com
    
    Args:
        ip: IP address to lookup
        log_file: Optional log file path
    
    Returns:
        Dictionary with geo-location information
    """
    # Validate IP
    if not validate_ip(ip):
        log(Fore.RED + f"[✘] Invalid IP address: {ip}", log_file)
        return {
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "org": "N/A",
            "isp": "N/A"
        }
    
    log(f"[i] Performing GEO-IP lookup (ip-api.com) on {ip}...", log_file)
    try:
        url = f"{GEOIP_API_URL}/{ip}"
        response = requests.get(url, timeout=GEOIP_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                log(Fore.GREEN + f"[✔] GEO-IP: {data.get('country')} - {data.get('city')}", log_file)
                return {
                    "country": data.get("country", "N/A"),
                    "region": data.get("regionName", "N/A"),
                    "city": data.get("city", "N/A"),
                    "org": data.get("org", "N/A"),
                    "isp": data.get("isp", "N/A")
                }
            else:
                log(Fore.YELLOW + f"[⚠] GEO-IP failed: {data.get('message', 'Unknown error')}", log_file)
        else:
            log(Fore.YELLOW + f"[⚠] GEO-IP API returned status {response.status_code}", log_file)
    except requests.exceptions.Timeout:
        log(Fore.RED + "[✘] GEO-IP request timeout.", log_file)
    except requests.exceptions.ConnectionError:
        log(Fore.RED + "[✘] GEO-IP connection error. Check internet connection.", log_file)
    except Exception as e:
        log(Fore.RED + f"[✘] GEO-IP failed: {e}", log_file)

    return {
        "country": "N/A",
        "region": "N/A",
        "city": "N/A",
        "org": "N/A",
        "isp": "N/A"
    }


def banner_grab(ip: str, port: int, log_file: Optional[Path] = None, timeout: int = 3) -> str:
    """
    Perform basic banner grabbing for services (HTTP, SSH, FTP, etc.)
    
    Args:
        ip: Target IP address
        port: Target port number
        log_file: Optional log file path
        timeout: Connection timeout in seconds
    
    Returns:
        Banner string or "N/A" if failed
    """
    # Validate inputs
    if not validate_ip(ip):
        log(Fore.RED + f"[✘] Invalid IP address: {ip}", log_file)
        return "N/A (invalid IP)"
    
    from modules.config import validate_port
    if not validate_port(port):
        log(Fore.RED + f"[✘] Invalid port number: {port}", log_file)
        return "N/A (invalid port)"
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Try HTTP banner first
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")
        except:
            # If HTTP fails, try generic banner grab
            banner = s.recv(1024).decode(errors="ignore")
        
        s.close()
        if banner and banner.strip():
            log(Fore.GREEN + f"[✔] Banner found on {ip}:{port}", log_file)
            return banner.strip()
        else:
            return "N/A (empty response)"
    except socket.timeout:
        log(Fore.YELLOW + f"[⚠] Banner grab timeout on {ip}:{port}", log_file)
        return "N/A (timeout)"
    except ConnectionRefusedError:
        log(Fore.YELLOW + f"[⚠] Connection refused on {ip}:{port}", log_file)
        return "N/A (connection refused)"
    except Exception as e:
        log(Fore.YELLOW + f"[⚠] No banner obtained on {ip}:{port} - {type(e).__name__}", log_file)
        return "N/A"


def basic_recon(ip: str, report_path: Path, log_file: Optional[Path] = None) -> Dict[str, any]:
    """
    Perform all basic reconnaissance tasks:
    - Reverse DNS
    - WHOIS
    - GEO-IP
    - Banner grabbing
    
    Args:
        ip: Target IP address
        report_path: Path to report file
        log_file: Optional log file path
    
    Returns:
        Dictionary with all reconnaissance data
    """
    # Validate IP
    if not validate_ip(ip):
        log(Fore.RED + f"[✘] Invalid IP address: {ip}", log_file)
        return {"ip": ip, "error": "Invalid IP address"}
    
    try:
        log(Fore.CYAN + f"\n[🔍] Starting basic reconnaissance of {ip}", log_file)

        recon_data = {"ip": ip}
        recon_data.update(reverse_dns(ip, log_file))
        recon_data["whois"] = whois_lookup(ip, log_file)
        recon_data.update(geoip_lookup(ip, log_file))
        recon_data["http_banner"] = banner_grab(ip, 80, log_file)
        recon_data["ftp_banner"] = banner_grab(ip, 21, log_file)
        recon_data["ssh_banner"] = banner_grab(ip, 22, log_file)

        # Add section to main report
        section_text = (
            f"Target IP: {ip}\n"
            f"Hostname: {recon_data.get('hostname')}\n"
            f"Country: {recon_data.get('country')} ({recon_data.get('city')})\n"
            f"Org/ISP: {recon_data.get('org')} / {recon_data.get('isp')}\n\n"
            f"[ WHOIS OUTPUT ]\n{recon_data.get('whois')}\n\n"
            f"[ HTTP Banner ]\n{recon_data.get('http_banner')}\n\n"
            f"[ SSH Banner ]\n{recon_data.get('ssh_banner')}\n\n"
            f"[ FTP Banner ]\n{recon_data.get('ftp_banner')}\n"
        )

        append_section(report_path, "BASIC RECONNAISSANCE", section_text)
        log(Fore.GREEN + "[✔] Basic reconnaissance completed.", log_file)

        return recon_data
    except Exception as e:
        error_msg = f"Error in basic reconnaissance: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return {"ip": ip, "error": str(e)}
