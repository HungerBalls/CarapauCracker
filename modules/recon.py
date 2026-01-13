# recon.py — CarapauCracker v2
import socket
import subprocess
import requests
from modules.utils import log, run_command_live, append_section
from colorama import Fore

# ================================================================
# 🔍 AUTOMATED BASIC RECONNAISSANCE
# ================================================================

def reverse_dns(ip: str, log_file=None) -> dict:
    """Perform reverse DNS lookup on target IP"""
    log(f"[i] Performing reverse DNS lookup on {ip}...", log_file)
    result = {}
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result["hostname"] = hostname
        result["aliases"] = aliases
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
        log(Fore.RED + f"[✘] Reverse DNS error: {e}", log_file)
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


def geoip_lookup(ip: str, log_file=None) -> dict:
    """Perform GEO-IP lookup using ip-api.com"""
    log(f"[i] Performing GEO-IP lookup (ip-api.com) on {ip}...", log_file)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
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


def banner_grab(ip: str, port: int, log_file=None) -> str:
    """
    Perform basic banner grabbing for services (HTTP, SSH, FTP, etc.)
    """
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        log(Fore.GREEN + f"[✔] Banner found on {ip}:{port}", log_file)
        return banner.strip()
    except socket.timeout:
        log(Fore.YELLOW + f"[⚠] Banner grab timeout on {ip}:{port}", log_file)
        return "N/A (timeout)"
    except ConnectionRefusedError:
        log(Fore.YELLOW + f"[⚠] Connection refused on {ip}:{port}", log_file)
        return "N/A (connection refused)"
    except Exception as e:
        log(Fore.YELLOW + f"[⚠] No banner obtained on {ip}:{port} - {type(e).__name__}", log_file)
        return "N/A"


def basic_recon(ip: str, report_path, log_file=None):
    """
    Perform all basic reconnaissance tasks:
    - Reverse DNS
    - WHOIS
    - GEO-IP
    - Banner grabbing
    """
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
