# recon.py — CarapauCracker v2
import socket
import subprocess
import requests
from modules.utils import log, run_command_live, append_section
from colorama import Fore

# ================================================================
# 🔍 RECONHECIMENTO BÁSICO AUTOMATIZADO
# ================================================================

def reverse_dns(ip: str, log_file=None) -> dict:
    log(f"[i] A efetuar reverse DNS lookup em {ip}...", log_file)
    result = {}
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result["hostname"] = hostname
        result["aliases"] = aliases
        log(Fore.GREEN + f"[✔] Hostname encontrado: {hostname}", log_file)
    except Exception:
        result["hostname"] = "N/A"
        result["aliases"] = []
        log(Fore.YELLOW + "[⚠] Reverse DNS falhou.", log_file)
    return result


def whois_lookup(ip: str, log_file=None) -> str:
    log(f"[i] A correr WHOIS para {ip}...", log_file)
    try:
        output = run_command_live(["whois", ip], log_file)
        return output
    except Exception as e:
        log(Fore.RED + f"[✘] WHOIS lookup falhou: {e}", log_file)
        return "Whois lookup failed"


def geoip_lookup(ip: str, log_file=None) -> dict:
    log(f"[i] A efetuar GEO-IP lookup (ip-api.com) em {ip}...", log_file)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            log(Fore.GREEN + f"[✔] GEO-IP: {data.get('country')} - {data.get('city')}", log_file)
            return {
                "country": data.get("country", "N/A"),
                "region": data.get("regionName", "N/A"),
                "city": data.get("city", "N/A"),
                "org": data.get("org", "N/A"),
                "isp": data.get("isp", "N/A")
            }
    except Exception as e:
        log(Fore.RED + f"[✘] GEO-IP falhou: {e}", log_file)

    return {
        "country": "N/A",
        "region": "N/A",
        "city": "N/A",
        "org": "N/A",
        "isp": "N/A"
    }


def banner_grab(ip: str, port: int, log_file=None) -> str:
    """
    Faz banner grabbing básico de serviços (HTTP, SSH, FTP, etc.)
    """
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        log(Fore.GREEN + f"[✔] Banner encontrado em {ip}:{port}", log_file)
        return banner.strip()
    except Exception:
        log(Fore.YELLOW + f"[⚠] Nenhum banner obtido em {ip}:{port}", log_file)
        return "N/A"


def basic_recon(ip: str, report_path, log_file=None):
    """
    Realiza todas as tarefas de reconhecimento básico:
    - Reverse DNS
    - WHOIS
    - GEO-IP
    - Banner grabbing
    """
    log(Fore.CYAN + f"\n[🔍] Iniciar reconhecimento básico de {ip}", log_file)

    recon_data = {"ip": ip}
    recon_data.update(reverse_dns(ip, log_file))
    recon_data["whois"] = whois_lookup(ip, log_file)
    recon_data.update(geoip_lookup(ip, log_file))
    recon_data["http_banner"] = banner_grab(ip, 80, log_file)
    recon_data["ftp_banner"] = banner_grab(ip, 21, log_file)
    recon_data["ssh_banner"] = banner_grab(ip, 22, log_file)

    # Adiciona a secção ao relatório principal
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

    append_section(report_path, "RECONHECIMENTO BÁSICO", section_text)
    log(Fore.GREEN + "[✔] Reconhecimento básico concluído.", log_file)

    return recon_data
