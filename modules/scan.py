# scan.py — CarapauCracker v3
import re
from modules.utils import run_command_live, append_section, log
from colorama import Fore

# ================================================================
# 🔍 SCAN NMAP INTEGRADO E VISUAL
# ================================================================

def run_nmap(ip: str, args: list, title: str, report_path, log_file=None) -> str:
    """
    Função genérica para correr Nmap com output live + logging + report
    """
    log(Fore.CYAN + f"\n[🧪] {title} em execução...", log_file)
    log(Fore.MAGENTA + f"    ➤ Comando: nmap {' '.join(args)} {ip}\n", log_file)

    # Executa comando e mostra em tempo real
    output = run_command_live(["nmap"] + args + [ip], log_file)

    append_section(report_path, title, output)
    log(Fore.GREEN + f"[✔] {title} concluído.\n", log_file)
    return output


# ================================================================
# 🔹 SCANS RÁPIDOS E DETALHADOS
# ================================================================

def nmap_quick(ip: str, report_path, log_file=None) -> str:
    """Quick scan para descobrir portas abertas"""
    return run_nmap(ip, ["-T4", "--open"], "Nmap Quick Scan", report_path, log_file)


def extract_open_tcp_ports(nmap_output: str) -> list:
    """Extrai as portas TCP abertas do output do nmap"""
    ports = []
    for line in nmap_output.splitlines():
        match = re.match(r"^(\d+)/tcp\s+open", line)
        if match:
            ports.append(match.group(1))
    return ports


def nmap_detailed(ip: str, ports: list, report_path, log_file=None) -> str:
    """
    Scan detalhado (-sV -sC)
    Mesmo que não haja portas abertas, faz um full scan inteligente (-sV -sC -T4)
    """
    if not ports:
        msg = "[!] Nenhuma porta TCP aberta encontrada no Quick Scan. A correr full detailed scan (-sV -sC )."
        log(Fore.YELLOW + msg, log_file)
        append_section(report_path, "Nmap Detailed Scan", msg)
        args = ["-sV", "-sC", "-T4"]
    else:
        port_str = ",".join(ports)
        args = ["-sV", "-sC", "-p", port_str]

    return run_nmap(ip, args, "Nmap Detailed Scan", report_path, log_file)


def nmap_os_detection(ip: str, report_path, log_file=None) -> str:
    """Deteção de Sistema Operativo"""
    return run_nmap(ip, ["-O"], "Nmap OS Detection", report_path, log_file)


def nmap_full_tcp(ip: str, report_path, log_file=None) -> str:
    """Scan completo de todas as portas TCP"""
    return run_nmap(ip, ["-p-", "-T4", "--open"], "Nmap Full TCP Scan", report_path, log_file)


def nmap_udp_scan(ip: str, report_path, log_file=None) -> str:
    """Scan UDP (limitado por default a 50 portas)"""
    return run_nmap(ip, ["-sU", "--top-ports", "50", "--open"], "Nmap UDP Scan", report_path, log_file)


def nmap_aggressive(ip: str, report_path, log_file=None) -> str:
    """Scan agressivo (-A): OS + version + script + traceroute"""
    return run_nmap(ip, ["-A"], "Nmap Aggressive Scan", report_path, log_file)


def nmap_all_formats(ip: str, output_path: str, report_path, log_file=None) -> str:
    """Gera output em todos os formatos (nmap, xml, grepable)"""
    return run_nmap(ip, ["-sC", "-sV", "-oA", output_path], "Nmap Output All Formats", report_path, log_file)


# ================================================================
# 🔹 FLUXO AUTOMÁTICO — EXECUTAR TODOS
# ================================================================

def full_scan_workflow(ip: str, report_path, log_file=None):
    """
    Workflow completo de scanning:
    1. Quick Scan
    2. Scan Detalhado (-sV -sC)
    3. OS Detection
    4. Aggressive Scan
    """
    log(Fore.CYAN + f"\n[🚀] Iniciar Scanning completo em {ip}", log_file)

    quick = nmap_quick(ip, report_path, log_file)
    open_ports = extract_open_tcp_ports(quick)

    nmap_detailed(ip, open_ports, report_path, log_file)
    nmap_os_detection(ip, report_path, log_file)
    nmap_aggressive(ip, report_path, log_file)

    log(Fore.GREEN + f"[✔] Scanning completo concluído para {ip}\n", log_file)
    return open_ports

