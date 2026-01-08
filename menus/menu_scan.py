from modules.scan import (
    nmap_quick, nmap_detailed, nmap_full_tcp,
    nmap_udp_scan, nmap_os_detection, full_scan_workflow,
    full_scan_with_cve
)
from modules.utils import banner, log
from colorama import Fore
from rich.panel import Panel
from rich.console import Console

def run_scan_menu(target, run_dir, report_path, session_log):
    """Scanning submenu for port and system scanning"""
    console = Console()
    
    while True:
        banner()
        console.print(Panel.fit(
            "[cyan]1[/cyan] - Quick Scan (open ports)\n"
            "[cyan]2[/cyan] - Detailed Scan (-sV -sC)\n"
            "[cyan]3[/cyan] - Full TCP Scan (-p-)\n"
            "[cyan]4[/cyan] - UDP Scan (Top 50)\n"
            "[cyan]5[/cyan] - OS Detection (-O)\n"
            "[cyan]6[/cyan] - Aggressive Scan (-A)\n"
            "[cyan]7[/cyan] - Run Complete Scan 🚀\n"
            "[cyan]8[/cyan] - Full Scan + CVE Check 🔍\n"
            "[cyan]0[/cyan] - Return",
            title="📡 Port Scanning Menu",
            border_style="cyan"
        ))

        opt = input(Fore.YELLOW + "\n[»] Choose option: ").strip()

        if opt == "0":
            banner()
            break
        elif opt == "1":
            nmap_quick(target, report_path, session_log)
        elif opt == "2":
            nmap_detailed(target, [], report_path, session_log)
        elif opt == "3":
            nmap_full_tcp(target, report_path, session_log)
        elif opt == "4":
            nmap_udp_scan(target, report_path, session_log)
        elif opt == "5":
            nmap_os_detection(target, report_path, session_log)
        elif opt == "6":
            from modules.scan import nmap_aggressive
            nmap_aggressive(target, report_path, session_log)
        elif opt == "7":
            full_scan_workflow(target, report_path, session_log)
        elif opt == "8":
            full_scan_with_cve(target, report_path, session_log)
        else:
            log(Fore.RED + "[✘] Invalid option. Try again.", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
