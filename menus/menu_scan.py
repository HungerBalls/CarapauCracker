from modules.scan import (
    nmap_quick, nmap_detailed, nmap_full_tcp,
    nmap_udp_scan, nmap_os_detection, full_scan_workflow
)
from modules.utils import banner, log
from colorama import Fore

def run_scan_menu(target, run_dir, report_path, session_log):
    """Scanning submenu for port and system scanning"""
    while True:
        banner()
        print(Fore.CYAN + "╭────────────[ SUBMENU: SCANNING - NMAP ]────────────╮")
        print(Fore.CYAN + "│" + Fore.GREEN + " 1 " + Fore.WHITE + "- Quick Scan (open ports)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 2 " + Fore.WHITE + "- Detailed Scan (-sV -sC)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 3 " + Fore.WHITE + "- Full TCP Scan (-p-)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 4 " + Fore.WHITE + "- UDP Scan (Top 50)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 5 " + Fore.WHITE + "- OS Detection (-O)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 6 " + Fore.WHITE + "- Aggressive Scan (-A)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 7 " + Fore.WHITE + "- Run Complete Scan 🚀")
        print(Fore.CYAN + "│" + Fore.GREEN + " 0 " + Fore.WHITE + "- Return")
        print(Fore.CYAN + "╰────────────────────────────────────────────────────╯")

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
        else:
            log(Fore.RED + "[✘] Invalid option. Try again.", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
