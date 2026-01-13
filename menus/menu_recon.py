# menu_recon.py — CarapauCracker v2

from modules.recon import basic_recon, whois_lookup, geoip_lookup, reverse_dns, banner_grab
from modules.utils import banner, log, append_section
from colorama import Fore
from rich.panel import Panel
from rich.console import Console


def run_recon_menu(target, run_dir, report_path, session_log):
    """
    Reconnaissance Submenu — v2
    Now everything uses central logging (session.log) and clean output.
    """
    console = Console()
    
    while True:
        banner()
        console.print(Panel.fit(
            "[cyan]1[/cyan] - WHOIS Lookup\n"
            "[cyan]2[/cyan] - GeoIP Lookup\n"
            "[cyan]3[/cyan] - Reverse DNS\n"
            "[cyan]4[/cyan] - Banner Grabbing (FTP, SSH, HTTP)\n"
            "[cyan]5[/cyan] - Run Complete Reconnaissance 🔍\n"
            "[cyan]0[/cyan] - Return to Main Menu",
            title="🔍 Reconnaissance Menu",
            border_style="cyan"
        ))

        opt = input(Fore.YELLOW + "\n[»] Choose an option: ").strip()

        if opt == "0":
            banner()
            break

        elif opt == "1":
            log(Fore.CYAN + f"\n[WHOIS] Running WHOIS for {target}", session_log)
            output = whois_lookup(target, session_log)
            append_section(report_path, "WHOIS", output)

        elif opt == "2":
            log(Fore.CYAN + f"\n[GEOIP] Running GEO-IP lookup for {target}", session_log)
            info = geoip_lookup(target, session_log)
            output = "\n".join([f"{k}: {v}" for k, v in info.items()])
            append_section(report_path, "GEOIP", output)

        elif opt == "3":
            log(Fore.CYAN + f"\n[DNS] Running Reverse DNS lookup for {target}", session_log)
            result = reverse_dns(target, session_log)
            output = "\n".join([f"{k}: {v}" for k, v in result.items()])
            append_section(report_path, "REVERSE DNS", output)

        elif opt == "4":
            log(Fore.CYAN + f"\n[BANNERS] Running banner grabbing for {target}", session_log)
            ftp = banner_grab(target, 21, session_log)
            ssh = banner_grab(target, 22, session_log)
            http = banner_grab(target, 80, session_log)
            output = f"FTP (21):\n{ftp}\n\nSSH (22):\n{ssh}\n\nHTTP (80):\n{http}"
            append_section(report_path, "BANNER GRABBING", output)

        elif opt == "5":
            log(Fore.CYAN + f"\n[🔍] Running complete basic reconnaissance on {target}", session_log)
            basic_recon(target, report_path, session_log)
            log(Fore.GREEN + "[✔] Complete reconnaissance finished.", session_log)

        else:
            log(Fore.RED + "[✘] Invalid option. Try again.", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
