# main.py — CarapauCracker v2

from dotenv import load_dotenv
from modules.utils import banner, make_run_dir, is_alive, log, validate_dependencies
from modules.report import export_pdf, export_json
from menus.menu_recon import run_recon_menu
from menus.menu_scan import run_scan_menu
from menus.menu_web_enum import run_web_enum_menu
from menus.menu_exploit import run_exploit_menu
from menus.menu_brute import run_brute_menu
from colorama import Fore, init
from rich.panel import Panel
from rich.console import Console
from pathlib import Path
import os

# Load environment variables from .env file
load_dotenv()

init(autoreset=True)


def main():
    """Main entry point for CarapauCracker"""
    console = Console()
    
    try:
        banner()
        console.print("[cyan][*] Welcome to [/cyan][yellow]CarapauCracker[/yellow][cyan] – where we fish for vulnerabilities with style ⚓🐟[/cyan]\n")

        # Validate all required tools before proceeding
        validate_dependencies()

        # ─────────── Target ───────────
        target = input(Fore.YELLOW + "[🎯] Enter target IP or hostname: ").strip()
        if not target:
            print(Fore.RED + "[✘] Invalid target. Try again.")
            return

        if not is_alive(target):
            print(Fore.YELLOW + "[⚠] Target may not be online or responding to ping.")
            cont = input(Fore.YELLOW + "    Continue anyway? (y/N): ").lower()
            if cont != 'y':
                return

        run_dir = make_run_dir(target)
        report_path = run_dir / "report.txt"
        session_log = run_dir / "session.log"

        log(f"\n=== CarapauCracker session started for {target} ===", session_log)

        # ─────────── Main Menu ───────────
        while True:
            banner()
            console.print(f"[cyan]🎯 Current target: [/cyan][white]{target}[/white]\n")
            console.print(Panel.fit(
                "[cyan]1[/cyan] - Basic Reconnaissance\n"
                "[cyan]2[/cyan] - Port & System Scanning\n"
                "[cyan]3[/cyan] - Advanced Web Enumeration\n"
                "[cyan]4[/cyan] - Automated Exploitation (Searchsploit)\n"
                "[cyan]5[/cyan] - Brute Force Attacks (Hydra)\n"
                "[cyan]6[/cyan] - Export Final Report 📄\n"
                "[cyan]0[/cyan] - Exit Session ⛔",
                title="🎯 MAIN MENU - CARAPAUPANEL",
                border_style="cyan"
            ))

            choice = input(Fore.YELLOW + "\n[»] Choose your module: ").strip()

            try:
                if choice == "1":
                    run_recon_menu(target, run_dir, report_path, session_log)
                elif choice == "2":
                    run_scan_menu(target, run_dir, report_path, session_log)
                elif choice == "3":
                    run_web_enum_menu(target, run_dir, report_path, session_log)
                elif choice == "4":
                    run_exploit_menu(target, run_dir, report_path, session_log)
                elif choice == "5":
                    run_brute_menu(target, run_dir, report_path, session_log)
                elif choice == "6":
                    export_pdf(report_path, run_dir / "report.pdf")
                    export_json(report_path, run_dir / "report.json")
                    console.print("\n[green][✓] Reports generated successfully![/green]")
                    console.print(f"[green]    📄 PDF:  {run_dir / 'report.pdf'}[/green]")
                    console.print(f"[green]    📄 JSON: {run_dir / 'report.json'}[/green]")
                    log("[✓] Reports exported successfully.", session_log)
                elif choice == "0":
                    console.print("\n[cyan]👋 Session terminated. Until next time, hacker.[/cyan]")
                    log("\n=== Session closed ===", session_log)
                    break
                else:
                    print(Fore.RED + "[✘] Invalid option. Try again.")
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n\n[⚠] Operation interrupted by user.")
                cont = input(Fore.YELLOW + "Return to main menu? (Y/n): ").lower()
                if cont == 'n':
                    console.print("\n[cyan]👋 Session terminated. Until next time, hacker.[/cyan]")
                    log("\n=== Session closed (interrupted by user) ===", session_log)
                    break
            except Exception as e:
                print(Fore.RED + f"[✘] Unexpected error in menu: {e}")
                log(f"[✘] Error in main menu: {e}", session_log)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[⚠] Program interrupted by user. Exiting...")
    except Exception as e:
        print(Fore.RED + f"[✘] Fatal error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
