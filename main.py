# main.py — CarapauCracker v3

from dotenv import load_dotenv
from modules.utils import banner, make_run_dir, is_alive, log, validate_dependencies
from modules.report import export_pdf, export_json, export_summary
from modules.config import validate_ip, validate_hostname, sanitize_input
from menus.menu_recon import run_recon_menu
from menus.menu_scan import run_scan_menu
from menus.menu_web_enum import run_web_enum_menu
from menus.menu_exploit import run_exploit_menu
from menus.menu_brute import run_brute_menu
from menus.menu_payloads import run_payloads_menu
from menus.menu_ctf import run_ctf_menu
from colorama import Fore, init
from rich.panel import Panel
from rich.console import Console
from pathlib import Path
import os
import sys

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
        
        # Sanitize and validate target
        target = sanitize_input(target)
        if not target:
            print(Fore.RED + "[✘] Target cannot be empty after sanitization.")
            return
        
        # Validate target format
        if not (validate_ip(target) or validate_hostname(target)):
            print(Fore.RED + "[✘] Invalid target format. Please enter a valid IP address or hostname.")
            return

        # Optional connectivity check
        console.print("[cyan][i] Checking target connectivity...[/cyan]")
        if not is_alive(target):
            console.print("[yellow][⚠] Target may not be online or responding to ping.[/yellow]")
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
                "[cyan]6[/cyan] - Payload Generator 💣\n"
                "[cyan]7[/cyan] - CTF Mode 🏆\n"
                "[cyan]8[/cyan] - Export Final Report 📄\n"
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
                    run_payloads_menu(target, run_dir, report_path, session_log)
                elif choice == "7":
                    run_ctf_menu(target, run_dir, report_path, session_log)
                elif choice == "8":
                    banner()
                    console.print(Panel.fit(
                        "[cyan]1[/cyan] - PDF Full Report (only findings)\n"
                        "[cyan]2[/cyan] - JSON Structured Data (only findings)\n"
                        "[cyan]3[/cyan] - Executive Summary (highlights)\n"
                        "[cyan]4[/cyan] - View Report Stats\n"
                        "[cyan]0[/cyan] - Cancel",
                        title="📄 Export Options",
                        border_style="cyan"
                    ))
                    
                    export_choice = input(Fore.YELLOW + "\n[»] Choose format: ").strip()
                    
                    if export_choice == "1":
                        pdf_file = run_dir / "report_filtered.pdf"
                        if export_pdf(report_path, pdf_file):
                            console.print(f"[green][✓] PDF saved to: {pdf_file}[/green]")
                    
                    elif export_choice == "2":
                        json_file = run_dir / "report_filtered.json"
                        if export_json(report_path, json_file):
                            console.print(f"[green][✓] JSON saved to: {json_file}[/green]")
                    
                    elif export_choice == "3":
                        summary_file = run_dir / "executive_summary.txt"
                        if export_summary(report_path, summary_file):
                            console.print(f"[green][✓] Summary saved to: {summary_file}[/green]")
                    
                    elif export_choice == "4":
                        # Mostrar estatísticas do report
                        try:
                            from modules.report import parse_report_sections
                            stats = report_path.stat()
                            sections = parse_report_sections(report_path)
                            total_sections = report_path.read_text().count("=" * 70) // 2
                            console.print(f"\n[cyan]Report Statistics:[/cyan]")
                            console.print(f"  File: {report_path}")
                            console.print(f"  Total sections: {total_sections}")
                            console.print(f"  Sections with findings: {len(sections)}")
                            console.print(f"  Size: {stats.st_size} bytes")
                        except Exception as e:
                            console.print(f"[red][✘] Error reading stats: {e}[/red]")
                    
                    elif export_choice == "0":
                        banner()
                    else:
                        console.print("[red][✘] Invalid option[/red]")
                    
                    input(Fore.YELLOW + "\nPress ENTER to continue...")
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
