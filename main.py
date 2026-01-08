# main.py — CarapauCracker v2

from modules.utils import banner, make_run_dir, is_alive, log, validate_dependencies
from modules.report import export_pdf, export_json
from menus.menu_recon import run_recon_menu
from menus.menu_scan import run_scan_menu
from menus.menu_web_enum import run_web_enum_menu
from menus.menu_exploit import run_exploit_menu
from menus.menu_brute import run_brute_menu
from colorama import Fore, init
from pathlib import Path
import os

init(autoreset=True)


def main():
    """Main entry point for CarapauCracker"""
    try:
        banner()
        print(Fore.CYAN + " [*] Welcome to " + Fore.YELLOW + "CarapauCracker" + Fore.CYAN +
              " – where we fish for vulnerabilities with style ⚓🐟\n")

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
            print(Fore.CYAN + f"🎯 Current target: " + Fore.WHITE + f"{target}\n")
            print(Fore.CYAN + "╭────────────[ MAIN MENU - CARAPAUPANEL ]────────────╮")
            print(Fore.CYAN + "│" + Fore.GREEN + " 1 " + Fore.WHITE + "- Basic Reconnaissance")
            print(Fore.CYAN + "│" + Fore.GREEN + " 2 " + Fore.WHITE + "- Port & System Scanning")
            print(Fore.CYAN + "│" + Fore.GREEN + " 3 " + Fore.WHITE + "- Advanced Web Enumeration")
            print(Fore.CYAN + "│" + Fore.GREEN + " 4 " + Fore.WHITE + "- Automated Exploitation (Searchsploit)")
            print(Fore.CYAN + "│" + Fore.GREEN + " 5 " + Fore.WHITE + "- Brute Force Attacks (Hydra)")
            print(Fore.CYAN + "│" + Fore.GREEN + " 6 " + Fore.WHITE + "- Export Final Report 📄")
            print(Fore.CYAN + "│" + Fore.GREEN + " 0 " + Fore.WHITE + "- Exit Session ⛔")
            print(Fore.CYAN + "╰──────────────────────────────────────────────────────────╯")

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
                    print(Fore.GREEN + f"\n[✓] Reports generated successfully!")
                    print(Fore.GREEN + f"    📄 PDF:  {run_dir / 'report.pdf'}")
                    print(Fore.GREEN + f"    📄 JSON: {run_dir / 'report.json'}")
                    log("[✓] Reports exported successfully.", session_log)
                elif choice == "0":
                    print(Fore.CYAN + "\n👋 Session terminated. Until next time, hacker.")
                    log("\n=== Session closed ===", session_log)
                    break
                else:
                    print(Fore.RED + "[✘] Invalid option. Try again.")
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n\n[⚠] Operation interrupted by user.")
                cont = input(Fore.YELLOW + "Return to main menu? (Y/n): ").lower()
                if cont == 'n':
                    print(Fore.CYAN + "\n👋 Session terminated. Until next time, hacker.")
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
