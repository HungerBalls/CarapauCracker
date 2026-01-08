# main.py — CarapauCracker v2

from modules.utils import banner, make_run_dir, is_alive, log
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
    banner()
    print(Fore.CYAN + " [*] Bem-vindo à " + Fore.YELLOW + "CarapauCracker" + Fore.CYAN +
          " – onde pescamos vulnerabilidades com estilo ⚓🐟\n")

    # ─────────── Alvo ───────────
    target = input(Fore.YELLOW + "[🎯] Introduz o IP ou hostname do alvo: ").strip()
    if not target:
        print(Fore.RED + "[✘] Alvo inválido. Tenta outra vez.")
        return

    if not is_alive(target):
        print(Fore.YELLOW + "[⚠] O alvo pode não estar online ou a responder a ping.")
        cont = input(Fore.YELLOW + "    Continuar mesmo assim? (s/N): ").lower()
        if cont != 's':
            return

    run_dir = make_run_dir(target)
    report_path = run_dir / "report.txt"
    session_log = run_dir / "session.log"

    log(f"\n=== Início da sessão CarapauCracker para {target} ===", session_log)

    # ─────────── Menu Principal ───────────
    while True:
        banner()
        print(Fore.CYAN + f"🎯 Alvo atual: " + Fore.WHITE + f"{target}\n")
        print(Fore.CYAN + "╭────────────[ MENU PRINCIPAL - CARAPAUPANEL ]────────────╮")
        print(Fore.CYAN + "│" + Fore.GREEN + " 1 " + Fore.WHITE + "- Reconhecimento Básico")
        print(Fore.CYAN + "│" + Fore.GREEN + " 2 " + Fore.WHITE + "- Scanning de Portas & Sistema")
        print(Fore.CYAN + "│" + Fore.GREEN + " 3 " + Fore.WHITE + "- Enumeração Web Avançada")
        print(Fore.CYAN + "│" + Fore.GREEN + " 4 " + Fore.WHITE + "- Exploração Automática (MSF + Searchsploit)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 5 " + Fore.WHITE + "- Ataques de Força Bruta (Hydra)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 6 " + Fore.WHITE + "- Exportar Relatório Final 📄")
        print(Fore.CYAN + "│" + Fore.GREEN + " 0 " + Fore.WHITE + "- Terminar Sessão ⛔")
        print(Fore.CYAN + "╰──────────────────────────────────────────────────────────╯")

        choice = input(Fore.YELLOW + "\n[»] Escolhe o teu módulo: ").strip()

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
            print(Fore.GREEN + f"\n[✓] Relatórios gerados com sucesso!")
            print(Fore.GREEN + f"    📄 PDF:  {run_dir / 'report.pdf'}")
            print(Fore.GREEN + f"    📄 JSON: {run_dir / 'report.json'}")
            log("[✓] Relatórios exportados com sucesso.", session_log)
        elif choice == "0":
            print(Fore.CYAN + "\n👋 Sessão terminada. Até à próxima pescaria, hacker.")
            log("\n=== Sessão encerrada ===", session_log)
            break
        else:
            print(Fore.RED + "[✘] Opção inválida. Tenta novamente.")

if __name__ == "__main__":
    main()
