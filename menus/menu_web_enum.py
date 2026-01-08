# menu_web_enum.py — CarapauCracker v2

from modules.web_enum import (
    http_headers, robots_txt, http_methods,
    whatweb_scan, nikto_scan, gobuster_dirs,
    nmap_http_enum, wpscan_scan, sslscan,
    ffuf_dirfuzz, full_web_enum
)
from modules.utils import banner, log
from colorama import Fore

DEFAULT_WORDLIST = "wordlists/common.txt"

def run_web_enum_menu(target, run_dir, report_path, session_log):
    while True:
        banner()
        print(Fore.CYAN + "╭────────────[ SUBMENU: ENUMERAÇÃO WEB AVANÇADA ]────────────╮")
        print(Fore.CYAN + "│" + Fore.GREEN + " 1 " + Fore.WHITE + "- HTTP Headers")
        print(Fore.CYAN + "│" + Fore.GREEN + " 2 " + Fore.WHITE + "- Robots.txt")
        print(Fore.CYAN + "│" + Fore.GREEN + " 3 " + Fore.WHITE + "- HTTP Methods")
        print(Fore.CYAN + "│" + Fore.GREEN + " 4 " + Fore.WHITE + "- WhatWeb (detecção de tecnologias)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 5 " + Fore.WHITE + "- Nikto (vulnerabilidades)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 6 " + Fore.WHITE + "- Gobuster (diretórios)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 7 " + Fore.WHITE + "- FFUF (fuzzing rápido)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 8 " + Fore.WHITE + "- Nmap HTTP Scripts")
        print(Fore.CYAN + "│" + Fore.GREEN + " 9 " + Fore.WHITE + "- SSLScan (443)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 10 " + Fore.WHITE + "- WPScan (WordPress)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 11 " + Fore.WHITE + "- Enumeração Web Completa 🚀")
        print(Fore.CYAN + "│" + Fore.GREEN + " 0 " + Fore.WHITE + "- Voltar")
        print(Fore.CYAN + "╰─────────────────────────────────────────────────────────────╯")

        opt = input(Fore.YELLOW + "\n[»] Escolhe uma opção: ").strip()
        if opt == "0":
            banner()
            break

        port = input(Fore.YELLOW + "[?] Porta (default 80): ").strip() or "80"
        port = int(port)
        wordlist = input(Fore.YELLOW + f"[?] Wordlist (default {DEFAULT_WORDLIST}): ").strip() or DEFAULT_WORDLIST

        match opt:
            case "1": http_headers(target, port, report_path, session_log)
            case "2": robots_txt(target, port, report_path, session_log)
            case "3": http_methods(target, port, report_path, session_log)
            case "4": whatweb_scan(target, port, report_path, session_log)
            case "5": nikto_scan(target, port, report_path, session_log)
            case "6": gobuster_dirs(target, port, wordlist, report_path, session_log)
            case "7": ffuf_dirfuzz(target, port, wordlist, report_path, session_log)
            case "8": nmap_http_enum(target, port, report_path, session_log)
            case "9": sslscan(target, 443, report_path, session_log)
            case "10": wpscan_scan(target, port, report_path, session_log)
            case "11": full_web_enum(target, port, wordlist, report_path, session_log)
            case _: log(Fore.RED + "[✘] Opção inválida. Tenta novamente.", session_log)

        input(Fore.YELLOW + "\nPressiona ENTER para continuar...")
