# menu_web_enum.py — CarapauCracker v2

from modules.web_enum import (
    http_headers, robots_txt, http_methods,
    whatweb_scan, nikto_scan, gobuster_dirs,
    nmap_http_enum, sslscan,
    ffuf_dirfuzz, full_web_enum
)
from modules.utils import banner, log
from colorama import Fore

DEFAULT_WORDLIST = "wordlists/common.txt"

def run_web_enum_menu(target, run_dir, report_path, session_log):
    """Advanced web enumeration submenu"""
    while True:
        banner()
        print(Fore.CYAN + "╭────────────[ SUBMENU: ADVANCED WEB ENUMERATION ]────────────╮")
        print(Fore.CYAN + "│" + Fore.GREEN + " 1 " + Fore.WHITE + "- HTTP Headers")
        print(Fore.CYAN + "│" + Fore.GREEN + " 2 " + Fore.WHITE + "- Robots.txt")
        print(Fore.CYAN + "│" + Fore.GREEN + " 3 " + Fore.WHITE + "- HTTP Methods")
        print(Fore.CYAN + "│" + Fore.GREEN + " 4 " + Fore.WHITE + "- WhatWeb (technology detection)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 5 " + Fore.WHITE + "- Nikto (vulnerabilities)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 6 " + Fore.WHITE + "- Gobuster (directories)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 7 " + Fore.WHITE + "- FFUF (fast fuzzing)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 8 " + Fore.WHITE + "- Nmap HTTP Scripts")
        print(Fore.CYAN + "│" + Fore.GREEN + " 9 " + Fore.WHITE + "- SSLScan (443)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 10 " + Fore.WHITE + "- Complete Web Enumeration 🚀")
        print(Fore.CYAN + "│" + Fore.GREEN + " 0 " + Fore.WHITE + "- Return")
        print(Fore.CYAN + "╰─────────────────────────────────────────────────────────────╯")

        opt = input(Fore.YELLOW + "\n[»] Choose an option: ").strip()
        if opt == "0":
            banner()
            break

        port = input(Fore.YELLOW + "[?] Port (default 80): ").strip() or "80"
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
            case "10": full_web_enum(target, port, wordlist, report_path, session_log)
            case _: log(Fore.RED + "[✘] Invalid option. Try again.", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
