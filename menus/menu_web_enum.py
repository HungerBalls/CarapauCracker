# menu_web_enum.py — CarapauCracker v2

from modules.web_enum import (
    http_headers, robots_txt, http_methods,
    whatweb_scan, nikto_scan, gobuster_dirs,
    nmap_http_enum, sslscan,
    ffuf_dirfuzz, full_web_enum
)
from modules.utils import banner, log
from colorama import Fore
from rich.panel import Panel
from rich.console import Console

DEFAULT_WORDLIST = "wordlists/common.txt"

def run_web_enum_menu(target, run_dir, report_path, session_log):
    """Advanced web enumeration submenu"""
    console = Console()
    
    while True:
        banner()
        console.print(Panel.fit(
            "[cyan]1[/cyan] - HTTP Headers\n"
            "[cyan]2[/cyan] - Robots.txt\n"
            "[cyan]3[/cyan] - HTTP Methods\n"
            "[cyan]4[/cyan] - WhatWeb (technology detection)\n"
            "[cyan]5[/cyan] - Nikto (vulnerabilities)\n"
            "[cyan]6[/cyan] - Gobuster (directories)\n"
            "[cyan]7[/cyan] - FFUF (fast fuzzing)\n"
            "[cyan]8[/cyan] - Nmap HTTP Scripts\n"
            "[cyan]9[/cyan] - SSLScan (443)\n"
            "[cyan]10[/cyan] - Complete Web Enumeration 🚀\n"
            "[cyan]0[/cyan] - Return",
            title="🌐 Advanced Web Enumeration Menu",
            border_style="cyan"
        ))

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
