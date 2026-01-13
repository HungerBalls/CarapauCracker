# menu_brute.py — CarapauCracker v2

from modules.brute_force import (
    brute_ftp, brute_ssh, brute_http_basic,
    brute_http_post, full_bruteforce, test_credentials
)
from modules.utils import banner, log
from colorama import Fore
from rich.panel import Panel
from rich.console import Console


DEFAULT_USERS = "wordlists/users.txt"
DEFAULT_PASSWORDS = "wordlists/rockyou.txt"


def run_brute_menu(target, run_dir, report_path, session_log):
    """Brute force attacks submenu"""
    console = Console()
    
    while True:
        banner()
        console.print(Panel.fit(
            "[cyan]1[/cyan] - FTP\n"
            "[cyan]2[/cyan] - SSH\n"
            "[cyan]3[/cyan] - HTTP Basic Auth\n"
            "[cyan]4[/cyan] - HTTP Form Login (POST)\n"
            "[cyan]5[/cyan] - Test known credentials\n"
            "[cyan]6[/cyan] - Run all 🚀\n"
            "[cyan]0[/cyan] - Return",
            title="🔨 Brute Force Menu - Hydra",
            border_style="cyan"
        ))

        opt = input(Fore.YELLOW + "\n[»] Choose an option: ").strip()

        if opt == "0":
            banner()
            break

        username = input(Fore.YELLOW + "[?] Username (ENTER = use wordlist): ").strip() or None
        password = input(Fore.YELLOW + "[?] Password (ENTER = use wordlist): ").strip() or None
        userlist = input(Fore.YELLOW + f"[?] Users wordlist (default {DEFAULT_USERS}): ").strip() or DEFAULT_USERS
        passlist = input(Fore.YELLOW + f"[?] Passwords wordlist (default {DEFAULT_PASSWORDS}): ").strip() or DEFAULT_PASSWORDS

        if opt == "1":
            brute_ftp(target, report_path, session_log, username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "2":
            brute_ssh(target, report_path, session_log, username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "3":
            brute_http_basic(target, 80, report_path, session_log, username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "4":
            path = input(Fore.YELLOW + "[?] Form path (e.g. /login.php): ").strip() or "/login.php"
            fail_str = input(Fore.YELLOW + "[?] Failure string (e.g. 'Invalid login'): ").strip() or "Invalid"
            brute_http_post(target, 80, path, fail_str, report_path, session_log,
                            username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "5":
            svc = input(Fore.YELLOW + "[?] Service (e.g. ssh, ftp): ").strip() or "ssh"
            port = input(Fore.YELLOW + "[?] Port (ENTER = default): ").strip() or None
            test_credentials(svc, target, username or "admin", password or "admin", port, report_path, session_log)
        elif opt == "6":
            full_bruteforce(target, report_path, session_log)
        else:
            log(Fore.RED + "[✘] Invalid option.", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
