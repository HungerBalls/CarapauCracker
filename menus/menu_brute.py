# menu_brute.py — CarapauCracker v2

from modules.brute_force import (
    brute_ftp, brute_ssh, brute_http_basic,
    brute_http_post, full_bruteforce, test_credentials
)
from modules.utils import banner, log
from colorama import Fore


DEFAULT_USERS = "wordlists/users.txt"
DEFAULT_PASSWORDS = "wordlists/rockyou.txt"


def run_brute_menu(target, run_dir, report_path, session_log):
    while True:
        banner()
        print(Fore.CYAN + "╭────────────[ SUBMENU: FORÇA BRUTA - HYDRA ]────────────╮")
        print(Fore.CYAN + "│" + Fore.GREEN + " 1 " + Fore.WHITE + "- FTP")
        print(Fore.CYAN + "│" + Fore.GREEN + " 2 " + Fore.WHITE + "- SSH")
        print(Fore.CYAN + "│" + Fore.GREEN + " 3 " + Fore.WHITE + "- HTTP Basic Auth")
        print(Fore.CYAN + "│" + Fore.GREEN + " 4 " + Fore.WHITE + "- HTTP Form Login (POST)")
        print(Fore.CYAN + "│" + Fore.GREEN + " 5 " + Fore.WHITE + "- Testar credenciais conhecidas")
        print(Fore.CYAN + "│" + Fore.GREEN + " 6 " + Fore.WHITE + "- Executar tudo 🚀")
        print(Fore.CYAN + "│" + Fore.GREEN + " 0 " + Fore.WHITE + "- Voltar")
        print(Fore.CYAN + "╰────────────────────────────────────────────────────────╯")

        opt = input(Fore.YELLOW + "\n[»] Escolhe uma opção: ").strip()

        if opt == "0":
            banner()
            break

        username = input(Fore.YELLOW + "[?] Username (ENTER = usar wordlist): ").strip() or None
        password = input(Fore.YELLOW + "[?] Password (ENTER = usar wordlist): ").strip() or None
        userlist = input(Fore.YELLOW + f"[?] Wordlist de utilizadores (default {DEFAULT_USERS}): ").strip() or DEFAULT_USERS
        passlist = input(Fore.YELLOW + f"[?] Wordlist de passwords (default {DEFAULT_PASSWORDS}): ").strip() or DEFAULT_PASSWORDS

        if opt == "1":
            brute_ftp(target, report_path, session_log, username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "2":
            brute_ssh(target, report_path, session_log, username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "3":
            brute_http_basic(target, 80, report_path, session_log, username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "4":
            path = input(Fore.YELLOW + "[?] Caminho do formulário (ex: /login.php): ").strip() or "/login.php"
            fail_str = input(Fore.YELLOW + "[?] String de falha (ex: 'Invalid login'): ").strip() or "Invalid"
            brute_http_post(target, 80, path, fail_str, report_path, session_log,
                            username=username, password=password, userlist=userlist, passlist=passlist)
        elif opt == "5":
            svc = input(Fore.YELLOW + "[?] Serviço (ex: ssh, ftp): ").strip() or "ssh"
            port = input(Fore.YELLOW + "[?] Porta (ENTER = padrão): ").strip() or None
            test_credentials(svc, target, username or "admin", password or "admin", port, report_path, session_log)
        elif opt == "6":
            full_bruteforce(target, report_path, session_log)
        else:
            log(Fore.RED + "[✘] Opção inválida.", session_log)

        input(Fore.YELLOW + "\nPressiona ENTER para continuar...")
