# brute_force.py — CarapauCracker v2
from modules.utils import run_command_live, append_section, log
from colorama import Fore
from typing import Optional

DEFAULT_USERS = "wordlists/users.txt"
DEFAULT_PASSWORDS = "wordlists/rockyou.txt"


# ================================================================
# ⚙️ FUNÇÃO BASE PARA HYDRA
# ================================================================
def run_hydra(
    service: str,
    target: str,
    port: Optional[int] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    userlist: str = DEFAULT_USERS,
    passlist: str = DEFAULT_PASSWORDS,
    extra_args: list = None,
    threads: int = 4,
    timeout: int = 5,
    report_path=None,
    log_file=None
) -> str:
    """
    Função genérica para correr Hydra com output ao vivo e logging.
    """
    cmd = ["hydra", "-t", str(threads), "-W", str(timeout), "-f"]

    if username and password:
        cmd += ["-l", username, "-p", password]
    elif username:
        cmd += ["-l", username, "-P", passlist]
    elif password:
        cmd += ["-L", userlist, "-p", password]
    else:
        cmd += ["-L", userlist, "-P", passlist]

    if extra_args:
        cmd += extra_args

    if port:
        cmd.append(f"{service}://{target}:{port}")
    else:
        cmd.append(f"{service}://{target}")

    log(Fore.CYAN + f"\n[🔑] A correr Hydra contra {target} ({service})", log_file)
    log(Fore.YELLOW + f"[→] Comando: {' '.join(cmd)}", log_file)

    output = run_command_live(cmd, log_file)

    append_section(report_path, f"Hydra Brute Force - {service.upper()}", output)
    log(Fore.GREEN + f"[✔] Ataque Hydra terminado ({service}).\n", log_file)

    return output


# ================================================================
# 🔹 ATAQUES ESPECÍFICOS
# ================================================================
def brute_ftp(ip: str, report_path, log_file=None, **kwargs):
    """Brute force FTP"""
    return run_hydra("ftp", ip, report_path=report_path, log_file=log_file, **kwargs)


def brute_ssh(ip: str, report_path, log_file=None, **kwargs):
    """Brute force SSH"""
    return run_hydra("ssh", ip, report_path=report_path, log_file=log_file, **kwargs)


def brute_http_post(
    ip: str,
    port: int,
    path: str,
    fail_string: str,
    report_path,
    log_file=None,
    username_field: str = "username",
    password_field: str = "password",
    **kwargs
):
    """
    HTTP POST brute-force (login forms)
    """
    form = f"{path}:{username_field}=^USER^&{password_field}=^PASS^:F={fail_string}"
    extra_args = [ip, "-s", str(port), "http-post-form", form]
    return run_hydra(
        "http-post-form",
        ip,
        port=port,
        extra_args=extra_args,
        report_path=report_path,
        log_file=log_file,
        **kwargs
    )


def brute_http_basic(
    ip: str,
    port: int,
    report_path,
    log_file=None,
    **kwargs
):
    """
    HTTP Basic Authentication brute-force
    """
    return run_hydra(
        "http-get",
        ip,
        port=port,
        report_path=report_path,
        log_file=log_file,
        **kwargs
    )


def test_credentials(
    service: str,
    ip: str,
    username: str,
    password: str,
    port: int = None,
    report_path=None,
    log_file=None
):
    """
    Teste direto de credenciais conhecidas.
    """
    return run_hydra(
        service=service,
        target=ip,
        port=port,
        username=username,
        password=password,
        report_path=report_path,
        log_file=log_file
    )


# ================================================================
# 🚀 FLUXO AUTOMÁTICO (TUDO DE UMA VEZ)
# ================================================================
def full_bruteforce(ip: str, report_path, log_file=None):
    """
    Executa ataques Hydra nos serviços comuns (FTP, SSH, HTTP).
    """
    log(Fore.CYAN + f"\n[🚀] Iniciar brute force completo em {ip}", log_file)

    brute_ftp(ip, report_path, log_file)
    brute_ssh(ip, report_path, log_file)
    brute_http_basic(ip, 80, report_path, log_file)

    log(Fore.GREEN + f"[✔] Brute force completo terminado para {ip}\n", log_file)
