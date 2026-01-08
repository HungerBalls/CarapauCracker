# utils.py — versão CarapauCracker v2
from pathlib import Path
from datetime import datetime
import subprocess
import shutil
import os
from colorama import Fore, init

init(autoreset=True)


# ============================================================
# 🐟 Banner bonito e coerente em todos os menus
# ============================================================

def banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(Fore.CYAN + r"""
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
  
    """ + Fore.YELLOW + "         Framework de Pentesting Avançado 🇵🇹\n" +
          Fore.MAGENTA + "                  by HungerBalls  🎯  |  CarapauCracker v2\n")


# ============================================================
# 📂 Diretórios e sessão centralizada
# ============================================================

def make_run_dir(target: str) -> Path:
    """
    Cria um único diretório de sessão:
      outputs/<target>/<timestamp>/
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path("outputs") / target / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    print(Fore.GREEN + f"[✔] Sessão criada em: {run_dir}")
    return run_dir


# ============================================================
# ⚙️ Utilitários de sistema
# ============================================================

def tool_exists(name: str) -> bool:
    """
    Verifica se uma ferramenta existe no PATH
    """
    path = shutil.which(name)
    if path:
        print(Fore.GREEN + f"[✔] {name} encontrado em: {path}")
        return True
    print(Fore.RED + f"[✘] {name} não encontrado no sistema.")
    return False


def is_alive(ip: str) -> bool:
    """
    Verifica se o IP responde a ping
    """
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        alive = result.returncode == 0
        if alive:
            print(Fore.GREEN + f"[✔] {ip} está ativo (responde a ping).")
        else:
            print(Fore.YELLOW + f"[⚠] {ip} não respondeu a ping.")
        return alive
    except Exception as e:
        print(Fore.RED + f"[✘] Erro ao executar ping: {e}")
        return False


# ============================================================
# 🧠 Execução em tempo real (output live + logging)
# ============================================================

def run_command_live(cmd: list, log_file: Path = None) -> str:
    """
    Executa um comando e mostra o output em tempo real no terminal.
    Também guarda o output completo num log central (session.log).
    """
    print(Fore.MAGENTA + f"\n[>] A executar: {' '.join(cmd)}\n")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    output = ""
    for line in process.stdout:
        print(line, end="")
        output += line
        if log_file:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line)

    process.wait()
    return output


# ============================================================
# 🧾 Logging unificado (session.log)
# ============================================================

def log(message: str, log_file: Path = None, color=Fore.CYAN):
    """
    Mostra e grava mensagens da framework (informativas, erros, etc.)
    """
    print(color + message)
    if log_file:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(message + "\n")


# ============================================================
# 📜 Escrita e relatórios (apenas um ficheiro por alvo)
# ============================================================

def append_section(report_path: Path, title: str, content: str):
    """
    Adiciona secções formatadas ao relatório principal.
    """
    try:
        with report_path.open("a", encoding="utf-8") as f:
            f.write("\n" + "=" * 70 + "\n")
            f.write(f"[ {title.upper()} ]\n")
            f.write("=" * 70 + "\n")
            f.write((content or "").strip() + "\n")
        print(Fore.BLUE + f"[✔] Secção '{title}' adicionada ao relatório.")
    except Exception as e:
        print(Fore.RED + f"[✘] Erro ao adicionar secção '{title}': {e}")
