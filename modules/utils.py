# utils.py — CarapauCracker v3
from pathlib import Path
from datetime import datetime
import subprocess
import shutil
import os
import sys
from colorama import Fore, init
from rich.console import Console
from rich.panel import Panel

init(autoreset=True)


# ============================================================
# 🐟 Beautiful and consistent banner across all menus
# ============================================================

def banner():
    """Clear screen and display CarapauCracker banner"""
    try:
        os.system("clear" if os.name == "posix" else "cls")
        console = Console()
        
        # Plain ASCII art without markup tags (using raw string to avoid escape sequence warnings)
        banner_art = r"""
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
"""
        
        # Print plain art in cyan using style parameter
        console.print(banner_art, style="bold cyan")
        console.print("        [yellow]Advanced Pentesting Framework 🐟[/yellow]")
        console.print("             [white]by HungerBalls[/white]  🎯  |  [cyan]CarapauCracker v3[/cyan]\n")
    except Exception as e:
        print(Fore.RED + f"[✘] Error displaying banner: {e}")


# ============================================================
# 📂 Directories and centralized session management
# ============================================================

def make_run_dir(target: str) -> Path:
    """
    Create a single session directory:
      outputs/<target>/<timestamp>/
    """
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = Path("outputs") / target / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        print(Fore.GREEN + f"[✔] Session created at: {run_dir}")
        return run_dir
    except Exception as e:
        print(Fore.RED + f"[✘] Error creating session directory: {e}")
        raise


# ============================================================
# ⚙️ System utilities and dependency validation
# ============================================================

def tool_exists(name: str) -> bool:
    """
    Check if a tool exists in PATH
    """
    try:
        path = shutil.which(name)
        return path is not None
    except Exception as e:
        print(Fore.RED + f"[✘] Error checking for tool '{name}': {e}")
        return False


def validate_dependencies():
    """
    Validate that all required external tools are installed.
    Exit with error message if critical tools are missing.
    """
    required_tools = {
        'core': ['nmap', 'masscan', 'whois', 'dig'],
        'web': ['nikto', 'gobuster', 'ffuf', 'whatweb', 'sslscan'],
        'exploitation': ['searchsploit'],
        'bruteforce': ['hydra'],
        'utilities': ['curl', 'wget']
    }
    
    print(Fore.CYAN + "\n[i] Validating external tool dependencies...\n")
    
    missing = {}
    for category, tools in required_tools.items():
        missing[category] = [tool for tool in tools if not tool_exists(tool)]
    
    # Display results
    has_missing = any(len(tools) > 0 for tools in missing.values())
    
    if has_missing:
        print(Fore.RED + "\n[✘] Missing required tools:\n")
        for category, tools in missing.items():
            if tools:
                print(Fore.YELLOW + f"  {category.upper()}:")
                for tool in tools:
                    print(Fore.RED + f"    - {tool}")
        
        print(Fore.CYAN + "\n[i] Install missing tools and try again.")
        print(Fore.CYAN + "[i] On Debian/Ubuntu: sudo apt install <tool-name>")
        print(Fore.CYAN + "[i] For SearchSploit: sudo apt install exploitdb")
        sys.exit(1)
    else:
        print(Fore.GREEN + "[✓] All required tools are installed!\n")


def is_alive(ip: str) -> bool:
    """
    Check if the IP responds to ping
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        alive = result.returncode == 0
        if alive:
            print(Fore.GREEN + f"[✔] {ip} is alive (responds to ping).")
        else:
            print(Fore.YELLOW + f"[⚠] {ip} did not respond to ping.")
        return alive
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + f"[⚠] Ping timeout for {ip}.")
        return False
    except FileNotFoundError:
        print(Fore.RED + f"[✘] Ping command not found.")
        return False
    except Exception as e:
        print(Fore.RED + f"[✘] Error executing ping: {e}")
        return False


# ============================================================
# 🧠 Real-time execution (live output + logging)
# ============================================================

def run_command_live(cmd: list, log_file: Path = None) -> str:
    """
    Execute a command and display output in real-time on the terminal.
    Also save the complete output to a central log (session.log).
    """
    try:
        print(Fore.MAGENTA + f"\n[>] Executing: {' '.join(cmd)}\n")
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )

        output = ""
        for line in process.stdout:
            print(line, end="")
            output += line
            if log_file:
                try:
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(line)
                except Exception as e:
                    print(Fore.RED + f"[✘] Error writing to log file: {e}")

        process.wait()
        return output
    
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed with exit code {e.returncode}: {' '.join(cmd)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return ""
    except FileNotFoundError:
        error_msg = f"Command not found: {cmd[0]}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        log(Fore.YELLOW + f"[i] Make sure {cmd[0]} is installed and in your PATH", log_file)
        return ""
    except Exception as e:
        error_msg = f"Unexpected error running command: {str(e)}"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return ""


# ============================================================
# 🧾 Unified logging (session.log)
# ============================================================

def log(message: str, log_file: Path = None, color=Fore.CYAN):
    """
    Display and save framework messages (informational, errors, etc.)
    """
    try:
        print(color + message)
        if log_file:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(message + "\n")
    except Exception as e:
        print(Fore.RED + f"[✘] Error logging message: {e}")


# ============================================================
# 📜 Writing and reports (only one file per target)
# ============================================================

def append_section(report_path: Path, title: str, content: str):
    """
    Add formatted sections to the main report.
    """
    try:
        with report_path.open("a", encoding="utf-8") as f:
            f.write("\n" + "=" * 70 + "\n")
            f.write(f"[ {title.upper()} ]\n")
            f.write("=" * 70 + "\n")
            f.write((content or "").strip() + "\n")
        print(Fore.BLUE + f"[✔] Section '{title}' added to report.")
    except FileNotFoundError:
        print(Fore.RED + f"[✘] Report file not found: {report_path}")
    except PermissionError:
        print(Fore.RED + f"[✘] Permission denied writing to: {report_path}")
    except Exception as e:
        print(Fore.RED + f"[✘] Error adding section '{title}': {e}")
