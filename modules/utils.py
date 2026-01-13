# utils.py — CarapauCracker v3
from pathlib import Path
from datetime import datetime
import subprocess
import shutil
import os
import sys
from typing import Optional, List
from colorama import Fore, init
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from modules.config import (
    OUTPUTS_DIR, get_ping_command, get_clear_command,
    validate_ip, validate_hostname, sanitize_input
)

init(autoreset=True)


# ============================================================
# 🐟 Beautiful and consistent banner across all menus
# ============================================================

def banner():
    """Clear screen and display CarapauCracker banner"""
    try:
        clear_cmd = get_clear_command()
        os.system(clear_cmd)
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
    
    Args:
        target: Target IP or hostname (will be sanitized)
    
    Returns:
        Path to the created session directory
    
    Raises:
        ValueError: If target is invalid
        OSError: If directory creation fails
    """
    try:
        # Sanitize target to prevent path traversal
        target = sanitize_input(target)
        if not target:
            raise ValueError("Target cannot be empty")
        
        # Validate target format
        if not (validate_ip(target) or validate_hostname(target)):
            raise ValueError(f"Invalid target format: {target}")
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use sanitized target in path
        safe_target = target.replace(":", "_").replace("/", "_")
        run_dir = OUTPUTS_DIR / safe_target / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        print(Fore.GREEN + f"[✔] Session created at: {run_dir}")
        return run_dir
    except ValueError as e:
        print(Fore.RED + f"[✘] Invalid target: {e}")
        raise
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
    Check if the IP responds to ping (platform-agnostic)
    
    Args:
        ip: IP address to ping (will be validated)
    
    Returns:
        True if host responds to ping, False otherwise
    """
    try:
        # Validate and sanitize IP
        if not validate_ip(ip):
            print(Fore.YELLOW + f"[⚠] Invalid IP format: {ip}")
            return False
        
        # Get platform-specific ping command
        ping_cmd = get_ping_command(ip)
        
        result = subprocess.run(
            ping_cmd,
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

def run_command_live(cmd: List[str], log_file: Optional[Path] = None, timeout: Optional[int] = None) -> str:
    """
    Execute a command and display output in real-time on the terminal.
    Also save the complete output to a central log (session.log).
    
    Args:
        cmd: Command to execute as a list of strings
        log_file: Optional path to log file
        timeout: Optional timeout in seconds
    
    Returns:
        Command output as string
    
    Security:
        Commands are executed as-is. Ensure cmd is from trusted sources.
    """
    if not cmd or not isinstance(cmd, list):
        error_msg = "Invalid command: must be a non-empty list"
        log(Fore.RED + f"[✘] {error_msg}", log_file)
        return ""
    
    try:
        # Sanitize command display (don't execute sanitized version, just for display)
        cmd_display = ' '.join(str(arg) for arg in cmd)
        print(Fore.MAGENTA + f"\n[>] Executing: {cmd_display}\n")
        
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        output = ""
        try:
            for line in process.stdout:
                if line:
                    print(line, end="")
                    output += line
                    if log_file:
                        try:
                            with open(log_file, "a", encoding="utf-8") as f:
                                f.write(line)
                        except Exception as e:
                            print(Fore.RED + f"[✘] Error writing to log file: {e}")
            
            # Wait for process with optional timeout
            if timeout:
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    error_msg = f"Command timed out after {timeout} seconds"
                    log(Fore.RED + f"[✘] {error_msg}", log_file)
                    return output
            else:
                process.wait()
        except KeyboardInterrupt:
            process.kill()
            log(Fore.YELLOW + "\n[⚠] Command interrupted by user", log_file)
            raise
        
        return output
    
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed with exit code {e.returncode}: {cmd_display}"
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

def log(message: str, log_file: Optional[Path] = None, color=Fore.CYAN, level: str = "INFO"):
    """
    Display and save framework messages (informational, errors, etc.)
    
    Args:
        message: Message to log
        log_file: Optional path to log file
        color: Colorama color code for terminal output
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] [{level}] {message}"
        
        print(color + message)
        if log_file:
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(formatted_msg + "\n")
            except (PermissionError, OSError) as e:
                print(Fore.RED + f"[✘] Error writing to log file: {e}")
    except Exception as e:
        print(Fore.RED + f"[✘] Error logging message: {e}")


# ============================================================
# 📜 Writing and reports (only one file per target)
# ============================================================

def append_section(report_path: Path, title: str, content: str):
    """
    Add formatted sections to the main report.
    
    Args:
        report_path: Path to report file
        title: Section title
        content: Section content (will be sanitized)
    """
    try:
        # Sanitize title and content
        title = sanitize_input(title, max_length=100)
        if content:
            # Limit content size to prevent huge reports
            max_content_size = 1000000  # 1MB
            if len(content) > max_content_size:
                content = content[:max_content_size] + "\n\n[Content truncated due to size limit]"
        
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
