# config.py — CarapauCracker Configuration
"""
Centralized configuration management for CarapauCracker
"""
import os
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================
# 📁 Paths Configuration
# ============================================================
BASE_DIR = Path(__file__).parent.parent
OUTPUTS_DIR = BASE_DIR / "outputs"
WORDLISTS_DIR = BASE_DIR / "wordlists"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure directories exist
OUTPUTS_DIR.mkdir(exist_ok=True)
WORDLISTS_DIR.mkdir(exist_ok=True)

# ============================================================
# 🔧 Tool Configuration
# ============================================================
DEFAULT_WORDLISTS = {
    "users": WORDLISTS_DIR / "users.txt.txt",
    "passwords": WORDLISTS_DIR / "rockyou.txt.txt",
    "directories": WORDLISTS_DIR / "common.txt" if (WORDLISTS_DIR / "common.txt").exists() else None
}

# ============================================================
# 🌐 API Configuration
# ============================================================
NVD_API_KEY = os.getenv("NVD_API_KEY", None)
GEOIP_API_URL = "http://ip-api.com/json"
GEOIP_TIMEOUT = 10

# ============================================================
# ⚙️ Scan Configuration
# ============================================================
SCAN_CONFIG = {
    "nmap_timeout": 300,  # 5 minutes
    "nmap_threads": 4,
    "hydra_threads": 4,
    "hydra_timeout": 5,
    "gobuster_threads": 50,
    "ffuf_threads": 30,
    "max_ports": 65535,
    "top_udp_ports": 50
}

# ============================================================
# 🔒 Security Configuration
# ============================================================
ALLOWED_PROTOCOLS = ["http", "https", "ftp", "ssh", "telnet", "smtp"]
ALLOWED_IP_PATTERNS = [
    r"^(\d{1,3}\.){3}\d{1,3}$",  # IPv4
    r"^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$",  # IPv6 (simplified)
]
MAX_INPUT_LENGTH = 255
MAX_PORT = 65535
MIN_PORT = 1

# ============================================================
# 📊 Logging Configuration
# ============================================================
LOG_LEVELS = {
    "DEBUG": 0,
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4
}

LOG_FORMAT = "[{timestamp}] [{level}] {message}"
LOG_FILE_ENCODING = "utf-8"

# ============================================================
# 🎨 UI Configuration
# ============================================================
UI_CONFIG = {
    "show_progress": True,
    "color_output": True,
    "table_style": "rounded",
    "progress_bar_style": "bar"
}

# ============================================================
# 🔍 Validation Functions
# ============================================================
def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    import re
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def validate_port(port: int) -> bool:
    """Validate port number"""
    return MIN_PORT <= port <= MAX_PORT


def validate_hostname(hostname: str) -> bool:
    """Basic hostname validation"""
    if not hostname or len(hostname) > MAX_INPUT_LENGTH:
        return False
    # Basic validation - allow letters, numbers, dots, hyphens
    import re
    pattern = r"^[a-zA-Z0-9.-]+$"
    return bool(re.match(pattern, hostname))


def sanitize_input(user_input: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not user_input:
        return ""
    # Remove dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    sanitized = user_input
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    # Truncate to max length
    return sanitized[:max_length].strip()


# ============================================================
# 🖥️ Platform Detection
# ============================================================
def is_windows() -> bool:
    """Check if running on Windows"""
    return os.name == "nt"


def is_linux() -> bool:
    """Check if running on Linux"""
    return os.name == "posix" and os.uname().sysname == "Linux"


def get_ping_command(ip: str) -> List[str]:
    """Get platform-specific ping command"""
    if is_windows():
        return ["ping", "-n", "1", "-w", "1000", ip]
    else:
        return ["ping", "-c", "1", "-W", "1", ip]


def get_clear_command() -> str:
    """Get platform-specific clear command"""
    return "cls" if is_windows() else "clear"
