#!/bin/bash
# ======================================================================
#  🐟 CarapauCracker Installer v4
#  Advanced Pentesting Framework 🇬🇧 — by HungerBalls 🎯
# ======================================================================

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No color

clear
echo -e "${CYAN}"
echo "   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  "
echo "  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ "
echo " | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |"
echo " | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| .  \| |___|  _ < "
echo "  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\\"
echo -e "${YELLOW}                Advanced Pentesting Framework — by HungerBalls${NC}\n"
sleep 1

# ======================================================================
# Progress Bar Function
# ======================================================================
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    
    printf "\r${CYAN}["
    printf "%${completed}s" | tr ' ' '█'
    printf "%$((width - completed))s" | tr ' ' '░'
    printf "] ${percentage}%%${NC}"
}

# ======================================================================
# 1️⃣ - Check Permissions
# ======================================================================
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[✘] This installer must be run as root (use:  sudo bash install.sh).${NC}"
  exit 1
fi

# ======================================================================
# 2️⃣ - Update System
# ======================================================================
echo -e "${YELLOW}[⚙] Updating system repositories...${NC}"
echo -e "${CYAN}→ Running apt update...${NC}"
apt update -y 2>&1 | while read line; do
    echo -e "${CYAN}  $line${NC}"
done

echo -e "\n${CYAN}→ Running apt upgrade (this may take a while)...${NC}"
DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>&1 | pv -p -t -e -N "Upgrading packages" > /dev/null 2>&1 || \
apt upgrade -y 2>&1 | while read line; do
    if [[ "$line" == *"Unpacking"* ]] || [[ "$line" == *"Setting up"* ]] || [[ "$line" == *"Processing"* ]]; then
        echo -e "${GREEN}  ✓ $line${NC}"
    fi
done

echo -e "${GREEN}[✔] System updated successfully.${NC}\n"

# ======================================================================
# 3️⃣ - Install Python and Dependencies
# ======================================================================
echo -e "${CYAN}[🐍] Installing Python and necessary libraries...${NC}"

echo -e "${YELLOW}→ Installing python3 and pip...${NC}"
apt install -y python3 python3-pip 2>&1 | grep -E "Setting up|Unpacking" | while read line; do
    echo -e "${GREEN}  ✓ $line${NC}"
done

echo -e "${YELLOW}→ Upgrading pip...${NC}"
pip install --upgrade pip --progress-bar on 2>&1

if [ -f "requirements.txt" ]; then
    echo -e "${YELLOW}→ Installing dependencies from requirements.txt...${NC}"
    
    # Count total dependencies
    TOTAL_DEPS=$(wc -l < requirements.txt)
    CURRENT=0
    
    while IFS= read -r package; do
        # Skip empty lines and comments
        [[ -z "$package" || "$package" =~ ^#. * ]] && continue
        
        CURRENT=$((CURRENT + 1))
        show_progress $CURRENT $TOTAL_DEPS
        echo -ne " Installing ${package}.. .\r"
        
        pip install "$package" --progress-bar off >/dev/null 2>&1
    done < requirements.txt
    
    echo -e "\n${GREEN}[✔] Python dependencies installed. ${NC}\n"
else
    echo -e "${RED}[!] requirements.txt file not found. You can create it manually.${NC}\n"
fi

# ======================================================================
# 4️⃣ - Install External Tools
# ======================================================================
TOOLS=(
  nmap whois curl whatweb nikto gobuster ffuf sslscan hydra
  exploitdb figlet jq
)

TOTAL_TOOLS=${#TOOLS[@]}
CURRENT_TOOL=0

echo -e "${CYAN}[🧰] Installing necessary pentesting tools...${NC}"
for TOOL in "${TOOLS[@]}"; do
  CURRENT_TOOL=$((CURRENT_TOOL + 1))
  
  if ! command -v $TOOL &>/dev/null; then
    echo -e "${YELLOW}   → Installing ${TOOL}...${NC}"
    
    apt install -y "$TOOL" 2>&1 | grep -E "Setting up|Unpacking" | while read line; do
        echo -e "${CYAN}     $line${NC}"
    done
    
    if command -v $TOOL &>/dev/null; then
      show_progress $CURRENT_TOOL $TOTAL_TOOLS
      echo -e " ${GREEN}[✔] ${TOOL} installed successfully.${NC}"
    else
      echo -e "${RED}   [!] Failed to install ${TOOL}.${NC}"
    fi
  else
    show_progress $CURRENT_TOOL $TOTAL_TOOLS
    echo -e " ${GREEN}[✓] ${TOOL} already installed.${NC}"
  fi
done
echo ""

# ======================================================================
# 5️⃣ - Prepare Folder Structure
# ======================================================================
echo -e "${CYAN}[📁] Preparing directory structure...${NC}"
mkdir -p outputs wordlists >/dev/null 2>&1
touch wordlists/users.txt >/dev/null 2>&1
echo -e "${GREEN}[✔] Structure created (outputs/, wordlists/).${NC}\n"

# ======================================================================
# 6️⃣ - Finalization
# ======================================================================
echo -e "${GREEN}[✔] Installation completed successfully!${NC}\n"
echo -e "${CYAN}To start CarapauCracker, run:${NC}"
echo -e "${YELLOW}  python3 main.py${NC}\n"
echo -e "${CYAN}Happy hacking, cyber sailor 🐟⚓${NC}\n"
