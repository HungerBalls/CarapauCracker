#!/bin/bash
# ======================================================================
#  🐟 CarapauCracker Installer v3
#  Framework de Pentesting Avançado 🇵🇹 — by HungerBalls 🎯
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
echo " | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < "
echo "  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\\"
echo -e "${YELLOW}                Framework de Pentesting Avançado — por HungerBalls${NC}\n"
sleep 1

# ======================================================================
# 1️⃣ - Verificar permissões
# ======================================================================
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[✘] Este instalador deve ser executado como root (usa: sudo bash install.sh).${NC}"
  exit 1
fi

# ======================================================================
# 2️⃣ - Atualizar o sistema
# ======================================================================
echo -e "${YELLOW}[⚙] A atualizar repositórios do sistema...${NC}"
apt update -y >/dev/null 2>&1 && apt upgrade -y >/dev/null 2>&1
echo -e "${GREEN}[✔] Sistema atualizado com sucesso.${NC}\n"

# ======================================================================
# 3️⃣ - Instalar Python e dependências
# ======================================================================
echo -e "${CYAN}[🐍] A instalar Python e bibliotecas necessárias...${NC}"
apt install -y python3 python3-pip >/dev/null 2>&1
pip install --upgrade pip >/dev/null 2>&1

if [ -f "requirements.txt" ]; then
    echo -e "${YELLOW}→ A instalar dependências listadas em requirements.txt...${NC}"
    pip install -r requirements.txt >/dev/null 2>&1 && \
    echo -e "${GREEN}[✔] Dependências Python instaladas.${NC}\n"
else
    echo -e "${RED}[!] Ficheiro requirements.txt não encontrado. Podes criá-lo manualmente.${NC}\n"
fi

# ======================================================================
# 4️⃣ - Instalar ferramentas externas
# ======================================================================
TOOLS=(
  nmap whois curl whatweb nikto gobuster ffuf sslscan hydra
  exploitdb figlet jq
)

echo -e "${CYAN}[🧰] A instalar ferramentas de pentesting necessárias...${NC}"
for TOOL in "${TOOLS[@]}"; do
  if ! command -v $TOOL &>/dev/null; then
    echo -e "${YELLOW}   → A instalar ${TOOL}...${NC}"
    apt install -y "$TOOL" >/dev/null 2>&1
    if command -v $TOOL &>/dev/null; then
      echo -e "${GREEN}   [✔] ${TOOL} instalado com sucesso.${NC}"
    else
      echo -e "${RED}   [!] Falha ao instalar ${TOOL}.${NC}"
    fi
  else
    echo -e "${GREEN}   [✓] ${TOOL} já está instalado.${NC}"
  fi
done
echo ""

# ======================================================================
# 5️⃣ - Preparar estrutura de pastas
# ======================================================================
echo -e "${CYAN}[📁] A preparar estrutura de diretórios...${NC}"
mkdir -p outputs wordlists >/dev/null 2>&1
touch wordlists/users.txt >/dev/null 2>&1
echo -e "${GREEN}[✔] Estrutura criada (outputs/, wordlists/).${NC}\n"

# ======================================================================
# 6️⃣ - Finalização
# ======================================================================
echo -e "${GREEN}[✔] Instalação concluída com sucesso!${NC}\n"
echo -e "${CYAN}Para iniciar o CarapauCracker, executa:${NC}"
echo -e "${YELLOW}  python3 main.py${NC}\n"
echo -e "${CYAN}Boa pescaria hacker, marinheiro do ciberespaço 🐟⚓${NC}\n"

