# 🐟 CarapauCracker

```
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
                                                                                           
```

**Framework de Penetration Testing Automatizado**  
*Desenvolvido para o Projeto Final do CTeSP em Cibersegurança*

---

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades](#-funcionalidades)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Utilização](#-utilização)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Módulos Disponíveis](#-módulos-disponíveis)
- [Relatórios](#-relatórios)
- [Licença](#-licença)

---

## 🎯 Sobre o Projeto

**CarapauCracker** é uma framework modular de pentesting desenvolvida em Python que automatiza fases cruciais de um teste de penetração em ambientes controlados de laboratório.

O objetivo é fornecer uma interface interativa e intuitiva que permite:
- Reconhecimento passivo e ativo
- Scanning de portas e serviços
- Enumeração web avançada
- Descoberta automática de exploits
- Ataques de força bruta coordenados
- Geração de relatórios profissionais

---

## ✨ Funcionalidades

### 🔍 **1. Reconhecimento Básico**
- Verificação de host ativo (ping)
- Reverse DNS lookup
- WHOIS lookup
- GeoIP localização
- Banner grabbing (FTP, SSH, HTTP)

### 🔎 **2. Scanning de Portas & Sistema**
- Quick Scan (portas comuns)
- Detailed Scan (`-sV -sC`)
- Full TCP Scan (1-65535)
- UDP Scan (top 50 portas)
- OS Detection
- Aggressive Scan (`-A`)

### 🌐 **3. Enumeração Web Avançada**
- HTTP Headers analysis
- robots.txt discovery
- HTTP Methods enumeration
- WhatWeb (detecção de tecnologias)
- Nikto (scan de vulnerabilidades)
- Gobuster (directory bruteforce)
- FFUF (fuzzing rápido)
- Nmap HTTP scripts (NSE)
- SSLScan (análise SSL/TLS)
- WPScan (WordPress específico)

### 💣 **4. Exploração Automática**
- SearchSploit integration
- Metasploit module search
- Classificação por severidade (RCE, Auth Bypass, LPE, DoS)
- Lançamento automático de exploits MSF

### 🔑 **5. Ataques de Força Bruta**
- SSH bruteforce (Hydra)
- FTP bruteforce
- HTTP Basic Auth
- HTTP POST forms
- Suporte para wordlists customizadas
- Teste de credenciais conhecidas

### 📄 **6. Relatórios**
- Relatório TXT unificado
- Export para PDF profissional
- Export para JSON estruturado
- Logging detalhado de todas as operações

---

## 🛠️ Requisitos

### Dependências do Sistema

As seguintes ferramentas **devem estar instaladas** no sistema:

```bash
# Kali Linux / Parrot OS (já incluídas)
nmap
hydra
nikto
gobuster
ffuf
whatweb
wpscan
searchsploit
metasploit-framework
curl
whois
sslscan
```

### Dependências Python

```bash
Python 3.8+
colorama
requests
fpdf
```

---

## 📦 Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/seu-username/CarapauCracker.git
cd CarapauCracker
```

### 2. Instalar dependências Python

```bash
pip install -r requirements.txt
```

### 3. Verificar ferramentas do sistema

```bash
# Verificar se todas as ferramentas estão instaladas
which nmap hydra nikto gobuster ffuf whatweb wpscan searchsploit msfconsole
```

### 4. Configurar wordlists (opcional)

```bash
# Criar diretório de wordlists
mkdir -p wordlists

# Copiar wordlists comuns
cp /usr/share/wordlists/rockyou.txt wordlists/
cp /usr/share/wordlists/dirb/common.txt wordlists/

# Criar wordlist básica de users
echo -e "admin\nroot\nuser\nadministrator" > wordlists/users.txt
```

---

## 🚀 Utilização

### Execução Básica

```bash
cd CarapauCracker
python3 main.py
```

### Fluxo de Trabalho Típico

1. **Iniciar a framework**
   ```bash
   python3 main.py
   ```

2. **Introduzir o alvo**
   ```
   [🎯] Introduz o IP ou hostname do alvo: 192.168.1.100
   ```

3. **Navegação pelos menus**
   - Use os números para selecionar opções
   - Comece sempre pelo **Reconhecimento** (opção 1)
   - Execute **Scanning** (opção 2) para descobrir serviços
   - Use **Enumeração Web** (opção 3) se houver serviço HTTP
   - Execute **Exploração** (opção 4) para descobrir vulnerabilidades
   - Use **Força Bruta** (opção 5) com cuidado

4. **Gerar relatório**
   - Opção 6 no menu principal
   - Relatórios salvos em `outputs/<IP>/<timestamp>/`

### Exemplo de Sessão

```bash
$ python3 main.py

   ____                               ____                _             
  / ___|__ _ _ __ ___  ___ _ __ ___  |  _ \ ___  __ _  __| | ___  _ __  
 | |   / _` | '__/ __|/ _ \ '__/ __| | |_) / _ \/ _` |/ _` |/ _ \| '_ \ 
 | |__| (_| | |  \__ \  __/ |  \__ \ |  __/  __/ (_| | (_| | (_) | | | |
  \____\__,_|_|  |___/\___|_|  |___/ |_|   \___|\__,_|\__,_|\___/|_| |_|  

[🎯] Introduz o IP ou hostname do alvo: 192.168.1.100
[✔] 192.168.1.100 está ativo (responde a ping).
[✔] Sessão criada em: outputs/192.168.1.100/20260107_143022

╭────────────[ MENU PRINCIPAL - CARAPAUPANEL ]────────────╮
│ 1 - Reconhecimento Básico
│ 2 - Scanning de Portas & Sistema
│ 3 - Enumeração Web Avançada
│ 4 - Exploração Automática (MSF + Searchsploit)
│ 5 - Ataques de Força Bruta (Hydra)
│ 6 - Exportar Relatório Final 📄
│ 0 - Terminar Sessão ⛔
╰──────────────────────────────────────────────────────────╯

[»] Escolhe o teu módulo: _
```

---

## 📁 Estrutura do Projeto

```
CarapauCracker/
├── main.py                    # Entry point principal
├── requirements.txt           # Dependências Python
├── README.md                  # Este ficheiro
│
├── menus/                     # Submenus interativos
│   ├── menu_recon.py         # Menu de reconhecimento
│   ├── menu_scan.py          # Menu de scanning
│   ├── menu_web_enum.py      # Menu de enumeração web
│   ├── menu_exploit.py       # Menu de exploração
│   └── menu_brute.py         # Menu de força bruta
│
├── modules/                   # Módulos core da framework
│   ├── recon.py              # Funções de reconhecimento
│   ├── scan.py               # Wrappers do Nmap
│   ├── web_enum.py           # Enumeração web
│   ├── exploit.py            # SearchSploit & MSF integration
│   ├── brute_force.py        # Hydra wrappers
│   ├── report.py             # Geração de relatórios
│   └── utils.py              # Utilitários (banner, logging, etc)
│
├── wordlists/                 # Wordlists para bruteforce
│   ├── users.txt             # Lista de usernames
│   ├── passwords.txt         # Lista de passwords (pequena)
│   └── common.txt            # Diretórios comuns
│
└── outputs/                   # Outputs por alvo
    └── <IP>/
        └── <timestamp>/
            ├── report.txt    # Relatório unificado
            ├── report.pdf    # Relatório PDF
            ├── report.json   # Relatório JSON
            └── session.log   # Log completo da sessão
```

---

## 🔧 Módulos Disponíveis

### Reconhecimento (`modules/recon.py`)
- `reverse_dns()` - Reverse DNS lookup
- `whois_lookup()` - WHOIS query
- `geoip_lookup()` - Geolocalização via ip-api.com
- `banner_grab()` - Banner grabbing de serviços
- `basic_recon()` - Workflow completo de reconhecimento

### Scanning (`modules/scan.py`)
- `nmap_quick()` - Quick scan
- `nmap_detailed()` - Scan com detecção de versões
- `nmap_full_tcp()` - Scan de todas as portas TCP
- `nmap_udp_scan()` - Scan UDP
- `nmap_os_detection()` - Detecção de OS
- `nmap_aggressive()` - Scan agressivo

### Web Enumeration (`modules/web_enum.py`)
- `http_headers()` - Análise de headers HTTP
- `robots_txt()` - Descoberta de robots.txt
- `whatweb_scan()` - Identificação de tecnologias
- `nikto_scan()` - Scan de vulnerabilidades web
- `gobuster_dirs()` - Directory bruteforce
- `ffuf_dirfuzz()` - Fuzzing rápido
- `nmap_http_enum()` - Scripts NSE HTTP
- `wpscan_scan()` - WordPress specific scan

### Exploração (`modules/exploit.py`)
- `parse_nmap_services()` - Parser de serviços Nmap
- `searchsploit_lookup()` - Pesquisa no SearchSploit
- `metasploit_lookup()` - Pesquisa no Metasploit
- `classify_exploit()` - Classificação por severidade
- `launch_msf_exploit()` - Lançamento automático MSF

### Força Bruta (`modules/brute_force.py`)
- `brute_ssh()` - SSH bruteforce
- `brute_ftp()` - FTP bruteforce
- `brute_http_basic()` - HTTP Basic Auth
- `brute_http_post()` - HTTP POST forms
- `test_credentials()` - Teste de credenciais conhecidas

---

## 📊 Relatórios

Os relatórios são gerados automaticamente e salvos em:

```
outputs/<IP>/<timestamp>/
├── report.txt      # Relatório unificado (texto)
├── report.pdf      # Relatório PDF profissional
├── report.json     # Dados estruturados em JSON
└── session.log     # Log completo com timestamps
```

### Exemplo de Conteúdo

```
======================================================================
[ RECONHECIMENTO BÁSICO ]
======================================================================
Target IP: 192.168.1.100
Hostname: server.local
Country: Portugal (Lisboa)
Org/ISP: NOS Comunicações

[ WHOIS OUTPUT ]
...

======================================================================
[ NMAP QUICK SCAN ]
======================================================================
Starting Nmap 7.95 ( https://nmap.org )
...
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

======================================================================
[ EXPLOITS - VSFTPD 2.3.4 ]
======================================================================
[RCE] vsftpd 2.3.4 - Backdoor Command Execution
...
```


---


## 📄 Licença

Este projeto está sob a licença **MIT**. Consulta o ficheiro [LICENSE](LICENSE) para mais detalhes.



**Made with ❤️ in Portugal 🇵🇹**

*"A melhor defesa é conhecer o ataque"*

