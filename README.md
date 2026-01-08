<div align="center">

# 🐟 CarapauCracker

```
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
```

**Framework Modular de Penetration Testing em Python**

*Automatização inteligente para testes de segurança em ambientes controlados* 🔒

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue? logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green. svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Educational%20Only-red)](README.md#-aviso-legal)

[Características](#-características-principais) •
[Instalação](#-instalação) •
[Utilização](#-utilização) •
[Módulos](#-módulos-disponíveis) •
[Documentação](#-estrutura-do-projeto) •
[Avisos Legais](#-aviso-legal)

</div>

---

## 📋 Sobre o Projeto

**CarapauCracker** é uma framework modular de pentesting desenvolvida inteiramente em Python que automatiza e centraliza as fases críticas de um teste de penetração em ambientes controlados de laboratório. 

Criada para profissionais de cibersegurança, investigadores e entusiastas de ethical hacking, esta ferramenta oferece uma interface CLI intuitiva que integra as ferramentas mais reconhecidas da indústria numa plataforma unificada.

### 🎯 Objetivos

- ✅ **Automatização**:  Reduzir tarefas repetitivas durante pentests
- ✅ **Centralização**: Unificar múltiplas ferramentas numa única interface
- ✅ **Documentação**: Gerar relatórios profissionais automaticamente
- ✅ **Modularidade**: Arquitetura extensível e fácil de manter
- ✅ **Educação**: Ferramenta de aprendizagem para técnicas de pentesting

---

## ✨ Características Principais

### 🔍 **1. Reconhecimento Avançado**

- ✓ Verificação de disponibilidade de host (ICMP ping)
- ✓ Reverse DNS lookup automático
- ✓ WHOIS integration para informação de registo
- ✓ GeoIP localização via API externa
- ✓ Banner grabbing multi-protocolo (FTP, SSH, HTTP)

### 🔎 **2. Scanning de Rede & Sistema**

- **Quick Scan**: Identificação rápida de portas comuns
- **Detailed Scan**: Detecção de versões e scripts NSE (`-sV -sC`)
- **Full TCP Scan**: Análise completa de todas as 65535 portas
- **UDP Scan**: Scanning das 50 portas UDP mais comuns
- **OS Detection**: Fingerprinting de sistema operativo
- **Aggressive Scan**: Modo agressivo com todas as técnicas (`-A`)

### 🌐 **3. Enumeração Web Completa**

| Ferramenta | Função |
|------------|--------|
| **HTTP Analysis** | Análise de headers e configurações |
| **WhatWeb** | Identificação de tecnologias e frameworks |
| **Nikto** | Scanning profundo de vulnerabilidades web |
| **Gobuster** | Directory/file bruteforce eficiente |
| **FFUF** | Fuzzing de alta performance |
| **Nmap NSE** | Scripts HTTP especializados |
| **SSLScan** | Análise detalhada de SSL/TLS |
| **WPScan** | Scanning específico para WordPress |

### 💣 **4. Descoberta de Exploits**

- 🔎 Integração com **SearchSploit** (Exploit-DB)
- 🧰 Pesquisa automática no **Metasploit Framework**
- 🎯 Classificação inteligente por severidade (RCE, Auth Bypass, LPE, DoS)
- ⚡ Sistema de ranking de exploits por prioridade
- 🚀 Lançamento automatizado de exploits MSF

### 🔑 **5. Ataques de Credenciais (Hydra)**

- 🔓 SSH bruteforce
- 🔓 FTP authentication testing
- 🔓 HTTP Basic Auth cracking
- 🔓 HTTP POST form attacks
- 📝 Suporte para wordlists customizadas
- ⚡ Teste rápido de credenciais conhecidas/default

### 📄 **6. Sistema de Relatórios**

- 📝 Relatório TXT unificado e estruturado
- 📄 Export automático para **PDF** profissional
- 🗂️ Export para **JSON** com dados estruturados
- 🕐 Logging detalhado com timestamps
- 🗃️ Organização por sessões e alvos

---

## 🛠️ Requisitos

### Sistema Operativo

- **Linux** (Kali Linux, Parrot OS, Ubuntu, Debian)
- **Python 3.8+**

### Ferramentas Externas

As seguintes ferramentas devem estar instaladas no sistema:

```bash
# Core Tools
nmap, masscan, whois, dig

# Web Enumeration
nikto, gobuster, ffuf, whatweb, wpscan, sslscan

# Exploitation
metasploit-framework, searchsploit

# Brute Force
hydra

# Utilities
curl, wget
```

### Dependências Python

```bash
colorama
requests
python-whois
fpdf
```

---

## 📦 Instalação

### Método 1: Instalação Automática (Recomendado)

```bash
# 1. Clonar o repositório
git clone https://github.com/HungerBalls/CarapauCracker.git
cd CarapauCracker

# 2. Executar o script de instalação
chmod +x install.sh
sudo ./install.sh

# 3. Iniciar a framework
python3 main.py
```

### Método 2: Instalação Manual

```bash
# 1. Clonar o repositório
git clone https://github.com/HungerBalls/CarapauCracker.git
cd CarapauCracker

# 2. Instalar dependências Python
pip3 install -r requirements.txt

# 3. Instalar ferramentas externas (exemplo para Debian/Ubuntu)
sudo apt update
sudo apt install nmap nikto hydra gobuster ffuf whatweb wpscan \
                 metasploit-framework exploitdb sslscan masscan \
                 whois dnsutils curl wget -y

# 4. Criar diretórios necessários
mkdir -p outputs wordlists

# 5. Executar
python3 main.py
```

---

## 🚀 Utilização

### Início Rápido

```bash
python3 main.py
```

### Fluxo de Trabalho Típico

```
1. Introduzir alvo (IP ou hostname)
   └─> Verificação automática de conectividade

2. Menu Principal - Escolher módulo: 
   ├─> 1. Reconhecimento Básico
   │   └─> WHOIS, GeoIP, DNS, Banner Grabbing
   │
   ├─> 2. Scanning de Portas
   │   └─> Quick/Detailed/Full TCP/UDP/OS Detection
   │
   ├─> 3. Enumeração Web
   │   └─> Headers, WhatWeb, Nikto, Gobuster, FFUF
   │
   ├─> 4. Exploração
   │   └─> SearchSploit, Metasploit
   │
   ├─> 5. Brute Force
   │   └─> SSH, FTP, HTTP (Hydra)
   │
   └─> 6. Exportar Relatório
       └─> PDF, JSON, TXT

3. Resultados salvos em:
   outputs/<target>/<timestamp>/
```

### Exemplo de Sessão

```bash
$ python3 main.py

[🎯] Introduz o IP ou hostname do alvo:  192.168.1.100
[✔] Sessão criada em: outputs/192.168.1.100/20260108_143022

╭────────────[ MENU PRINCIPAL - CARAPAUPANEL ]────────────╮
│ 1 - Reconhecimento Básico
│ 2 - Scanning de Portas & Sistema
│ 3 - Enumeração Web Avançada
│ 4 - Exploração Automática (MSF + Searchsploit)
│ 5 - Ataques de Força Bruta (Hydra)
│ 6 - Exportar Relatório Final 📄
│ 0 - Terminar Sessão ⛔
╰──────────────────────────────────────────────────────────╯

[»] Escolhe o teu módulo:  1
```

---

## 📁 Estrutura do Projeto

```
CarapauCracker/
├── main.py                 # Ponto de entrada principal
├── install.sh              # Script de instalação automática
├── requirements.txt        # Dependências Python
│
├── modules/                # Módulos funcionais
│   ├── recon.py           # Reconhecimento (WHOIS, DNS, GeoIP)
│   ├── scan.py            # Port scanning (Nmap, Masscan)
│   ├── web_enum.py        # Enumeração web (Nikto, Gobuster, FFUF)
│   ├── exploit.py         # Exploit discovery (SearchSploit, MSF)
│   ├── brute_force.py     # Ataques de credenciais (Hydra)
│   ├── report.py          # Geração de relatórios (PDF, JSON)
│   └── utils.py           # Utilitários (logging, execução, banner)
│
├── menus/                  # Menus interativos
│   ├── menu_recon.py
│   ├── menu_scan.py
│   ├── menu_web_enum.py
│   ├── menu_exploit.py
│   └── menu_brute. py
│
├── wordlists/              # Wordlists para fuzzing e bruteforce
│   ├── common.txt
│   ├── users.txt
│   └── rockyou.txt
│
└── outputs/                # Resultados de sessões
    └── <target>/
        └── <timestamp>/
            ├── report.txt
            ├── report. pdf
            ├── report.json
            └── session. log
```

---

## 🔧 Módulos Disponíveis

### 1️⃣ Módulo de Reconhecimento (`modules/recon.py`)

```python
# Funções principais
whois_lookup(target)      # WHOIS information
geoip_lookup(target)      # Geolocalização IP
reverse_dns(target)       # DNS reverso
banner_grab(ip, port)     # Banner grabbing
basic_recon(target)       # Reconhecimento completo
```

### 2️⃣ Módulo de Scanning (`modules/scan.py`)

```python
quick_scan(target)        # Top 1000 portas
detailed_scan(target)     # Version detection + NSE
full_tcp_scan(target)     # Todas as portas TCP
udp_scan(target)          # Top 50 portas UDP
os_detection(target)      # OS fingerprinting
aggressive_scan(target)   # Scan agressivo completo
```

### 3️⃣ Módulo Web (`modules/web_enum.py`)

```python
http_headers(target, port)
whatweb_scan(target, port)
nikto_scan(target, port)
gobuster_dirs(target, port, wordlist)
ffuf_dirfuzz(target, port, wordlist)
sslscan(target, port)
wpscan_scan(target, port)
```

### 4️⃣ Módulo de Exploits (`modules/exploit.py`)

```python
searchsploit_search(service, version)
msf_search(keyword)
rank_exploits(exploits)
launch_msf_exploit(module, target, port)
```

### 5️⃣ Módulo de Brute Force (`modules/brute_force.py`)

```python
brute_ssh(target, userlist, passlist)
brute_ftp(target, userlist, passlist)
brute_http_basic(target, port, userlist, passlist)
brute_http_post(target, port, path, userlist, passlist)
```

---

## 📊 Relatórios

### Formato TXT

```
================== CARAPAUPANEL FINAL REPORT ==================
Target: 192.168.1.100
Scan Date: 2026-01-08 14:30:22

[WHOIS]
Domain: example.com
Registrar: Example Inc.
... 

[NMAP SCAN]
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1
80/tcp   open  http       Apache 2.4.41
... 
```

### Formato PDF

- Header profissional com logo
- Secções organizadas
- Tabelas formatadas
- Timestamps e metadata

### Formato JSON

```json
{
  "target":  "192.168.1.100",
  "timestamp": "2026-01-08T14:30:22",
  "sections": {
    "whois": { ... },
    "nmap":  { ... },
    "exploits": [ ... ]
  }
}
```

---

## ⚠️ AVISO LEGAL

> **APENAS PARA FINS EDUCACIONAIS E TESTES AUTORIZADOS**

```
⚖️ TERMOS DE USO E RESPONSABILIDADE

Este software é fornecido "AS IS" exclusivamente para: 
✓ Ambientes de laboratório controlados
✓ Testes de penetração autorizados por escrito
✓ Fins educacionais e de pesquisa
✓ Auditorias de segurança legítimas

❌ UTILIZAÇÃO ILEGAL PROIBIDA: 
- Testes em sistemas sem autorização explícita
- Ataques a infraestruturas de terceiros
- Qualquer atividade que viole leis locais/internacionais

O autor NÃO se responsabiliza por:
- Uso indevido ou ilegal desta ferramenta
- Danos causados a sistemas ou redes
- Consequências legais de ações não autorizadas

Ao utilizar este software, você concorda em: 
1. Obter autorização escrita antes de qualquer teste
2. Respeitar todas as leis aplicáveis
3. Assumir total responsabilidade pelas suas ações

🔒 "With great power comes great responsibility"
```

---

## 🤝 Contribuições

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Cria uma branch para a tua feature (`git checkout -b feature/AmazingFeature`)
3. Commit as tuas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abre um Pull Request

### Ideias para Contribuição

- 🆕 Novos módulos (e. g., WiFi testing, mobile security)
- 🐛 Correção de bugs
- 📚 Melhorias na documentação
- 🎨 Interface gráfica (GUI)
- 🔌 Integrações com outras ferramentas

---

## 📜 Licença

Este projeto está licenciado sob a **MIT License** - vê o ficheiro [LICENSE](LICENSE) para detalhes.

---

## 📞 Contacto & Suporte

- **Autor**: HungerBalls
- **GitHub**: [@HungerBalls](https://github.com/HungerBalls)
- **Projeto**: [CarapauCracker](https://github.com/HungerBalls/CarapauCracker)

### Reportar Issues

Encontraste um bug ou tens uma sugestão? [Abre uma issue](https://github.com/HungerBalls/CarapauCracker/issues)! 

---

## 🌟 Agradecimentos

Ferramentas e projetos que tornaram isto possível:

- [Nmap](https://nmap.org/) - Network scanning
- [Metasploit](https://www.metasploit.com/) - Exploitation framework
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Brute force attacks
- [Gobuster](https://github.com/OJ/gobuster) - Directory brute forcing
- [Nikto](https://cirt.net/Nikto2) - Web server scanning
- [FFUF](https://github.com/ffuf/ffuf) - Web fuzzing

---

<div align="center">

**🐟 CarapauCracker - Pescando vulnerabilidades com estilo ⚓**

Made with ❤️ and 🐍 Python

[⬆ Voltar ao topo](#-carapaucracker)

</div>
