# 🐟 CarapauCracker

```
   ____    _    ____      _    ____   _   _   _  ____ ____      _    ____ _  _______ ____  
  / ___|  / \  |  _ \    / \  |  _ \ / \ | | | |/ ___|  _ \    / \  / ___| |/ / ____|  _ \ 
 | |     / _ \ | |_) |  / _ \ | |_) / _ \| | | | |   | |_) |  / _ \| |   | ' /|  _| | |_) |
 | |___ / ___ \|  _ <  / ___ \|  __/ ___ \ |_| | |___|  _ <  / ___ \ |___| . \| |___|  _ < 
  \____/_/   \_\_| \_\/_/   \_\_| /_/   \_\___/ \____|_| \_\/_/   \_\____|_|\_\_____|_| \_\
                                                                                           
```
Framework Modular de Penetration Testing
Automatização inteligente para testes de segurança em ambientes controlados

📋 Índice

Sobre o Projeto
Funcionalidades
Requisitos
Instalação
Utilização
Estrutura do Projeto
Módulos Disponíveis
Relatórios
Considerações Legais
Licença


🎯 Sobre o Projeto
CarapauCracker é uma framework modular de pentesting desenvolvida em Python que automatiza e centraliza as fases críticas de um teste de penetração em ambientes controlados de laboratório.
Criada para profissionais de cibersegurança e investigadores, esta ferramenta oferece:

Interface CLI interativa e intuitiva
Execução automatizada de ferramentas de reconhecimento
Integração com ferramentas standard da indústria (Nmap, Hydra, Metasploit, etc.)
Sistema de logging centralizado
Geração automática de relatórios profissionais


✨ Funcionalidades
🔍 1. Reconhecimento Avançado

Verificação de disponibilidade de host (ICMP)
Reverse DNS lookup automático
WHOIS integration para informação de registo
GeoIP localização via API externa
Banner grabbing multi-protocolo (FTP, SSH, HTTP)

🔎 2. Scanning de Rede & Sistema

Quick Scan: Identificação rápida de portas comuns
Detailed Scan: Detecção de versões e scripts NSE (-sV -sC)
Full TCP Scan: Análise completa de todas as 65535 portas
UDP Scan: Scanning das 50 portas UDP mais comuns
OS Detection: Fingerprinting de sistema operativo
Aggressive Scan: Modo agressivo com todas as técnicas (-A)

🌐 3. Enumeração Web Completa

Análise de HTTP headers e configurações
Descoberta de ficheiros sensíveis (robots.txt, etc.)
Enumeração de métodos HTTP permitidos
WhatWeb: Identificação de tecnologias e frameworks
Nikto: Scanning profundo de vulnerabilidades web
Gobuster: Directory/file bruteforce eficiente
FFUF: Fuzzing de alta performance
Nmap NSE: Scripts HTTP especializados
SSLScan: Análise detalhada de SSL/TLS
WPScan: Scanning específico para WordPress

💣 4. Descoberta de Exploits

Integração com SearchSploit (Exploit-DB)
Pesquisa automática no Metasploit Framework
Classificação inteligente por severidade (RCE, Auth Bypass, LPE, DoS)
Sistema de ranking de exploits por prioridade
Lançamento automatizado de exploits MSF

🔑 5. Ataques de Credenciais

SSH bruteforce via Hydra
FTP authentication testing
HTTP Basic Auth cracking
HTTP POST form attacks
Suporte para wordlists customizadas
Teste rápido de credenciais conhecidas/default

📄 6. Sistema de Relatórios

Relatório TXT unificado e estruturado
Export automático para PDF profissional
Export para JSON com dados estruturados
Logging detalhado com timestamps
Organização por sessões e alvos


🛠️ Requisitos
Sistema Operativo

Linux (Kali Linux, Parrot OS, Ubuntu, Debian)
Python 3.8 ou superior

Ferramentas Externas Necessárias
As seguintes ferramentas devem estar instaladas no sistema:
