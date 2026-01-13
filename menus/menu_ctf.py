# menu_ctf.py — CarapauCracker CTF Mode Menu
from modules.ctf_helpers import *
from modules.listener import start_listener
from modules.utils import banner, log, run_command_live
from modules.scan import quick_scan
from colorama import Fore
from rich.panel import Panel
from rich.console import Console
from pathlib import Path

console = Console()


def run_ctf_menu(target, run_dir, report_path, session_log):
    """CTF Mode - Quick access to essential tools"""
    while True:
        banner()
        console.print(f"[cyan]🎯 CTF Mode - Target: [/cyan][white]{target}[/white]\n")
        console.print(Panel.fit(
            "[cyan]1[/cyan] - Quick Scan (Common Ports)\n"
            "[cyan]2[/cyan] - Reverse Shell Listener\n"
            "[cyan]3[/cyan] - Encode/Decode Tools\n"
            "[cyan]4[/cyan] - Hash Identifier\n"
            "[cyan]5[/cyan] - CTF Cheatsheet\n"
            "[cyan]6[/cyan] - Generate Wordlist from File\n"
            "[cyan]0[/cyan] - Return to Main Menu",
            title="🏆 CTF MODE",
            border_style="yellow"
        ))

        opt = input(Fore.YELLOW + "\n[»] Choose an option: ").strip()

        if opt == "0":
            banner()
            break

        elif opt == "1":
            log(Fore.CYAN + "\n[⚡] Quick CTF scan (common ports only)...", session_log)
            cmd = quick_scan(target, common_ports=True)
            console.print(f"[dim]Command: {cmd}[/dim]\n")
            run_command_live(cmd.split(), session_log)

        elif opt == "2":
            console.print("\n[cyan]Reverse Shell Listener[/cyan]")
            port = input(Fore.YELLOW + "[?] Port (default 4444): ").strip() or "4444"
            try:
                port = int(port)
                start_listener(port)
            except ValueError:
                log(Fore.RED + "[✘] Invalid port", session_log)
            except KeyboardInterrupt:
                console.print("\n[yellow]Listener stopped[/yellow]")

        elif opt == "3":
            console.print("\n[cyan]Encode/Decode Tools[/cyan]")
            data = input(Fore.YELLOW + "[?] Enter data: ").strip()
            action = input(Fore.YELLOW + "[?] Action (encode/decode): ").strip().lower()
            encoding = input(Fore.YELLOW + "[?] Type (base64/hex/url/rot13): ").strip() or "base64"
            
            try:
                if action == "encode":
                    if encoding == "base64":
                        result = encode_base64(data)
                    elif encoding == "hex":
                        result = encode_hex(data)
                    elif encoding == "url":
                        result = encode_url(data)
                    elif encoding == "rot13":
                        result = rot13(data)
                    else:
                        result = "Unknown encoding"
                    console.print(f"\n[green]Encoded:[/green] {result}")
                
                elif action == "decode":
                    if encoding == "base64":
                        result = decode_base64(data)
                    elif encoding == "hex":
                        result = decode_hex(data)
                    elif encoding == "url":
                        result = decode_url(data)
                    elif encoding == "rot13":
                        result = rot13(data)  # ROT13 is symmetric
                    else:
                        result = "Unknown encoding"
                    console.print(f"\n[green]Decoded:[/green] {result}")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        elif opt == "4":
            console.print("\n[cyan]Hash Identifier[/cyan]")
            hash_value = input(Fore.YELLOW + "[?] Enter hash: ").strip()
            possible = identify_hash(hash_value)
            
            console.print(f"\n[green]Possible hash types:[/green]")
            for p in possible:
                console.print(f"  - {p}")
            
            # Show hash command
            if "MD5" in possible or "SHA1" in possible or "SHA256" in possible:
                console.print("\n[dim]💡 Try: hashcat -m <mode> hash.txt wordlist.txt[/dim]")
                console.print("[dim]   Or: john --wordlist=rockyou.txt hash.txt[/dim]")

        elif opt == "5":
            ctf_cheatsheet()

        elif opt == "6":
            console.print("\n[cyan]Generate Wordlist from File[/cyan]")
            file_path = input(Fore.YELLOW + "[?] Input file path: ").strip()
            output = input(Fore.YELLOW + "[?] Output file (default: wordlist.txt): ").strip() or "wordlist.txt"
            
            if Path(file_path).exists():
                generate_wordlist_from_file(file_path, output)
            else:
                log(Fore.RED + f"[✘] File not found: {file_path}", session_log)

        else:
            log(Fore.RED + "[✘] Invalid option", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
