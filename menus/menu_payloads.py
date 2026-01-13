# menu_payloads.py — CarapauCracker Payloads Menu
import base64
import urllib.parse
from modules.payloads import PayloadGenerator
from modules.utils import banner, log
from colorama import Fore
from rich.panel import Panel
from rich.console import Console
from rich.table import Table

console = Console()
payload_gen = PayloadGenerator()


def run_payloads_menu(target, run_dir, report_path, session_log):
    """Payload generation menu for CTF and pentesting"""
    while True:
        banner()
        console.print(f"[cyan]🎯 Target: [/cyan][white]{target}[/white]\n")
        console.print(Panel.fit(
            "[cyan]1[/cyan] - Reverse Shell Payloads\n"
            "[cyan]2[/cyan] - Web Shell Payloads\n"
            "[cyan]3[/cyan] - SQL Injection Payloads\n"
            "[cyan]4[/cyan] - XSS Payloads\n"
            "[cyan]5[/cyan] - Command Injection Payloads\n"
            "[cyan]6[/cyan] - Encode/Decode Payload\n"
            "[cyan]0[/cyan] - Return to Main Menu",
            title="💣 Payload Generator",
            border_style="cyan"
        ))

        opt = input(Fore.YELLOW + "\n[»] Choose an option: ").strip()

        if opt == "0":
            banner()
            break

        elif opt == "1":
            console.print("\n[cyan]Reverse Shell Payload Generator[/cyan]")
            ip = input(Fore.YELLOW + "[?] Your IP: ").strip() or "10.10.10.10"
            port = input(Fore.YELLOW + "[?] Listener Port: ").strip() or "4444"
            
            try:
                port = int(port)
                payloads = payload_gen.reverse_shell(ip, port)
                payload_gen.display_payloads(payloads, "Reverse Shell Payloads")
                
                # Show listener command
                console.print(Panel.fit(
                    f"[bold green]Listener Command:[/bold green]\n\n"
                    f"[white]nc -lvnp {port}[/white]\n\n"
                    f"Or use: [cyan]python3 -m modules.listener {port}[/cyan]",
                    border_style="green"
                ))
            except ValueError:
                log(Fore.RED + "[✘] Invalid port number", session_log)

        elif opt == "2":
            console.print("\n[cyan]Web Shell Generator[/cyan]")
            lang = input(Fore.YELLOW + "[?] Language (php/jsp/asp): ").strip() or "php"
            shell = payload_gen.web_shell("", 0, lang)
            
            console.print("\n[bold cyan]Web Shell Code:[/bold cyan]")
            console.print(Panel(shell, border_style="yellow"))
            console.print("\n[dim]💡 Save this to a file and upload to the target[/dim]\n")

        elif opt == "3":
            console.print("\n[cyan]SQL Injection Payloads[/cyan]")
            technique = input(Fore.YELLOW + "[?] Technique (union/boolean/time/error): ").strip() or "union"
            payloads = payload_gen.sql_injection(technique)
            payload_gen.display_payloads(payloads, f"SQL Injection - {technique.upper()}")

        elif opt == "4":
            console.print("\n[cyan]XSS Payloads[/cyan]")
            context = input(Fore.YELLOW + "[?] Context (html/attribute/script): ").strip() or "html"
            payloads = payload_gen.xss_payloads(context)
            
            table = Table(title="XSS Payloads", show_header=True)
            table.add_column("Payload", style="white")
            for p in payloads:
                table.add_row(p)
            console.print("\n")
            console.print(table)

        elif opt == "5":
            console.print("\n[cyan]Command Injection Payloads[/cyan]")
            payloads = payload_gen.command_injection()
            
            table = Table(title="Command Injection Payloads", show_header=True)
            table.add_column("Payload", style="white")
            for p in payloads:
                table.add_row(p)
            console.print("\n")
            console.print(table)

        elif opt == "6":
            console.print("\n[cyan]Encode/Decode Payload[/cyan]")
            data = input(Fore.YELLOW + "[?] Enter data: ").strip()
            action = input(Fore.YELLOW + "[?] Action (encode/decode): ").strip().lower()
            encoding = input(Fore.YELLOW + "[?] Encoding (base64/url/hex/unicode): ").strip() or "base64"
            
            if action == "encode":
                result = payload_gen.encode_payload(data, encoding)
                console.print(f"\n[green]Encoded:[/green] {result}")
            elif action == "decode":
                if encoding == "base64":
                    try:
                        result = base64.b64decode(data).decode()
                        console.print(f"\n[green]Decoded:[/green] {result}")
                    except:
                        console.print("[red]Invalid base64[/red]")
                elif encoding == "url":
                    result = urllib.parse.unquote(data)
                    console.print(f"\n[green]Decoded:[/green] {result}")
                else:
                    console.print("[red]Decode not implemented for this encoding[/red]")

        else:
            log(Fore.RED + "[✘] Invalid option", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")
