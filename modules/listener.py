# listener.py — CarapauCracker Reverse Shell Listener
"""
Reverse shell listener for receiving connections
Essential for CTF and pentesting
"""
import socket
import threading
import subprocess
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from colorama import Fore

console = Console()


class ReverseShellListener:
    """Listen for reverse shell connections"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 4444):
        self.host = host
        self.port = port
        self.socket = None
        self.client = None
        self.running = False
    
    def start(self):
        """Start listening for connections"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            
            console.print(Panel.fit(
                f"[bold green]🔌 Reverse Shell Listener[/bold green]\n\n"
                f"Host: {self.host}\n"
                f"Port: {self.port}\n\n"
                f"[yellow]Waiting for connection...[/yellow]",
                border_style="green"
            ))
            
            self.running = True
            self.client, addr = self.socket.accept()
            
            console.print(f"[green][✓] Connection received from {addr[0]}:{addr[1]}[/green]\n")
            
            return True
            
        except Exception as e:
            console.print(f"[red][✘] Error starting listener: {e}[/red]")
            return False
    
    def interact(self):
        """Interact with the reverse shell"""
        if not self.client:
            console.print("[red][✘] No client connected[/red]")
            return
        
        console.print("[cyan]Type 'exit' to close the connection[/cyan]\n")
        
        try:
            while self.running:
                # Receive data
                data = self.client.recv(1024)
                if not data:
                    break
                
                print(data.decode('utf-8', errors='replace'), end='')
                
                # Send command
                cmd = input()
                if cmd.lower() == 'exit':
                    break
                
                self.client.send((cmd + '\n').encode())
                
        except KeyboardInterrupt:
            console.print("\n[yellow][⚠] Interrupted by user[/yellow]")
        except Exception as e:
            console.print(f"[red][✘] Error: {e}[/red]")
        finally:
            self.close()
    
    def close(self):
        """Close connections"""
        self.running = False
        if self.client:
            self.client.close()
        if self.socket:
            self.socket.close()
        console.print("[cyan]Listener closed[/cyan]")


def start_listener(port: int = 4444, host: str = "0.0.0.0"):
    """
    Quick function to start a reverse shell listener
    
    Args:
        port: Port to listen on
        host: Host to bind to
    """
    listener = ReverseShellListener(host, port)
    if listener.start():
        listener.interact()
