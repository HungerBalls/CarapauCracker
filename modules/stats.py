# stats.py — CarapauCracker Session Statistics
"""
Statistics and metrics collection for sessions
"""
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from colorama import Fore

console = Console()


class SessionStats:
    """Collect and display session statistics"""
    
    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()
        self.operations = []
        self.ports_discovered = []
        self.services_found = []
        self.cves_found = []
        self.exploits_found = []
        self.credentials_found = []
        self.errors = []
    
    def add_operation(self, operation: str, duration: float, success: bool = True):
        """Record an operation"""
        self.operations.append({
            "operation": operation,
            "duration": duration,
            "success": success,
            "timestamp": datetime.now()
        })
    
    def add_port(self, port: int, service: str, version: str = ""):
        """Record discovered port"""
        self.ports_discovered.append({
            "port": port,
            "service": service,
            "version": version
        })
    
    def add_cve(self, cve_id: str, severity: str, service: str):
        """Record found CVE"""
        self.cves_found.append({
            "cve_id": cve_id,
            "severity": severity,
            "service": service
        })
    
    def add_exploit(self, exploit_title: str, service: str):
        """Record found exploit"""
        self.exploits_found.append({
            "title": exploit_title,
            "service": service
        })
    
    def add_credential(self, service: str, username: str):
        """Record found credential"""
        self.credentials_found.append({
            "service": service,
            "username": username
        })
    
    def add_error(self, error: str):
        """Record error"""
        self.errors.append({
            "error": error,
            "timestamp": datetime.now()
        })
    
    def get_summary(self) -> Dict:
        """Get summary statistics"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # Count by severity
        critical_cves = len([c for c in self.cves_found if c.get("severity") == "CRITICAL"])
        high_cves = len([c for c in self.cves_found if c.get("severity") == "HIGH"])
        medium_cves = len([c for c in self.cves_found if c.get("severity") == "MEDIUM"])
        
        # Count successful operations
        successful_ops = len([o for o in self.operations if o.get("success")])
        failed_ops = len([o for o in self.operations if not o.get("success")])
        
        return {
            "target": self.target,
            "duration_seconds": duration,
            "duration_formatted": self._format_duration(duration),
            "operations_total": len(self.operations),
            "operations_successful": successful_ops,
            "operations_failed": failed_ops,
            "ports_discovered": len(self.ports_discovered),
            "services_found": len(self.services_found),
            "cves_total": len(self.cves_found),
            "cves_critical": critical_cves,
            "cves_high": high_cves,
            "cves_medium": medium_cves,
            "exploits_found": len(self.exploits_found),
            "credentials_found": len(self.credentials_found),
            "errors": len(self.errors)
        }
    
    def display_summary(self):
        """Display formatted summary table"""
        summary = self.get_summary()
        
        # Main stats table
        table = Table(title="📊 Session Statistics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="white", width=20)
        
        table.add_row("Target", summary["target"])
        table.add_row("Duration", summary["duration_formatted"])
        table.add_row("Operations", f"{summary['operations_successful']}/{summary['operations_total']} successful")
        table.add_row("Ports Discovered", str(summary["ports_discovered"]))
        table.add_row("Services Found", str(summary["services_found"]))
        table.add_row("CVEs Found", str(summary["cves_total"]))
        table.add_row("  └─ Critical", f"[red]{summary['cves_critical']}[/red]")
        table.add_row("  └─ High", f"[yellow]{summary['cves_high']}[/yellow]")
        table.add_row("  └─ Medium", f"[white]{summary['cves_medium']}[/white]")
        table.add_row("Exploits Found", str(summary["exploits_found"]))
        table.add_row("Credentials Found", str(summary["credentials_found"]))
        table.add_row("Errors", f"[red]{summary['errors']}[/red]" if summary["errors"] > 0 else "0")
        
        console.print("\n")
        console.print(table)
        
        # Recommendations
        if summary["cves_critical"] > 0 or summary["cves_high"] > 0:
            console.print("\n")
            console.print(Panel.fit(
                "[bold red]⚠️  CRITICAL VULNERABILITIES DETECTED[/bold red]\n\n"
                f"Found {summary['cves_critical']} critical and {summary['cves_high']} high severity CVEs.\n"
                "Recommendation: Prioritize patching these vulnerabilities immediately.",
                border_style="red"
            ))
        
        if summary["credentials_found"] > 0:
            console.print("\n")
            console.print(Panel.fit(
                "[bold yellow]🔑 CREDENTIALS DISCOVERED[/bold yellow]\n\n"
                f"Found {summary['credentials_found']} valid credential(s).\n"
                "Recommendation: Review and secure these accounts.",
                border_style="yellow"
            ))
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def export_summary(self, file_path: Path):
        """Export summary to file"""
        summary = self.get_summary()
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("CARAPAUPANEL SESSION SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Target: {summary['target']}\n")
            f.write(f"Duration: {summary['duration_formatted']}\n")
            f.write(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("Operations:\n")
            f.write(f"  Total: {summary['operations_total']}\n")
            f.write(f"  Successful: {summary['operations_successful']}\n")
            f.write(f"  Failed: {summary['operations_failed']}\n\n")
            
            f.write("Discoveries:\n")
            f.write(f"  Ports: {summary['ports_discovered']}\n")
            f.write(f"  Services: {summary['services_found']}\n")
            f.write(f"  CVEs: {summary['cves_total']}\n")
            f.write(f"    Critical: {summary['cves_critical']}\n")
            f.write(f"    High: {summary['cves_high']}\n")
            f.write(f"    Medium: {summary['cves_medium']}\n")
            f.write(f"  Exploits: {summary['exploits_found']}\n")
            f.write(f"  Credentials: {summary['credentials_found']}\n\n")
            
            if summary['errors'] > 0:
                f.write("Errors:\n")
                for error in self.errors:
                    f.write(f"  - {error['error']}\n")
