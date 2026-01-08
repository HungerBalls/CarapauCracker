# cve_checker.py — CarapauCracker v3
import requests
import re
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from modules.utils import append_section


def check_cve(service, version):
    """
    Query CVE database for known vulnerabilities
    API: https://cve.circl.lu/api/search/{service}/{version}
    """
    console = Console()
    console.print(f"[cyan][i] Checking CVEs for {service} {version}...[/cyan]")
    
    url = f"https://cve.circl.lu/api/search/{service}/{version}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            if not data:
                console.print("[green][✓] No known CVEs found![/green]")
                return []
            
            cves = []
            for cve in data:
                cve_info = {
                    'id': cve.get('id'),
                    'summary': cve.get('summary', ''),
                    'cvss': cve.get('cvss', 'N/A'),
                    'published': cve.get('Published', 'Unknown')
                }
                cves.append(cve_info)
            
            display_cve_results(cves, service)
            return cves
            
    except Exception as e:
        console.print(f"[red][✘] CVE check failed: {e}[/red]")
        return []


def display_cve_results(cves, service):
    """Display CVE results in a formatted table"""
    console = Console()
    table = Table(title=f"🔴 CVE Results for {service}", show_header=True)
    table.add_column("CVE ID", style="red")
    table.add_column("CVSS", style="yellow", justify="center")
    table.add_column("Severity", style="magenta")
    table.add_column("Summary", style="white")
    
    for cve in cves:
        severity = get_severity(cve['cvss'])
        summary = cve['summary'][:80] + "..." if len(cve['summary']) > 80 else cve['summary']
        table.add_row(cve['id'], str(cve['cvss']), severity, summary)
    
    console.print(table)


def get_severity(cvss):
    """Convert CVSS score to severity level"""
    try:
        score = float(cvss)
        if score >= 9.0:
            return "🔴 CRITICAL"
        elif score >= 7.0:
            return "🟠 HIGH"
        elif score >= 4.0:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"
    except (ValueError, TypeError):
        return "⚪ UNKNOWN"


def auto_cve_scan(services, report_path, log_file=None):
    """Automatically check CVEs for all discovered services"""
    all_cves = []
    
    for svc in services:
        service_name = svc['service']
        version = extract_version(svc.get('version', ''))
        
        if version:
            cves = check_cve(service_name, version)
            all_cves.extend(cves)
    
    # Generate summary - only count CVEs with numeric CVSS scores
    critical = []
    high = []
    for c in all_cves:
        try:
            cvss_score = float(c.get('cvss', 0))
            if cvss_score >= 9.0:
                critical.append(c)
            elif cvss_score >= 7.0:
                high.append(c)
        except (ValueError, TypeError):
            # Skip CVEs with non-numeric CVSS scores
            pass
    
    summary = f"""
CVE SCAN SUMMARY:
- Total CVEs Found: {len(all_cves)}
- Critical: {len(critical)}
- High: {len(high)}
"""
    append_section(report_path, "CVE Analysis", summary)
    return all_cves


def extract_version(version_string):
    """Extract version number from service banner"""
    match = re.search(r'(\d+\.[\d.]+)', version_string)
    return match.group(1) if match else None
