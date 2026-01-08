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
        
        if response.status_code != 200:
            console.print(f"[yellow][⚠] CVE API returned status {response.status_code}[/yellow]")
            return []
        
        data = response.json()
        
        # Handle different response formats
        if not data:
            console.print("[green][✓] No known CVEs found![/green]")
            return []
        
        if not isinstance(data, list):
            console.print("[yellow][⚠] Unexpected API response format[/yellow]")
            return []
        
        cves = []
        for item in data:
            try:
                # Check if item is a dict or string
                if isinstance(item, dict):
                    # Try to get CVSS score, fallback to cvss2, then N/A
                    cvss_score = item.get('cvss')
                    if cvss_score is None:
                        cvss_score = item.get('cvss2', 'N/A')
                    
                    cve_info = {
                        'id': item.get('id', 'Unknown'),
                        'summary': item.get('summary', 'No description'),
                        'cvss': cvss_score,
                        'published': item.get('Published', item.get('published', 'Unknown'))
                    }
                    cves.append(cve_info)
                elif isinstance(item, str):
                    # If API returns just CVE IDs as strings
                    cves.append({
                        'id': item,
                        'summary': 'Details not available',
                        'cvss': 'N/A',
                        'published': 'Unknown'
                    })
            except Exception as e:
                console.print(f"[dim red]Warning: Skipped malformed CVE entry: {e}[/dim red]")
                continue
        
        if cves:
            display_cve_results(cves, service)
            return cves
        else:
            console.print("[green][✓] No valid CVE data found.[/green]")
            return []
            
    except requests.RequestException as e:
        console.print(f"[red][✘] CVE API request failed: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red][✘] CVE check failed: {type(e).__name__}: {str(e)}[/red]")
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
        severity = get_severity(cve.get('cvss', 'N/A'))
        summary = cve.get('summary', 'No description')
        
        # Truncate long summaries
        if len(summary) > 80:
            summary = summary[:77] + "..."
        
        table.add_row(
            cve.get('id', 'Unknown'),
            str(cve.get('cvss', 'N/A')),
            severity,
            summary
        )
    
    console.print(table)


def get_severity(cvss):
    """Convert CVSS score to severity level"""
    try:
        # Handle string 'N/A' or other non-numeric values
        if cvss == 'N/A' or cvss is None:
            return "⚪ UNKNOWN"
        
        score = float(cvss)
        if score >= 9.0:
            return "🔴 CRITICAL"
        elif score >= 7.0:
            return "🟠 HIGH"
        elif score >= 4.0:
            return "🟡 MEDIUM"
        elif score > 0:
            return "🟢 LOW"
        else:
            return "⚪ UNKNOWN"
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
