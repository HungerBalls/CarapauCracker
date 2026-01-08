# cve_checker.py — CarapauCracker v3
import requests
import time
import os
import re
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get NVD API key from environment (optional but recommended)
NVD_API_KEY = os.getenv('NVD_API_KEY', None)

def check_cve_nvd(service, version):
    """
    Query NIST NVD API 2.0 for CVEs
    API Docs: https://nvd.nist.gov/developers/vulnerabilities
    
    Rate Limits:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    """
    console = Console()
    console.print(f"[cyan][i] Checking NVD database for {service} {version}...[/cyan]")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Build search query
    keyword = f"{service} {version}"
    
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 20
    }
    
    # Add API key if available
    headers = {}
    delay = 6  # seconds between requests (without key)
    
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
        delay = 0.6  # With key: 50 req/30s = ~0.6s delay
        console.print("[dim][i] Using NVD API key (faster rate limit)[/i][/dim]")
    else:
        console.print("[dim yellow][i] No API key - using rate limit 5 req/30s[/i][/dim yellow]")
    
    try:
        # Rate limiting
        time.sleep(delay)
        
        response = requests.get(url, params=params, headers=headers, timeout=20)
        
        # Handle rate limiting
        if response.status_code == 403:
            console.print("[red][✘] NVD API rate limit exceeded. Wait 30 seconds.[/red]")
            return []
        
        if response.status_code != 200:
            console.print(f"[yellow][⚠] NVD API returned status {response.status_code}[/yellow]")
            return []
        
        data = response.json()
        
        # Parse vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            console.print("[green][✓] No CVEs found in NVD database.[/green]")
            return []
        
        # Extract CVE information
        cves = []
        for vuln_item in vulnerabilities:
            cve = vuln_item.get('cve', {})
            
            # Get CVE ID
            cve_id = cve.get('id', 'Unknown')
            
            # Get English description
            descriptions = cve.get('descriptions', [])
            summary = 'No description'
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    summary = desc.get('value', 'No description')
                    break
            
            # Get CVSS score (try v3.1, then v3.0, then v2.0)
            metrics = cve.get('metrics', {})
            cvss_score = 'N/A'
            severity = 'UNKNOWN'
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                # V2 doesn't have severity text, calculate it
                try:
                    score = float(cvss_score)
                    if score >= 9.0:
                        severity = 'CRITICAL'
                    elif score >= 7.0:
                        severity = 'HIGH'
                    elif score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                except:
                    severity = 'UNKNOWN'
            
            # Get published date
            published = cve.get('published', 'Unknown')
            if published != 'Unknown':
                # Format date nicely
                published = published.split('T')[0]  # Get just the date part
            
            cve_info = {
                'id': cve_id,
                'summary': summary,
                'cvss': cvss_score,
                'severity': severity,
                'published': published
            }
            
            cves.append(cve_info)
        
        # Display results
        if cves:
            display_nvd_results(cves, service)
        
        return cves
        
    except requests.Timeout:
        console.print("[red][✘] NVD API request timed out.[/red]")
        return []
    except requests.RequestException as e:
        console.print(f"[red][✘] NVD API request failed: {e}[/red]")
        return []
    except Exception as e:
        console.print(f"[red][✘] Unexpected error during CVE check: {e}[/red]")
        return []


def display_nvd_results(cves, service):
    """Display NVD CVE results in a formatted Rich table"""
    console = Console()
    
    table = Table(
        title=f"🔴 NVD Vulnerability Results for {service}",
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("CVE ID", style="red", width=18)
    table.add_column("CVSS", style="yellow", justify="center", width=6)
    table.add_column("Severity", style="magenta", width=14)
    table.add_column("Published", style="cyan", width=12)
    table.add_column("Summary", style="white", width=60)
    
    for cve in cves:
        # Get severity display with emoji
        severity_display = get_severity_display(cve['severity'], cve['cvss'])
        
        # Truncate summary if too long
        summary = cve['summary']
        if len(summary) > 57:
            summary = summary[:57] + "..."
        
        table.add_row(
            cve['id'],
            str(cve['cvss']),
            severity_display,
            cve['published'],
            summary
        )
    
    console.print(table)
    console.print(f"\n[cyan][i] Found {len(cves)} CVE(s) in NVD database[/i][/cyan]\n")


def get_severity_display(severity, cvss):
    """Convert severity to display format with emoji"""
    try:
        score = float(cvss) if cvss != 'N/A' else 0
    except:
        score = 0
    
    if severity == 'CRITICAL' or score >= 9.0:
        return "🔴 CRITICAL"
    elif severity == 'HIGH' or score >= 7.0:
        return "🟠 HIGH"
    elif severity == 'MEDIUM' or score >= 4.0:
        return "🟡 MEDIUM"
    elif severity == 'LOW' or score > 0:
        return "🟢 LOW"
    else:
        return "⚪ UNKNOWN"


def extract_version(version_string):
    """Extract version number from service banner"""
    if not version_string:
        return None
    
    # Try to match common version patterns
    patterns = [
        r'(\d+\.\d+\.\d+)',      # 1.2.3
        r'(\d+\.\d+)',            # 1.2
        r'v(\d+\.\d+\.\d+)',      # v1.2.3
        r'v(\d+\.\d+)',           # v1.2
    ]
    
    for pattern in patterns:
        match = re.search(pattern, version_string)
        if match:
            return match.group(1)
    
    return None


def auto_cve_scan(services, report_path, log_file=None):
    """Automatically check CVEs for all discovered services"""
    from modules.utils import append_section, log
    
    console = Console()
    console.print("\n[bold cyan]🔍 Running automatic CVE vulnerability check...[/bold cyan]\n")
    
    all_cves = []
    
    for svc in services:
        service_name = svc.get('service', 'unknown')
        version_string = svc.get('version', '')
        
        # Extract version number
        version = extract_version(version_string)
        
        if version and service_name != 'unknown':
            cves = check_cve_nvd(service_name, version)
            all_cves.extend(cves)
        else:
            console.print(f"[dim yellow][⚠] Skipping {service_name} - no version detected[/dim yellow]")
    
    # Generate summary
    if all_cves:
        critical = [c for c in all_cves if c.get('severity') == 'CRITICAL' or float(str(c.get('cvss', 0)).replace('N/A', '0')) >= 9.0]
        high = [c for c in all_cves if c.get('severity') == 'HIGH' or (7.0 <= float(str(c.get('cvss', 0)).replace('N/A', '0')) < 9.0)]
        medium = [c for c in all_cves if c.get('severity') == 'MEDIUM' or (4.0 <= float(str(c.get('cvss', 0)).replace('N/A', '0')) < 7.0)]
        
        summary = f"""
CVE VULNERABILITY SCAN SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total CVEs Found: {len(all_cves)}
  🔴 Critical: {len(critical)}
  🟠 High: {len(high)}
  🟡 Medium: {len(medium)}
  🟢 Low: {len(all_cves) - len(critical) - len(high) - len(medium)}

Source: NIST National Vulnerability Database (NVD)
"""
        append_section(report_path, "CVE Analysis Summary", summary)
        log(summary, log_file)
        
        console.print("[bold green][✓] CVE check completed. Found vulnerabilities.[/bold green]")
    else:
        summary = "CVE scan completed. No vulnerabilities found."
        append_section(report_path, "CVE Analysis", summary)
        console.print("[bold green][✓] CVE check completed. No vulnerabilities.[/bold green]")
    
    return all_cves


# Backward compatibility - alias old function name
check_cve = check_cve_nvd
