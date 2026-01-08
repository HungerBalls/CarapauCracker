# cve_checker.py — CarapauCracker v3
import requests
import time
import os
import re
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from modules.utils import append_section

# Load environment variables
load_dotenv()
NVD_API_KEY = os.getenv('NVD_API_KEY', None)


def check_cve_nvd(service, version):
    """
    Query NIST NVD API 2.0 for CVEs
    
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    Rate Limits:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    
    Args:
        service: Service name (e.g., 'openssh', 'apache')
        version: Version number (e.g., '7.4', '2.4.49')
    
    Returns:
        List of CVE dictionaries
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
    
    # Setup headers with API key if available
    headers = {}
    delay = 6  # Default delay without key
    
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
        delay = 0.6  # With key: 50 req/30s = ~0.6s between requests
        console.print("[dim cyan][i] Using NVD API key (enhanced rate limit)[/dim cyan]")
    else:
        console.print("[dim yellow][i] No API key - using public rate limit (5 req/30s)[/dim yellow]")
    
    try:
        # Rate limiting
        time.sleep(delay)
        
        response = requests.get(url, params=params, headers=headers, timeout=20)
        
        # Handle rate limiting
        if response.status_code == 403:
            console.print("[red][✘] NVD API rate limit exceeded. Please wait 30 seconds.[/red]")
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
            
            # CVE ID
            cve_id = cve.get('id', 'Unknown')
            
            # Description (English)
            descriptions = cve.get('descriptions', [])
            summary = 'No description available'
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    summary = desc.get('value', 'No description available')
                    break
            
            # CVSS Score (try v3.1, then v3.0, then v2.0)
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
                # Calculate severity from v2 score
                try:
                    score = float(cvss_score)
                    if score >= 7.0:
                        severity = 'HIGH'
                    elif score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                except:
                    severity = 'UNKNOWN'
            
            # Published date
            published = cve.get('published', 'Unknown')
            if published != 'Unknown':
                # Format date (remove time part for cleaner display)
                published = published.split('T')[0]
            
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
    """Display NVD CVE results in a Rich table"""
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
        # Get severity with emoji
        severity_display = get_severity_display(cve['severity'], cve['cvss'])
        
        # Truncate summary
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


def get_severity(cvss):
    """Convert CVSS score to severity level (backward compatibility)"""
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


def display_cve_results(cves, service):
    """Display CVE results in a formatted table (backward compatibility)"""
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


def extract_version(version_string):
    """Extract version number from service banner"""
    import re
    
    if not version_string:
        return None
    
    # Try to match version patterns
    patterns = [
        r'(\d+\.\d+\.\d+)',      # 1.2.3
        r'(\d+\.\d+)',            # 1.2
        r'v(\d+\.\d+\.\d+)',      # v1.2.3
    ]
    
    for pattern in patterns:
        match = re.search(pattern, version_string)
        if match:
            return match.group(1)
    
    return None


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
