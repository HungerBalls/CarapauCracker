import requests
import time
import os
import re
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Load environment variables
load_dotenv()

# NVD API Configuration
NVD_API_KEY = os.getenv('NVD_API_KEY', None)
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting
RATE_LIMIT_DELAY = 0.6 if NVD_API_KEY else 6  # seconds between requests


def check_cve(service, version):
    """
    Check CVEs using NIST NVD API 2.0
    
    Args:
        service: Service name (e.g., 'openssh', 'apache')
        version: Version number (e.g., '7.4', '2.4.49')
    
    Returns:
        List of CVE dictionaries
    """
    console = Console()
    
    # Validate inputs
    if not service or not version:
        console.print("[yellow][⚠] Missing service or version for CVE check[/yellow]")
        return []
    
    console.print(f"[cyan][i] Checking NVD database for {service} {version}...[/cyan]")
    
    # Check if API key is configured
    if not NVD_API_KEY:
        console.print("[dim yellow][!] NVD_API_KEY not set. Using rate-limited access (5 req/30s)[/dim yellow]")
        console.print("[dim yellow][i] Get free API key at: https://nvd.nist.gov/developers/request-an-api-key[/dim yellow]")
    
    # Build search query
    keyword = f"{service} {version}"
    
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 20
    }
    
    # Add API key to headers if available
    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
    
    try:
        # Respect rate limits
        time.sleep(RATE_LIMIT_DELAY)
        
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=20)
        
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
        cves = parse_nvd_vulnerabilities(vulnerabilities)
        
        # Display results
        if cves:
            display_cve_results(cves, service)
        
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


def parse_nvd_vulnerabilities(vulnerabilities):
    """
    Parse NVD API vulnerability data
    
    Args:
        vulnerabilities: List of vulnerability items from NVD API
    
    Returns:
        List of parsed CVE dictionaries
    """
    cves = []
    
    for vuln_item in vulnerabilities:
        try:
            cve = vuln_item.get('cve', {})
            
            # Get CVE ID
            cve_id = cve.get('id', 'Unknown')
            
            # Get English description
            descriptions = cve.get('descriptions', [])
            summary = 'No description available'
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    summary = desc.get('value', 'No description')
                    break
            
            # Get CVSS score (try v3.1 → v3.0 → v2.0)
            metrics = cve.get('metrics', {})
            cvss_score, severity = extract_cvss_metrics(metrics)
            
            # Get published date
            published = cve.get('published', 'Unknown')[:10]  # YYYY-MM-DD
            
            # Get references (exploit links, advisories)
            references = cve.get('references', [])
            exploit_refs = [ref.get('url') for ref in references if 'exploit' in ref.get('url', '').lower()]
            
            cve_info = {
                'id': cve_id,
                'summary': summary,
                'cvss': cvss_score,
                'severity': severity,
                'published': published,
                'exploit_refs': exploit_refs
            }
            
            cves.append(cve_info)
            
        except Exception as e:
            # Skip malformed entries
            continue
    
    return cves


def extract_cvss_metrics(metrics):
    """
    Extract CVSS score and severity from metrics
    
    Returns:
        Tuple of (cvss_score, severity)
    """
    cvss_score = 'N/A'
    severity = 'UNKNOWN'
    
    # Try CVSS v3.1 (preferred)
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        cvss_score = cvss_data.get('baseScore', 'N/A')
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    
    # Fallback to CVSS v3.0
    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
        cvss_score = cvss_data.get('baseScore', 'N/A')
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    
    # Fallback to CVSS v2.0
    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
        cvss_score = cvss_data.get('baseScore', 'N/A')
        # Calculate severity for v2 (doesn't have baseSeverity)
        # CVSS v2: HIGH (7.0-10.0), MEDIUM (4.0-6.9), LOW (0.0-3.9)
        try:
            score = float(cvss_score)
            if score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
        except (ValueError, TypeError):
            severity = 'UNKNOWN'
    
    return cvss_score, severity


def display_cve_results(cves, service):
    """Display CVE results in a Rich table"""
    console = Console()
    
    table = Table(
        title=f"🔴 NVD Vulnerability Database - {service}",
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("CVE ID", style="red", width=18)
    table.add_column("CVSS", style="yellow", justify="center", width=6)
    table.add_column("Severity", style="magenta", width=14)
    table.add_column("Published", style="cyan", width=12)
    table.add_column("Summary", style="white", width=50)
    
    for cve in cves:
        # Get severity display with emoji
        severity_display = get_severity_display(cve['severity'], cve['cvss'])
        
        # Truncate summary
        summary = cve['summary']
        if len(summary) > 47:
            summary = summary[:47] + "..."
        
        # Add exploit indicator
        if cve.get('exploit_refs'):
            summary = "⚡ " + summary
        
        table.add_row(
            cve['id'],
            str(cve['cvss']),
            severity_display,
            cve['published'],
            summary
        )
    
    console.print(table)
    console.print(f"\n[cyan][✓] Found {len(cves)} CVE(s) in NVD database[/cyan]")
    
    # Show critical vulnerabilities count (CVSS v3.x only, as v2 doesn't have CRITICAL)
    critical = 0
    for c in cves:
        if c['severity'] == 'CRITICAL':
            critical += 1
        elif c['cvss'] != 'N/A':
            try:
                if isinstance(c['cvss'], (int, float)) and c['cvss'] >= 9.0:
                    critical += 1
            except (ValueError, TypeError):
                pass
    
    if critical > 0:
        console.print(f"[bold red][!] {critical} CRITICAL vulnerabilities found![/bold red]\n")


def get_severity_display(severity, cvss):
    """Convert severity to display format with emoji"""
    try:
        score = float(cvss) if cvss != 'N/A' else 0
    except (ValueError, TypeError):
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
    
    # Try common version patterns
    patterns = [
        r'(\d+\.\d+\.\d+)',      # 1.2.3
        r'(\d+\.\d+)',            # 1.2
        r'v(\d+\.\d+\.\d+)',      # v1.2.3
        r'version (\d+\.\d+)',    # version 1.2
    ]
    
    for pattern in patterns:
        match = re.search(pattern, version_string, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def auto_cve_scan(services, report_path, log_file=None):
    """
    Automatically check CVEs for all discovered services
    
    Args:
        services: List of service dictionaries
        report_path: Path to report file
        log_file: Optional log file
    
    Returns:
        List of all CVEs found
    """
    from modules.utils import append_section
    
    console = Console()
    console.print("\n[bold cyan]🔍 Running CVE vulnerability check...[/bold cyan]\n")
    
    all_cves = []
    
    for svc in services:
        service_name = svc.get('service', '').lower()
        version_string = svc.get('version', '')
        
        # Extract clean version number
        version = extract_version(version_string)
        
        if not version:
            console.print(f"[dim][i] Skipping {service_name} - no version detected[/i][/dim]")
            continue
        
        # Check CVEs
        cves = check_cve(service_name, version)
        
        if cves:
            all_cves.extend(cves)
            
            # Add to report
            cve_summary = f"Found {len(cves)} CVE(s) for {service_name} {version}\n"
            for cve in cves:
                cve_summary += f"  - {cve['id']}: CVSS {cve['cvss']} ({cve['severity']})\n"
            
            append_section(report_path, f"CVE Analysis - {service_name} {version}", cve_summary)
    
    # Generate summary
    if all_cves:
        critical = sum(1 for c in all_cves if c['severity'] == 'CRITICAL')
        high = sum(1 for c in all_cves if c['severity'] == 'HIGH')
        medium = sum(1 for c in all_cves if c['severity'] == 'MEDIUM')
        
        summary = f"""
CVE VULNERABILITY SUMMARY:
=========================
Total CVEs Found: {len(all_cves)}
  - Critical: {critical}
  - High: {high}
  - Medium: {medium}
"""
        append_section(report_path, "CVE Analysis Summary", summary)
        console.print(f"[green][✓] CVE check completed. Found {len(all_cves)} vulnerabilities.[/green]\n")
    else:
        console.print("[green][✓] CVE check completed. Found 0 vulnerabilities.[/green]\n")
        append_section(report_path, "CVE Analysis", "No CVEs found for scanned services.")
    
    return all_cves
