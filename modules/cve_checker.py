# cve_checker.py — CarapauCracker v3
import requests
import time
import os
import re
from rich.console import Console
from rich.table import Table
from modules.utils import append_section, log

# Constants
NVD_API_KEY = os.getenv('NVD_API_KEY', None)
SUMMARY_MAX_LENGTH = 62  # Maximum length for summary display in tables

def check_cve_nvd(service, version, log_file=None):
    """
    Query NIST NVD API 2.0 for known CVEs
    
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    Rate Limits:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    
    Args:
        service: Service name (e.g., 'openssh', 'apache')
        version: Version string (e.g., '7.4', '2.4.49')
        log_file: Optional log file path
    
    Returns:
        List of CVE dictionaries
    """
    console = Console()
    
    if not version:
        console.print("[dim][i] No version specified, skipping CVE check[/i][/dim]")
        return []
    
    log(f"[i] Checking NVD database for {service} {version}...", log_file)
    console.print(f"[cyan][i] Querying NVD API for {service} {version}...[/cyan]")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Build search query
    keyword = f"{service} {version}"
    
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 20
    }
    
    # Add API key if available
    headers = {}
    delay = 6  # Default: 6 seconds between requests (5 req/30s)
    
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
        delay = 0.7  # With key: 50 req/30s = ~0.6s, use 0.7s to be safe
        log("[i] Using NVD API key for higher rate limit", log_file)
    else:
        log("[!] No NVD_API_KEY found. Using public rate limit (5 req/30s)", log_file)
    
    try:
        # Rate limiting
        time.sleep(delay)
        
        response = requests.get(url, params=params, headers=headers, timeout=20)
        
        # Handle rate limiting
        if response.status_code == 403:
            console.print("[red][✘] NVD API rate limit exceeded. Please wait 30 seconds.[/red]")
            log("[!] NVD API rate limit exceeded", log_file)
            return []
        
        if response.status_code != 200:
            console.print(f"[yellow][⚠] NVD API returned status code: {response.status_code}[/yellow]")
            log(f"[!] NVD API error: HTTP {response.status_code}", log_file)
            return []
        
        data = response.json()
        
        # Parse vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            console.print("[green][✓] No CVEs found in NVD database[/green]")
            log(f"[i] No CVEs found for {service} {version}", log_file)
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
            
            # CVSS Score (try v3.1 > v3.0 > v2.0)
            metrics = cve.get('metrics', {})
            cvss_score = 'N/A'
            severity = 'UNKNOWN'
            
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Try CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 'N/A')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Fallback to CVSS v2
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
            
            cve_info = {
                'id': cve_id,
                'summary': summary,
                'description': summary,  # Add 'description' as alias for compatibility
                'cvss': cvss_score,
                'score': cvss_score,  # Add 'score' as alias for compatibility
                'severity': severity,
                'published': published
            }
            
            cves.append(cve_info)
        
        # Display results
        if cves:
            display_nvd_results(cves, service)
            log(f"[+] Found {len(cves)} CVE(s) for {service} {version}", log_file)
        
        return cves
        
    except requests.Timeout:
        console.print("[red][✘] NVD API request timed out[/red]")
        log("[!] NVD API timeout", log_file)
        return []
    except requests.RequestException as e:
        console.print(f"[red][✘] NVD API request failed: {e}[/red]")
        log(f"[!] NVD API error: {e}", log_file)
        return []
    except Exception as e:
        console.print(f"[red][✘] Unexpected error during CVE check: {e}[/red]")
        log(f"[!] CVE check error: {e}", log_file)
        return []


def display_nvd_results(cves, service):
    """Display NVD CVE results in a formatted Rich table"""
    console = Console()
    
    table = Table(
        title=f"🔴 NVD Vulnerability Database Results for {service}",
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("CVE ID", style="red", width=18)
    table.add_column("CVSS", style="yellow", justify="center", width=6)
    table.add_column("Severity", style="magenta", width=15)
    table.add_column("Summary", style="white", width=65)
    
    for cve in cves:
        severity_display = get_severity_display(cve['severity'], cve['cvss'])
        
        # Truncate long summaries
        summary = cve['summary']
        if len(summary) > SUMMARY_MAX_LENGTH:
            summary = summary[:SUMMARY_MAX_LENGTH] + "..."
        
        table.add_row(
            cve['id'],
            str(cve['cvss']),
            severity_display,
            summary
        )
    
    console.print(table)
    console.print(f"\n[cyan][i] Total: {len(cves)} CVE(s) found in NVD database[/i][/cyan]\n")


def get_severity_display(severity, cvss):
    """Convert severity string to display format with emoji"""
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
    """
    Extract clean version number from service banner
    
    Examples:
        'OpenSSH 7.4' -> '7.4'
        'Apache/2.4.49 (Unix)' -> '2.4.49'
        'nginx/1.18.0' -> '1.18.0'
    """
    if not version_string:
        return None
    
    # Try multiple version patterns
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


def check_service_vulnerabilities(services, report_path, log_file=None):
    """
    Verifica CVEs para TODOS os serviços encontrados num scan
    
    Args:
        services: Lista de dicts [{'port': '22', 'service': 'ssh', 'version': 'OpenSSH 7.4'}, ...]
        report_path: Caminho do report.txt
        log_file: Ficheiro de log da sessão
    
    Returns:
        Lista de todos os CVEs encontrados
    """
    console = Console()
    all_cves = []
    
    console.print("\n[cyan]═══════════════════════════════════════[/cyan]")
    console.print("[cyan bold]  🔍 CVE VULNERABILITY ANALYSIS[/cyan bold]")
    console.print("[cyan]═══════════════════════════════════════[/cyan]\n")
    
    # Processar cada serviço
    for svc in services:
        service_name = svc.get('service', 'unknown')
        version = svc.get('version', '')
        port = svc.get('port', 'N/A')
        
        # Ignorar se não tiver versão
        if not version or version == 'N/A' or len(version) < 3:
            log(f"[i] Skipping {service_name} (no version info)", log_file)
            continue
        
        console.print(f"[cyan][🔍] Analyzing {service_name} {version} (port {port})...[/cyan]")
        
        # Chamar função existente check_cve_nvd()
        cves = check_cve_nvd(service_name, version, log_file)
        
        if cves:
            # Adicionar info do serviço a cada CVE
            for cve in cves:
                cve['affected_service'] = service_name
                cve['affected_version'] = version
                cve['affected_port'] = port
            
            all_cves.extend(cves)
            
            # Contar por severidade
            critical = [c for c in cves if c.get('severity') == 'CRITICAL']
            high = [c for c in cves if c.get('severity') == 'HIGH']
            medium = [c for c in cves if c.get('severity') == 'MEDIUM']
            
            # Alertas visuais em tempo real
            if critical:
                console.print(f"[red bold]  🔴 {len(critical)} CRITICAL CVEs found![/red bold]")
            if high:
                console.print(f"[yellow]  🟠 {len(high)} HIGH CVEs found[/yellow]")
            if medium:
                console.print(f"[white]  🟡 {len(medium)} MEDIUM CVEs found[/white]")
        else:
            console.print(f"[green]  ✓ No CVEs found for {service_name} {version}[/green]")
        
        console.print()  # Linha vazia
    
    # Adicionar ao report se encontrou CVEs
    if all_cves:
        console.print(f"[red bold]\n🚨 TOTAL: {len(all_cves)} vulnerabilities detected across all services![/red bold]\n")
        
        # Formatar e adicionar ao report
        cve_report = format_cve_report(all_cves, services)
        append_section(report_path, "CVE VULNERABILITIES", cve_report)
        
        log(f"[✓] CVE analysis complete: {len(all_cves)} vulnerabilities found", log_file)
        log(f"[✓] CVE report added to {report_path}", log_file)
    else:
        console.print("[green][✓] No CVEs found in any service[/green]\n")
        log("[i] CVE analysis complete: No vulnerabilities found", log_file)
    
    return all_cves


def format_cve_report(cves, services):
    """
    Formata lista de CVEs para o report de forma profissional
    
    Args:
        cves: Lista de CVEs encontrados
        services: Lista de serviços analisados
    
    Returns:
        String formatada para adicionar ao report
    """
    lines = []
    
    # Header
    lines.append("╔═══════════════════════════════════════════════════════════════╗")
    lines.append("║           VULNERABILITY ANALYSIS REPORT (NVD)                 ║")
    lines.append("╚═══════════════════════════════════════════════════════════════╝")
    lines.append("")
    
    # Estatísticas por severidade
    critical = [c for c in cves if c.get('severity') == 'CRITICAL']
    high = [c for c in cves if c.get('severity') == 'HIGH']
    medium = [c for c in cves if c.get('severity') == 'MEDIUM']
    low = [c for c in cves if c.get('severity') == 'LOW']
    
    lines.append(f"Total Vulnerabilities Found: {len(cves)}")
    lines.append(f"  🔴 Critical: {len(critical)}")
    lines.append(f"  🟠 High:      {len(high)}")
    lines.append(f"  🟡 Medium:   {len(medium)}")
    lines.append(f"  ⚪ Low:      {len(low)}")
    lines.append("")
    
    # Serviços analisados
    lines.append("Services Analyzed:")
    for svc in services:
        service_name = svc.get('service', 'unknown')
        version = svc.get('version', 'N/A')
        port = svc.get('port', 'N/A')
        if version and version != 'N/A':
            lines.append(f"  - {service_name} {version} (port {port})")
    lines.append("")
    lines.append("=" * 70)
    lines.append("")
    
    # Ordenar CVEs por severidade (CRITICAL primeiro) e depois por score
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    
    def get_cve_sort_key(cve):
        severity = cve.get('severity', 'UNKNOWN')
        severity_rank = severity_order.get(severity, 999)
        # Get score, handle both 'cvss' and 'score' keys
        score = cve.get('score', cve.get('cvss', 0))
        try:
            score_val = float(score) if score != 'N/A' else 0
        except (ValueError, TypeError):
            score_val = 0
        return (severity_rank, -score_val)
    
    sorted_cves = sorted(cves, key=get_cve_sort_key)
    
    # Listar cada CVE
    for i, cve in enumerate(sorted_cves, 1):
        cve_id = cve.get('id', 'N/A')
        severity = cve.get('severity', 'UNKNOWN')
        # Handle both 'cvss' and 'score' keys
        score = cve.get('score', cve.get('cvss', 'N/A'))
        # Use 'summary' if 'description' not available (for compatibility)
        description = cve.get('description', cve.get('summary', 'No description available'))
        published = cve.get('published', 'N/A')
        affected_service = cve.get('affected_service', 'N/A')
        affected_version = cve.get('affected_version', 'N/A')
        affected_port = cve.get('affected_port', 'N/A')
        
        # Emoji por severidade
        emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '⚪'
        }.get(severity, '⚫')
        
        lines.append(f"{emoji} [{i}/{len(sorted_cves)}] {cve_id}")
        lines.append(f"    Severity:       {severity}")
        lines.append(f"    CVSS Score:     {score}")
        lines.append(f"    Affected:       {affected_service} {affected_version} (port {affected_port})")
        lines.append(f"    Published:      {published}")
        lines.append(f"    Description:    {description[:300]}...")  # Limitar descrição
        lines.append(f"    Reference:      https://nvd.nist.gov/vuln/detail/{cve_id}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("")
    
    # Footer com recomendação
    lines.append("=" * 70)
    lines.append("⚠️  RECOMMENDATION: Prioritize patching CRITICAL and HIGH severity CVEs")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def create_cve_summary_table(cves):
    """
    Cria tabela Rich com resumo de CVEs para mostrar no terminal
    """
    console = Console()
    
    table = Table(title="🔍 CVE Summary (Top 10)", show_header=True, header_style="bold magenta")
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("Severity", style="red", width=10)
    table.add_column("Score", justify="center", width=6)
    table.add_column("Service", style="yellow", width=15)
    table.add_column("Description", style="white", width=40)
    
    # Mostrar apenas top 10 mais críticos
    for cve in cves[:10]:
        cve_id = cve.get('id', 'N/A')
        severity = cve.get('severity', 'UNKNOWN')
        # Handle both 'cvss' and 'score' keys
        score = str(cve.get('score', cve.get('cvss', 'N/A')))
        service = cve.get('affected_service', 'N/A')
        # Use 'summary' if 'description' not available
        desc = cve.get('description', cve.get('summary', 'N/A'))[:50] + "..."
        
        # Cor por severidade
        severity_style = {
            'CRITICAL': 'red bold',
            'HIGH': 'yellow',
            'MEDIUM': 'white',
            'LOW': 'green'
        }.get(severity, 'white')
        
        table.add_row(cve_id, f"[{severity_style}]{severity}[/{severity_style}]", score, service, desc)
    
    console.print(table)
    
    if len(cves) > 10:
        console.print(f"[dim]... and {len(cves) - 10} more (check full report)[/dim]\n")


def auto_cve_scan(services, report_path, log_file=None):
    """
    Automatically check CVEs for all discovered services
    
    Args:
        services: List of service dictionaries with 'service' and 'version' keys
        report_path: Path to report file
        log_file: Optional log file path
    
    Returns:
        List of all found CVEs
    """
    console = Console()
    console.print("\n[bold cyan]━━━ Running CVE vulnerability check... ━━━[/bold cyan]\n")
    
    all_cves = []
    
    for svc in services:
        service_name = svc.get('service', 'unknown')
        version_raw = svc.get('version', '')
        
        # Extract clean version number
        version = extract_version(version_raw)
        
        if not version:
            console.print(f"[dim]Skipping {service_name} (no version detected)[/dim]")
            continue
        
        # Check CVEs for this service
        cves = check_cve_nvd(service_name, version, log_file)
        
        if cves:
            all_cves.extend(cves)
    
    # Generate summary report
    if all_cves:
        # Helper function to safely convert CVSS to float
        def safe_cvss_to_float(cve):
            try:
                cvss = cve.get('cvss', 0)
                return float(cvss) if cvss != 'N/A' else 0
            except (ValueError, TypeError):
                return 0
        
        critical = [c for c in all_cves if c.get('severity') == 'CRITICAL' or safe_cvss_to_float(c) >= 9.0]
        high = [c for c in all_cves if c.get('severity') == 'HIGH' or (7.0 <= safe_cvss_to_float(c) < 9.0)]
        medium = [c for c in all_cves if c.get('severity') == 'MEDIUM' or (4.0 <= safe_cvss_to_float(c) < 7.0)]
        
        summary = f"""
CVE VULNERABILITY SCAN SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total CVEs Found: {len(all_cves)}
  🔴 Critical: {len(critical)}
  🟠 High: {len(high)}
  🟡 Medium: {len(medium)}

Recommendations:
  - Prioritize patching CRITICAL and HIGH severity vulnerabilities
  - Review service versions and update when possible
  - Consult NVD database for detailed remediation steps
"""
        
        append_section(report_path, "CVE Analysis Summary", summary)
        log(f"[+] CVE scan complete: {len(all_cves)} vulnerabilities found", log_file)
    else:
        console.print("[green][✓] CVE check completed. Found 0 vulnerabilities.[/green]\n")
        append_section(report_path, "CVE Analysis", "No known CVEs found for discovered services.")
    
    return all_cves
