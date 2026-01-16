from modules.scan import (
    nmap_quick, nmap_detailed, nmap_full_tcp,
    nmap_udp_scan, nmap_os_detection, full_scan_workflow,
    full_scan_with_cve
)
from modules.utils import banner, log, append_section
from colorama import Fore
from rich.panel import Panel
from rich.console import Console

def run_scan_menu(target, run_dir, report_path, session_log):
    """Scanning submenu for port and system scanning"""
    console = Console()
    
    while True:
        banner()
        console.print(Panel.fit(
            "[cyan]1[/cyan] - Quick Scan (open ports)\n"
            "[cyan]2[/cyan] - Detailed Scan (-sV -sC)\n"
            "[cyan]3[/cyan] - Full TCP Scan (-p-)\n"
            "[cyan]4[/cyan] - UDP Scan (Top 50)\n"
            "[cyan]5[/cyan] - OS Detection (-O)\n"
            "[cyan]6[/cyan] - Aggressive Scan (-A)\n"
            "[cyan]7[/cyan] - Manual CVE Check\n"
            "[cyan]8[/cyan] - Run Complete Scan 🚀\n"
            "[cyan]9[/cyan] - Full Scan + CVE Check 🔍\n"
            "[cyan]0[/cyan] - Return",
            title="📡 Port Scanning Menu",
            border_style="cyan"
        ))

        opt = input(Fore.YELLOW + "\n[»] Choose option: ").strip()

        if opt == "0":
            banner()
            break
        elif opt == "1":
            nmap_quick(target, report_path, session_log)
        elif opt == "2":
            log(Fore.CYAN + f"\n[NMAP] Running detailed scan on {target}", session_log)
            output = nmap_detailed(target, [], report_path, session_log)
            
            # Extrair serviços do output do Nmap
            from modules.scan import extract_services_from_output
            services = extract_services_from_output(output)
            
            if services:
                # Mostrar serviços encontrados
                console. print(f"\n[green]✓ Found {len(services)} services with version info[/green]")
                
                # ═══ PERGUNTAR se quer fazer CVE check ═══
                run_cve = input(Fore.YELLOW + "\n[?] Run CVE vulnerability check on these services? (Y/n): ").strip().lower()
                
                if run_cve != 'n':  # Default é "yes"
                    console.print("\n[cyan]┌─────────────────────────────────────┐[/cyan]")
                    console.print("[cyan]│  Starting CVE Analysis...            │[/cyan]")
                    console.print("[cyan]└─────────────────────────────────────┘[/cyan]\n")
                    
                    # Importar e executar CVE checker
                    from modules.cve_checker import check_service_vulnerabilities, create_cve_summary_table
                    
                    try:
                        cves = check_service_vulnerabilities(services, report_path, session_log)
                        
                        # Mostrar resumo visual no terminal
                        if cves:
                            create_cve_summary_table(cves)
                            
                            # Sugestão de próximos passos
                            console.print("\n[yellow]💡 Tip: Check 'Automated Exploitation' menu to search for exploits[/yellow]")
                        else:
                            console.print("[green]✓ Good news! No known CVEs for detected service versions[/green]")
                    
                    except Exception as e: 
                        log(Fore.RED + f"[✘] Error during CVE analysis: {e}", session_log)
                        console.print(f"[red][✘] CVE analysis failed:  {e}[/red]")
                else:
                    console.print("[yellow]⊘ CVE check skipped[/yellow]")
            else:
                log(Fore. YELLOW + "[!] No services with version info found", session_log)
                console. print("[yellow][⚠] No services with version detected[/yellow]")
        elif opt == "3":
            nmap_full_tcp(target, report_path, session_log)
        elif opt == "4":
            nmap_udp_scan(target, report_path, session_log)
        elif opt == "5":
            nmap_os_detection(target, report_path, session_log)
        elif opt == "6":
            from modules.scan import nmap_aggressive
            nmap_aggressive(target, report_path, session_log)
        elif opt == "7":
            console.print("[cyan]Manual CVE Vulnerability Check[/cyan]\n")
            
            service = input(Fore.YELLOW + "[?] Service name (e.g., apache, openssh, mysql): ").strip()
            version = input(Fore.YELLOW + "[?] Version (e.g., 2.4.29, 7.4, 5.5.62): ").strip()
            
            if service and version:
                from modules.cve_checker import check_cve_nvd, format_cve_report
                
                log(Fore.CYAN + f"\n[CVE] Manual check: {service} {version}", session_log)
                cves = check_cve_nvd(service, version, session_log)
                
                if cves:
                    from modules.cve_checker import create_cve_summary_table
                    
                    # Mostrar tabela
                    create_cve_summary_table(cves)
                    
                    # Perguntar se quer adicionar ao report
                    add_to_report = input(Fore.YELLOW + "\n[?] Add to report? (y/N): ").strip().lower()
                    if add_to_report == 'y':
                        # Criar mock de services para formatar
                        services = [{'service': service, 'version': version, 'port': 'manual'}]
                        cve_report = format_cve_report(cves, services)
                        append_section(report_path, f"CVE CHECK - {service} {version}", cve_report)
                        console.print("[green][✓] Added to report[/green]")
                else:
                    console.print(f"[green]✓ No CVEs found for {service} {version}[/green]")
            else:
                console.print("[red][✘] Service and version are required[/red]")
        elif opt == "8":
            full_scan_workflow(target, report_path, session_log)
        elif opt == "9":
            full_scan_with_cve(target, report_path, session_log)
        else:
            log(Fore.RED + "[✘] Invalid option. Try again.", session_log)

        input(Fore.YELLOW + "\nPress ENTER to continue...")

