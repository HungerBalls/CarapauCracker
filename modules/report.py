# modules/report.py
from fpdf import FPDF
import json
from colorama import Fore
from datetime import datetime
from pathlib import Path


def is_section_empty(content):
    """Verifica se secção está vazia ou sem resultados"""
    if not content or len(content.strip()) < 20:
        return True
    
    empty_keywords = [
        "no data", "not found", "no results", "failed",
        "error", "timeout", "n/a", "none found",
        "0 results", "no ports", "nothing found"
    ]
    
    content_lower = content.lower()
    for keyword in empty_keywords:
        if keyword in content_lower and len(content) < 200:
            return True
    
    return False


def parse_report_sections(report_path):
    """
    Parse do report em secções, removendo vazias
    Retorna: dict com {título: conteúdo} apenas de secções com dados relevantes
    """
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Dividir por separadores "=" * 70
        parts = content.split("=" * 70)
        report_data = {}
        
        # Process pairs: title part and content part
        for i in range(len(parts) - 1):
            # Get the title from current part
            title_part = parts[i]
            lines = [l.strip() for l in title_part.splitlines() if l.strip()]
            
            # Look for a line with [ ... ]
            title = None
            for line in lines:
                if line.startswith('[') and line.endswith(']'):
                    title = line[1:-1].strip()
                    break
            
            # If we found a title, get content from next part
            if title and i + 1 < len(parts):
                content_part = parts[i + 1]
                section_content = content_part.strip()
                
                # Verificar se a secção tem conteúdo relevante
                if not is_section_empty(section_content):
                    report_data[title] = section_content
        
        return report_data
    
    except FileNotFoundError:
        print(Fore.RED + f"[!] Report file not found: {report_path}")
        return {}
    except Exception as e:
        print(Fore.RED + f"[!] Error parsing report sections: {e}")
        return {}


def export_pdf(report_path, output_pdf):
    """
    Convert the text report file to a professional PDF with filtered sections
    """
    try:
        # Parse e filtrar secções
        sections = parse_report_sections(report_path)
        
        if not sections:
            print(Fore.YELLOW + "[!] No relevant sections found in report")
            return False
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Header profissional
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, txt="CarapauCracker Security Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.cell(0, 6, txt=f"Sections with findings: {len(sections)}", ln=True, align="C")
        pdf.ln(10)
        
        # Table of Contents
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, txt="Table of Contents", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for i, title in enumerate(sections.keys(), 1):
            pdf.cell(0, 6, txt=f"  {i}. {title}", ln=True)
        pdf.ln(10)
        
        # Secções com conteúdo
        for title, content in sections.items():
            # Título com background azul claro
            pdf.set_fill_color(173, 216, 230)  # Light blue
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, txt=title, ln=True, fill=True)
            
            # Conteúdo em fonte Courier
            pdf.set_font("Courier", "", 9)
            for line in content.splitlines():
                try:
                    pdf.cell(0, 4, txt=line.encode('latin-1', 'ignore').decode('latin-1'), ln=True)
                except (UnicodeError, UnicodeEncodeError):
                    pdf.cell(0, 4, txt="[Line encoding error]", ln=True)
            
            pdf.ln(5)  # Separação entre secções
        
        # Footer
        pdf.ln(10)
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 6, txt="End of Report - CarapauCracker", ln=True, align="C")
        
        pdf.output(output_pdf)
        
        # Mensagem de sucesso com estatísticas
        print(Fore.GREEN + f"[✓] PDF report generated: {output_pdf}")
        print(Fore.GREEN + f"    ├─ Sections included: {len(sections)}")
        print(Fore.GREEN + f"    └─ Empty sections filtered out")
        
        return True

    except FileNotFoundError:
        print(Fore.RED + f"[!] Report file not found: {report_path}")
        return False
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied writing to: {output_pdf}")
        return False
    except Exception as e:
        print(Fore.RED + f"[!] Error exporting PDF: {e}")
        return False


def export_json(report_path, output_json):
    """
    Convert the report to JSON with metadata and filtered sections
    """
    try:
        # Parse e filtrar secções
        sections = parse_report_sections(report_path)
        
        if not sections:
            print(Fore.YELLOW + "[!] No relevant sections found in report")
            return False
        
        # Estrutura JSON melhorada
        report_data = {
            "metadata": {
                "tool": "CarapauCracker",
                "generated": datetime.now().isoformat(),
                "sections_count": len(sections)
            },
            "findings": sections
        }

        with open(output_json, "w", encoding="utf-8") as j:
            json.dump(report_data, j, indent=4, ensure_ascii=False)

        # Mensagem de sucesso com estatísticas
        print(Fore.GREEN + f"[✓] JSON report generated: {output_json}")
        print(Fore.GREEN + f"    ├─ Sections included: {len(sections)}")
        print(Fore.GREEN + f"    └─ Empty sections filtered out")
        
        return True

    except FileNotFoundError:
        print(Fore.RED + f"[!] Report file not found: {report_path}")
        return False
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied writing to: {output_json}")
        return False
    except json.JSONDecodeError as e:
        print(Fore.RED + f"[!] JSON encoding error: {e}")
        return False
    except Exception as e:
        print(Fore.RED + f"[!] Error exporting JSON: {e}")
        return False


def export_summary(report_path, output_summary):
    """
    Gera resumo executivo com apenas os highlights
    - Título e data
    - Primeiras 5 linhas de cada secção relevante
    - Total de secções com descobertas
    """
    try:
        # Parse e filtrar secções
        sections = parse_report_sections(report_path)
        
        if not sections:
            print(Fore.YELLOW + "[!] No relevant sections found in report")
            return False
        
        with open(output_summary, "w", encoding="utf-8") as f:
            # Header
            f.write("=" * 70 + "\n")
            f.write("CARAPAUCRACKER - EXECUTIVE SUMMARY\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total sections with findings: {len(sections)}\n")
            f.write("=" * 70 + "\n\n")
            
            # Highlights de cada secção (primeiras 5 linhas)
            for title, content in sections.items():
                f.write(f"\n[ {title} ]\n")
                f.write("-" * 70 + "\n")
                
                lines = content.splitlines()
                preview_lines = lines[:5]  # Primeiras 5 linhas
                f.write("\n".join(preview_lines))
                
                if len(lines) > 5:
                    f.write(f"\n... ({len(lines) - 5} more lines)")
                
                f.write("\n\n")
            
            # Footer
            f.write("=" * 70 + "\n")
            f.write("END OF EXECUTIVE SUMMARY\n")
            f.write("=" * 70 + "\n")
        
        # Mensagem de sucesso
        print(Fore.GREEN + f"[✓] Executive summary generated: {output_summary}")
        print(Fore.GREEN + f"    ├─ Sections included: {len(sections)}")
        print(Fore.GREEN + f"    └─ Preview: first 5 lines per section")
        
        return True
    
    except FileNotFoundError:
        print(Fore.RED + f"[!] Report file not found: {report_path}")
        return False
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied writing to: {output_summary}")
        return False
    except Exception as e:
        print(Fore.RED + f"[!] Error exporting summary: {e}")
        return False
