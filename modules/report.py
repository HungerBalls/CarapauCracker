# modules/report.py
from fpdf import FPDF
import json
from colorama import Fore

def export_pdf(report_path, output_pdf):
    """
    Converte o ficheiro de relatório de texto num PDF simples e legível
    """
    try:
        text = ""
        with open(report_path, "r", encoding="utf-8") as f:
            text = f.read()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Courier", size=10)

        for line in text.splitlines():
            pdf.cell(0, 5, txt=line.encode('latin-1', 'ignore').decode('latin-1'), ln=True)

        pdf.output(output_pdf)
        print(Fore.GREEN + f"[✓] Relatório PDF gerado: {output_pdf}")

    except Exception as e:
        print(Fore.RED + f"[!] Erro ao exportar PDF: {e}")


def export_json(report_path, output_json):
    """
    Converte o relatório em JSON (cada secção separada por ===)
    """
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()

        sections = content.split("=" * 60)
        report_data = {}
        current_title = None

        for section in sections:
            lines = [l.strip() for l in section.splitlines() if l.strip()]
            if not lines:
                continue
            # Primeira linha é o título
            current_title = lines[0]
            report_data[current_title] = "\n".join(lines[1:])

        with open(output_json, "w", encoding="utf-8") as j:
            json.dump(report_data, j, indent=4, ensure_ascii=False)

        print(Fore.GREEN + f"[✓] Relatório JSON gerado: {output_json}")

    except Exception as e:
        print(Fore.RED + f"[!] Erro ao exportar JSON: {e}")
