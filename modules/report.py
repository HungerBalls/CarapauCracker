# modules/report.py
from fpdf import FPDF
import json
from colorama import Fore

def export_pdf(report_path, output_pdf):
    """
    Convert the text report file to a simple and readable PDF
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
            try:
                pdf.cell(0, 5, txt=line.encode('latin-1', 'ignore').decode('latin-1'), ln=True)
            except (UnicodeError, UnicodeEncodeError) as e:
                # Skip lines with encoding issues
                pdf.cell(0, 5, txt="[Line encoding error]", ln=True)

        pdf.output(output_pdf)
        print(Fore.GREEN + f"[✓] PDF report generated: {output_pdf}")

    except FileNotFoundError:
        print(Fore.RED + f"[!] Report file not found: {report_path}")
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied writing to: {output_pdf}")
    except Exception as e:
        print(Fore.RED + f"[!] Error exporting PDF: {e}")


def export_json(report_path, output_json):
    """
    Convert the report to JSON (each section separated by ===)
    """
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()

        sections = content.split("=" * 70)
        report_data = {}
        current_title = None

        for section in sections:
            lines = [l.strip() for l in section.splitlines() if l.strip()]
            if not lines:
                continue
            # First line is the title
            current_title = lines[0]
            report_data[current_title] = "\n".join(lines[1:])

        with open(output_json, "w", encoding="utf-8") as j:
            json.dump(report_data, j, indent=4, ensure_ascii=False)

        print(Fore.GREEN + f"[✓] JSON report generated: {output_json}")

    except FileNotFoundError:
        print(Fore.RED + f"[!] Report file not found: {report_path}")
    except PermissionError:
        print(Fore.RED + f"[!] Permission denied writing to: {output_json}")
    except json.JSONDecodeError as e:
        print(Fore.RED + f"[!] JSON encoding error: {e}")
    except Exception as e:
        print(Fore.RED + f"[!] Error exporting JSON: {e}")
