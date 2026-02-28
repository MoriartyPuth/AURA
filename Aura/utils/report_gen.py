from fpdf import FPDF
from datetime import datetime

class AuraReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 14)
        self.cell(0, 10, "AURA-SCANNER: NATIONAL AUDIT REPORT", ln=True, align="C")
        self.ln(5)

def generate_pdf_report(target, osint, ids, nucs, output_path):
    pdf = AuraReport()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, f"Target: {target}", ln=True)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", ln=True)
    pdf.ln(10)

    for title, data in [("OSINT Discovery", osint), ("Identity & Logic", ids), ("Vulnerability Scan", nucs)]:
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(0, 10, title, ln=True, fill=True)
        pdf.set_font("helvetica", "", 10)
        if not data: pdf.cell(0, 8, "No findings.", ln=True)
        for line in data: pdf.multi_cell(0, 8, f"- {line}")
        pdf.ln(5)

    pdf.output(output_path)