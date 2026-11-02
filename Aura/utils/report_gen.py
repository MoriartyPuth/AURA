from datetime import datetime

from fpdf import FPDF
from fpdf.enums import XPos, YPos

# Move to the start of the next line after each cell (fpdf2 defaults to staying on the same line).
NEXT_LINE = {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}

class AuraReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 14)
        self.cell(0, 10, "AURA-SCANNER: NATIONAL AUDIT REPORT", **NEXT_LINE, align="C")
        self.ln(5)

def _render_phase(pdf, title, phase_data):
    pdf.set_fill_color(230, 235, 245)
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(0, 10, title, **NEXT_LINE, fill=True)
    pdf.set_font("helvetica", "", 10)

    for sub_title, entries in phase_data.items():
        pdf.set_font("helvetica", "B", 10)
        pdf.multi_cell(0, 7, f"[{sub_title}]", **NEXT_LINE)
        pdf.set_font("helvetica", "", 10)
        if not entries:
            pdf.multi_cell(0, 7, "- No significant findings.", **NEXT_LINE)
        for line in entries:
            pdf.multi_cell(0, 7, f"- {line}", **NEXT_LINE)
        pdf.ln(1)

    pdf.ln(4)


def _render_risk_table(pdf, risks, max_rows=25):
    pdf.set_fill_color(245, 230, 230)
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(0, 10, "Prioritized Risk Table", **NEXT_LINE, fill=True)
    pdf.set_font("helvetica", "", 9)

    if not risks:
        pdf.multi_cell(0, 6, "No prioritized risks generated.", **NEXT_LINE)
        pdf.ln(3)
        return

    for risk in risks[:max_rows]:
        line = (
            f"[{risk['score']}] [{risk['severity']}] "
            f"{risk['phase']} / {risk['source']} - {risk['finding']}"
        )
        pdf.multi_cell(0, 6, line, **NEXT_LINE)

    pdf.ln(4)


def generate_pdf_report(target, phase0, phase1, phase2, risks, output_path):
    pdf = AuraReport()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, f"Target: {target}", **NEXT_LINE)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", **NEXT_LINE)
    pdf.ln(10)

    _render_risk_table(pdf, risks)
    _render_phase(pdf, "Phase 0: Recon & Attack Surface", phase0)
    _render_phase(pdf, "Phase 1: Identity & Vulnerability Probes", phase1)
    _render_phase(pdf, "Phase 2: Deep Vulnerability Scanning", phase2)

    pdf.output(output_path)
