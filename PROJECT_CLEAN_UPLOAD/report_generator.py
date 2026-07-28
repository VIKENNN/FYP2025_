from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from tabulate import tabulate
import os


class ReportGenerator:
    """
    A class to generate scan reports in both text and PDF formats.
    Fully supports CVE lookup, misconfiguration checks, port scanning, and generic session data.
    PDF output uses Courier font for a consistent monospaced style.
    """

    def __init__(self):
        # Load default styles and initialize custom ones
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

        # Table styling defaults
        self.max_items_per_page = 40
        self.table_style = {
            'header_color': colors.HexColor('#3A5FCD'),
            'header_text_color': colors.whitesmoke,
            'body_color': colors.HexColor('#F0F8FF'),
            'grid_color': colors.HexColor('#7D9EC0'),
            'font_name': 'Courier',  # Use Courier for all PDF tables
            'font_size': 9
        }

    def _init_custom_styles(self):
        """Initialize custom paragraph styles for bullets and table cells"""
        if 'CellStyle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CellStyle',
                parent=self.styles['Normal'],
                fontName='Courier',
                fontSize=8,
                leading=10,
                spaceAfter=2,
                spaceBefore=2
            ))

        if 'MyBullet' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='MyBullet',
                parent=self.styles['Normal'],
                fontName='Courier',
                leftIndent=10,
                bulletIndent=5,
                spaceAfter=4,
                bulletFontName='Courier',
                bulletFontSize=10
            ))

    def _sanitize_filename(self, text):
        """Sanitize filenames to remove invalid characters"""
        return "".join(c if c.isalnum() or c in ('-', '_') else "_" for c in text)

    def _format_timestamp(self):
        """Return current timestamp as string"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _create_table(self, data, headers=None, col_widths=None):
        """Create a styled PDF table with Courier font"""
        if isinstance(data[0], dict):
            if not headers:
                headers = list(data[0].keys())
            table_data = [headers] + [[str(row.get(h, '')) for h in headers] for row in data]
        else:
            table_data = data
            if headers:
                table_data.insert(0, headers)

        table = Table(table_data, colWidths=col_widths) if col_widths else Table(table_data)

        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.table_style['header_color']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.table_style['header_text_color']),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), f"{self.table_style['font_name']}-Bold"),
            ('FONTSIZE', (0, 0), (-1, 0), self.table_style['font_size']),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), self.table_style['body_color']),
            ('GRID', (0, 0), (-1, -1), 0.5, self.table_style['grid_color']),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ])
        table.setStyle(style)
        return table

    def _handle_cve_lookup(self, data, report_lines, pdf_elements):
        """Handle CVE lookup results with PDF table and text output"""
        software_info = data.get("software_info", "Unknown")
        results = data.get("results", [])
        count_msg = data.get("count_message", "")

        report_lines.append(f"Detected Software: {software_info}")
        pdf_elements.append(Paragraph(f"Detected Software: {software_info}", self.styles['Normal']))

        if not results:
            return

        # Text table
        report_lines.append(
            tabulate(results, headers="keys", tablefmt="grid", maxcolwidths=[None, None, 50, None, 30, None, None], stralign="left")
        )

        # PDF table
        headers = list(results[0].keys())
        wrapped_data = [headers]
        small_style = ParagraphStyle(
            name='SmallCell', parent=self.styles['Normal'], fontName='Courier',
            fontSize=7, leading=8, spaceAfter=2, spaceBefore=2
        )

        for row in results:
            wrapped_row = [Paragraph(str(row.get(h, "")), small_style) for h in headers]
            wrapped_data.append(wrapped_row)

        col_widths = [25, 50, 150, 40, 100, 50, 50]
        table = Table(wrapped_data, colWidths=col_widths)

        # Alternating row colors
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3A5FCD')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#7D9EC0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 3),
            ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ])
        for i in range(1, len(wrapped_data)):
            bg = colors.whitesmoke if i % 2 == 0 else colors.HexColor('#F0F8FF')
            table_style.add('BACKGROUND', (0, i), (-1, i), bg)

        table.setStyle(table_style)
        pdf_elements.append(table)

        if count_msg:
            report_lines.append(count_msg)
            pdf_elements.append(Paragraph(count_msg, self.styles['Normal']))

    def _handle_misconfig_checks(self, data, report_lines, pdf_elements):
        """Handle misconfiguration checks with bullet points"""
        def add_bullet_items(label, items):
            if items:
                report_lines.append(f"{label}:")
                pdf_elements.append(Paragraph(f"{label}:", self.styles['Normal']))
                for item in items:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            report_lines.append(f"  - {k}: {v}")
                            pdf_elements.append(Paragraph(f"{k}: {v}", self.styles['MyBullet']))
                    else:
                        report_lines.append(f"  - {item}")
                        pdf_elements.append(Paragraph(str(item), self.styles['MyBullet']))

        add_bullet_items("Directory Listing Enabled At", data.get("directory_listing", []))
        add_bullet_items("Missing Security Headers", data.get("missing_headers", []))
        verbose = data.get("verbose_errors", False)
        report_lines.append(f"Verbose Errors Detected: {'Yes' if verbose else 'No'}")
        pdf_elements.append(Paragraph(f"Verbose Errors Detected: {'Yes' if verbose else 'No'}", self.styles['Normal']))
        add_bullet_items("Insecure HTTP Methods Detected", data.get("insecure_methods", []))

    def _handle_portscan_data(self, data, report_lines, pdf_elements):
        """Handle Nmap/Portscan results"""
        if "results" in data and data["results"]:
            scan_type = data.get("scan_type", "")
            report_lines.append(f"[INFO] Nmap Scan Results: {scan_type}")
            pdf_elements.append(Paragraph(f"[INFO] Nmap Scan Results: {scan_type}", self.styles['Normal']))

            # Text table
            report_lines.append(tabulate(data["results"], headers="keys", tablefmt="grid", stralign="left"))

            # PDF table
            headers = list(data["results"][0].keys())
            col_widths = [60, 40, 100, 100, 50] if "Version" in headers else [70, 50, 100, 50]
            table = self._create_table(data["results"], headers=headers, col_widths=col_widths)
            pdf_elements.append(table)

            if "os_info" in data:
                report_lines.append(f"[INFO] OS Detection: {data['os_info']}")
                pdf_elements.append(Paragraph(f"[INFO] OS Detection: {data['os_info']}", self.styles['Normal']))
            if "cpe_info" in data:
                report_lines.append(f"[INFO] CPE Info: {data['cpe_info']}")
                pdf_elements.append(Paragraph(f"[INFO] CPE Info: {data['cpe_info']}", self.styles['Normal']))
            return True
        return False

    def _handle_generic_data(self, data, report_lines, pdf_elements, level=0):
        """Recursively handle generic dict/list data with bullets"""
        indent = "  " * level
        bullet_style = self.styles['MyBullet']

        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    report_lines.append(f"{indent}{k}:")
                    pdf_elements.append(Paragraph(f"{k}:", self.styles['Normal']))
                    self._handle_generic_data(v, report_lines, pdf_elements, level + 1)
                else:
                    report_lines.append(f"{indent}- {k}: {v}")
                    pdf_elements.append(Paragraph(f"{k}: {v}", bullet_style))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._handle_generic_data(item, report_lines, pdf_elements, level + 1)
                else:
                    report_lines.append(f"{indent}- {item}")
                    pdf_elements.append(Paragraph(str(item), bullet_style))
        else:
            report_lines.append(f"{indent}- {data}")
            pdf_elements.append(Paragraph(str(data), bullet_style))

    def generate_report(self, session_data, target_url, target_host):
        """Generate the full text and PDF report"""
        timestamp = self._format_timestamp()
        report_lines = [
            "=" * 80,
            f"SCAN REPORT FOR {target_host} ({target_url})",
            f"Generated: {timestamp}",
            "=" * 80,
            "\n"
        ]
        pdf_elements = [
            Paragraph(f"SCAN REPORT FOR {target_host} ({target_url})", ParagraphStyle('Title', fontName='Courier', fontSize=16)),
            Paragraph(f"Generated: {timestamp}", ParagraphStyle('Normal', fontName='Courier', fontSize=10)),
            Spacer(1, 12)
        ]

        for entry in session_data:
            module_type = entry.get("type", "UNKNOWN")
            data = entry.get("data", {})

            section_header = f"[{module_type.upper()}]"
            report_lines.extend([section_header, "-" * 80])
            pdf_elements.append(Paragraph(section_header, ParagraphStyle('Heading2', fontName='Courier', fontSize=12)))
            pdf_elements.append(Spacer(1, 6))

            if module_type == "vuln_CVELOOKUP":
                self._handle_cve_lookup(data, report_lines, pdf_elements)
            elif module_type == "vuln_MISCONFIGCHECKS":
                self._handle_misconfig_checks(data, report_lines, pdf_elements)
            elif module_type == "reconnaissance_PORTSCAN":
                if not self._handle_portscan_data(data, report_lines, pdf_elements):
                    self._handle_generic_data(data, report_lines, pdf_elements)
            else:
                self._handle_generic_data(data, report_lines, pdf_elements)

            report_lines.append("-" * 80)
            pdf_elements.append(Spacer(1, 12))

        return "\n".join(report_lines), pdf_elements

    def save_report(self, report_text, pdf_elements, target_host, target_url):
        """Save report to text and PDF files"""
        output_dir = "scan_reports"
        os.makedirs(output_dir, exist_ok=True)
        safe_host = self._sanitize_filename(target_host)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save text file
        txt_filename = os.path.join(output_dir, f"{safe_host}_{timestamp}_report.txt")
        with open(txt_filename, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"[+] Text report saved to {txt_filename}")

        # Save PDF file
        pdf_filename = os.path.join(output_dir, f"{safe_host}_{timestamp}_report.pdf")

        def add_footer(canvas, doc):
            """Add page footer to PDF"""
            canvas.saveState()
            canvas.setFont('Courier', 8)
            page_num = f"Page {canvas.getPageNumber()}"
            canvas.drawString(30, 30, page_num)
            canvas.drawRightString(A4[0] - 30, 30, f"Report for {target_host}")
            canvas.restoreState()

        doc = SimpleDocTemplate(pdf_filename, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
        doc.build(pdf_elements, onFirstPage=add_footer, onLaterPages=add_footer)
        print(f"[+] PDF report saved to {pdf_filename}")


