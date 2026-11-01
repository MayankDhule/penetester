"""
Phase 5: Professional PDF Reporting Module - Enhanced Version
"""
import os
from datetime import datetime
from typing import Dict, List
from .tool_recommender import ToolRecommender


class ReportGenerator:
    """Generates professional PDF penetration testing reports"""
    
    def __init__(self, results: Dict, logger):
        self.results = results
        self.logger = logger
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.target_clean = self._clean_filename(results.get('target', 'unknown'))
        self.report_data = self._prepare_report_data()
        self.tool_recommender = ToolRecommender()  # Initialize tool recommender
    
    def _clean_filename(self, name: str) -> str:
        """Clean filename by removing invalid characters"""
        import re
        name = re.sub(r'https?://', '', name)
        name = re.sub(r'[^\w\-.]', '_', name)
        return name[:50]
    
    def _prepare_report_data(self) -> Dict:
        """Prepare comprehensive report data"""
        vulns = self.results.get('vulnerabilities', {})
        exploits = self.results.get('exploits', {})
        profile = self.results.get('profile', {})
        strategy = self.results.get('strategy', {})
        
        total_vulns = vulns.get('total_count', 0)
        exploitable = exploits.get('exploits_successful', 0)
        
        risk_level = 'LOW'
        if exploitable > 0 or vulns.get('critical', 0) > 0:
            risk_level = 'CRITICAL'
        elif vulns.get('high', 0) > 0:
            risk_level = 'HIGH'
        elif vulns.get('medium', 0) > 0:
            risk_level = 'MEDIUM'
        
        return {
            'metadata': {
                'target': self.results.get('target'),
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'generated_by': 'Pentestrr v1.0.0',
                'report_id': f"PENTEST-{self.timestamp}"
            },
            'executive_summary': {
                'risk_level': risk_level,
                'total_vulnerabilities': total_vulns,
                'exploitable_vulnerabilities': exploitable,
                'critical_count': vulns.get('critical', 0),
                'high_count': vulns.get('high', 0),
                'medium_count': vulns.get('medium', 0),
                'low_count': vulns.get('low', 0)
            },
            'target_profile': {
                'type': profile.get('target_type', 'unknown'),
                'cms': profile.get('cms'),
                'web_server': profile.get('web_server'),
                'programming_language': profile.get('programming_language'),
                'frameworks': profile.get('frameworks', []),
                'attack_surface': profile.get('attack_surface', []),
                'waf': profile.get('waf'),
                'cdn': profile.get('cdn'),
                'open_ports': profile.get('open_ports', [])
            },
            'attack_strategy': {
                'recommended_phases': strategy.get('recommended_phases', []),
                'recommended_tools': strategy.get('recommended_tools', []),
                'attack_vectors': strategy.get('attack_vectors', []),
                'risk_level': strategy.get('risk_level', 'unknown')
            },
            'findings': self._prepare_findings(vulns, exploits)
        }
    
    def _prepare_findings(self, vulns: Dict, exploits: Dict) -> List[Dict]:
        """Prepare findings list sorted by severity"""
        findings = []
        
        for vuln in vulns.get('vulnerabilities', []):
            findings.append({
                'type': 'vulnerability',
                'title': vuln.get('title'),
                'severity': vuln.get('severity'),
                'category': vuln.get('category'),
                'description': vuln.get('description'),
                'url': vuln.get('url'),
                'exploitable': False
            })
        
        for exploit in exploits.get('exploits', []):
            findings.append({
                'type': 'exploit',
                'title': exploit.get('type'),
                'severity': exploit.get('severity'),
                'category': 'Exploitation',
                'description': exploit.get('evidence'),
                'url': exploit.get('url'),
                'exploitable': True,
                'confidence': exploit.get('confidence', 'probable'),
                'impact': exploit.get('impact'),
                'recommendation': exploit.get('recommendation')
            })
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        return findings
    
    def generate_all_reports(self, output_dir: str = 'reports'):
        """Generate PDF report with unique filename"""
        os.makedirs(output_dir, exist_ok=True)
        
        pdf_file = os.path.join(output_dir, f"pentest_{self.target_clean}_{self.timestamp}.pdf")
        
        self.logger.info(f"\n[REPORT] Generating professional PDF report...")
        
        result = self.generate_pdf_report(pdf_file)
        
        if result:
            self.logger.info(f"[REPORT] Report saved: {output_dir}/{os.path.basename(pdf_file)}")
        
        return {'pdf': result}
    
    def generate_pdf_report(self, output_file: str):
        """Generate professional PDF report using ReportLab"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, PageBreak,
                                           Table, TableStyle, KeepTogether)
            from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
            
            # Create document
            doc = SimpleDocTemplate(
                output_file,
                pagesize=A4,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=0.75*inch,
                bottomMargin=0.75*inch
            )
            
            story = []
            styles = getSampleStyleSheet()
            
            # Define colors
            primary_color = colors.HexColor('#1a237e')
            secondary_color = colors.HexColor('#283593')
            critical_color = colors.HexColor('#b71c1c')
            high_color = colors.HexColor('#d32f2f')
            medium_color = colors.HexColor('#f57c00')
            low_color = colors.HexColor('#fbc02d')
            info_color = colors.HexColor('#0288d1')
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=28,
                textColor=primary_color,
                spaceAfter=20,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=primary_color,
                fontName='Helvetica-Bold',
                spaceAfter=12,
                spaceBefore=20
            )
            
            subheading_style = ParagraphStyle(
                'CustomSubHeading',
                parent=styles['Heading2'],
                fontSize=12,
                textColor=secondary_color,
                fontName='Helvetica-Bold',
                spaceAfter=8,
                spaceBefore=10
            )
            
            body_style = ParagraphStyle(
                'CustomBody',
                parent=styles['BodyText'],
                fontSize=10,
                alignment=TA_JUSTIFY,
                spaceAfter=10
            )
            
            # Get data
            meta = self.report_data['metadata']
            summary = self.report_data['executive_summary']
            profile = self.report_data['target_profile']
            findings = self.report_data['findings']
            
            # === COVER PAGE ===
            story.append(Spacer(1, 2*inch))
            story.append(Paragraph("PENETRATION TESTING REPORT", title_style))
            story.append(Spacer(1, 0.5*inch))
            
            # Target info
            target_style = ParagraphStyle('Target', parent=styles['Heading2'], 
                                         fontSize=18, alignment=TA_CENTER,
                                         textColor=secondary_color, fontName='Helvetica-Bold')
            story.append(Paragraph(meta['target'], target_style))
            story.append(Spacer(1, 0.5*inch))
            
            # Risk badge
            risk_color = {
                'CRITICAL': critical_color,
                'HIGH': high_color,
                'MEDIUM': medium_color,
                'LOW': low_color
            }.get(summary['risk_level'], colors.grey)
            
            risk_table = Table([[summary['risk_level']]], colWidths=[2.5*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), risk_color),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 18),
                ('PADDING', (0, 0), (-1, -1), 15),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 1*inch))
            
            # Metadata table
            meta_data = [
                ['Report ID:', meta['report_id']],
                ['Date:', meta['generated_at']],
                ['Generated By:', meta['generated_by']],
                ['Classification:', 'CONFIDENTIAL']
            ]
            meta_table = Table(meta_data, colWidths=[2*inch, 3.5*inch])
            meta_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.grey),
            ]))
            story.append(meta_table)
            story.append(PageBreak())
            
            # === EXECUTIVE SUMMARY ===
            story.append(Paragraph("1. EXECUTIVE SUMMARY", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            summary_text = f"""This report presents the findings of a comprehensive security assessment 
            conducted on <b>{meta['target']}</b>. The assessment identified a total of 
            <b>{summary['total_vulnerabilities']}</b> security vulnerabilities, of which 
            <b>{summary['exploitable_vulnerabilities']}</b> were confirmed as exploitable."""
            
            story.append(Paragraph(summary_text, body_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Vulnerability breakdown
            vuln_data = [
                ['Severity', 'Count'],
                ['Critical', str(summary['critical_count'])],
                ['High', str(summary['high_count'])],
                ['Medium', str(summary['medium_count'])],
                ['Low', str(summary['low_count'])]
            ]
            
            vuln_table = Table(vuln_data, colWidths=[2.5*inch, 1.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('PADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(vuln_table)
            
            if summary['exploitable_vulnerabilities'] > 0:
                story.append(Spacer(1, 0.3*inch))
                alert_text = f"""<b>CRITICAL ALERT:</b> {summary['exploitable_vulnerabilities']} 
                vulnerabilities were successfully exploited during testing, indicating immediate 
                security risks that require urgent remediation."""
                alert_style = ParagraphStyle('Alert', parent=body_style, 
                                            textColor=critical_color,
                                            leftIndent=10, rightIndent=10,
                                            borderWidth=1, borderColor=critical_color,
                                            borderPadding=10)
                story.append(Paragraph(alert_text, alert_style))
            
            story.append(PageBreak())
            
            # === TARGET PROFILE ===
            story.append(Paragraph("2. TARGET PROFILE", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Technology stack
            tech_data = [['Component', 'Details']]
            if profile.get('type'):
                tech_data.append(['Target Type', profile['type']])
            if profile.get('cms'):
                tech_data.append(['CMS', profile['cms']])
            if profile.get('web_server'):
                tech_data.append(['Web Server', profile['web_server']])
            if profile.get('waf'):
                tech_data.append(['WAF', profile['waf']])
            if profile.get('cdn'):
                tech_data.append(['CDN', profile['cdn']])
            
            if len(tech_data) > 1:
                tech_table = Table(tech_data, colWidths=[2*inch, 4*inch])
                tech_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), secondary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                story.append(tech_table)
            
            # Attack surface
            if profile.get('attack_surface'):
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("<b>Attack Surface:</b>", subheading_style))
                attack_text = ', '.join(profile['attack_surface'])
                story.append(Paragraph(attack_text, body_style))
            
            # Open ports
            if profile.get('open_ports'):
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("<b>Open Ports:</b>", subheading_style))
                ports_text = ', '.join([str(p) for p in profile['open_ports'][:20]])
                story.append(Paragraph(ports_text, body_style))
            
            story.append(PageBreak())
            
            # === DETAILED FINDINGS ===
            story.append(Paragraph("3. DETAILED SECURITY FINDINGS", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            if not findings:
                story.append(Paragraph("No security vulnerabilities were identified.", body_style))
            else:
                for idx, finding in enumerate(findings, 1):
                    # Finding header
                    severity_color_map = {
                        'CRITICAL': critical_color,
                        'HIGH': high_color,
                        'MEDIUM': medium_color,
                        'LOW': low_color,
                        'INFO': info_color
                    }
                    sev_color = severity_color_map.get(finding['severity'], colors.grey)
                    
                    header_data = [[f"Finding #{idx}: {finding['title']}", finding['severity']]]
                    header_table = Table(header_data, colWidths=[4.5*inch, 1.5*inch])
                    header_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, 0), secondary_color),
                        ('BACKGROUND', (1, 0), (1, 0), sev_color),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 11),
                        ('PADDING', (0, 0), (-1, -1), 10),
                        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
                    ]))
                    story.append(header_table)
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Finding details
                    if finding.get('category'):
                        story.append(Paragraph(f"<b>Category:</b> {finding['category']}", body_style))
                    if finding.get('url'):
                        story.append(Paragraph(f"<b>URL:</b> {finding['url']}", body_style))
                    if finding.get('exploitable'):
                        conf = (finding.get('confidence') or 'probable').lower()
                        status_map = {
                            'confirmed': 'CONFIRMED - Vulnerability validated during testing',
                            'probable': 'PROBABLE - Indicator observed; manual verification required',
                            'info': 'INFORMATIONAL - Potential issue, not verified',
                        }
                        story.append(Paragraph(
                            f"<b>Status:</b> {status_map.get(conf, status_map['probable'])}",
                            body_style))
                    
                    story.append(Paragraph(f"<b>Description:</b> {finding['description']}", body_style))
                    
                    if finding.get('impact'):
                        story.append(Paragraph(f"<b>Impact:</b> {finding['impact']}", body_style))
                    if finding.get('recommendation'):
                        story.append(Paragraph(f"<b>Recommendation:</b> {finding['recommendation']}", body_style))
                    
                    # Add tool recommendations
                    if finding.get('recommended_tools'):
                        story.append(Spacer(1, 0.1*inch))
                        story.append(Paragraph("<b>🛠️ Recommended Tools for Further Testing:</b>", body_style))
                        
                        for tool_idx, tool in enumerate(finding['recommended_tools'][:2], 1):  # Top 2 tools
                            tool_text = f"{tool_idx}. <b>{tool['name']}</b> ({tool['type']}): {tool['description']}"
                            story.append(Paragraph(tool_text, body_style))
                            cmd_style = ParagraphStyle('Command', parent=body_style, 
                                                      fontName='Courier', fontSize=8,
                                                      leftIndent=20, textColor=colors.HexColor('#2c3e50'))
                            story.append(Paragraph(f"<i>{tool['command']}</i>", cmd_style))
                    
                    story.append(Spacer(1, 0.3*inch))
            
            story.append(PageBreak())
            
            # === METHODOLOGY ===
            story.append(Paragraph("4. ASSESSMENT METHODOLOGY", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            methodology_text = """This security assessment followed industry-standard penetration testing 
            methodologies including OWASP Testing Guide and PTES (Penetration Testing Execution Standard)."""
            story.append(Paragraph(methodology_text, body_style))
            story.append(Spacer(1, 0.2*inch))
            
            phases = [
                ("Phase 0: Smart Profiling", "Intelligent target analysis and attack strategy generation"),
                ("Phase 1: Reconnaissance", "Information gathering, DNS enumeration, and port scanning"),
                ("Phase 2: Scanning & Enumeration", "Web crawling, directory discovery, and endpoint enumeration"),
                ("Phase 3: Vulnerability Detection", "Security header analysis, SSL/TLS checks, and vulnerability scanning"),
                ("Phase 4: Exploitation", "Safe exploitation attempts to confirm vulnerability exploitability")
            ]
            
            for phase_name, phase_desc in phases:
                story.append(Paragraph(f"<b>{phase_name}:</b> {phase_desc}", body_style))
            
            # Footer
            story.append(Spacer(1, 0.5*inch))
            footer_text = """<i>This report contains confidential information and is intended solely for 
            the use of the individual or entity to whom it is addressed. Unauthorized distribution or 
            copying of this report is strictly prohibited.</i>"""
            story.append(Paragraph(footer_text, body_style))
            
            # Build PDF
            doc.build(story)
            self.logger.info(f"[REPORT] Professional PDF generated successfully")
            return output_file
            
        except Exception as e:
            self.logger.error(f"[REPORT] PDF generation failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return None
