"""
Phase 5: Professional PDF Reporting Module
"""
import json
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List


class ReportGenerator:
    """Generates professional PDF penetration testing reports"""
    
    def __init__(self, results: Dict, logger):
        self.results = results
        self.logger = logger
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.target_clean = self._clean_filename(results.get('target', 'unknown'))
        self.report_data = self._prepare_report_data()
    
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
        recon = self.results.get('reconnaissance', {})
        scanning = self.results.get('scanning', {})
        
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
                'generated_by': 'SecureIntel Pro Framework',
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
            self.logger.info(f"[REPORT] ✓ Report saved: {output_dir}/{os.path.basename(pdf_file)}")
        
        return {'pdf': result}
    
    def generate_pdf_report(self, output_file: str):
        """Generate professional PDF report"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
            
            doc = SimpleDocTemplate(output_file, pagesize=A4, rightMargin=72, leftMargin=72, 
                                   topMargin=72, bottomMargin=72)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=28, 
                                        textColor=colors.HexColor('#667eea'), spaceAfter=30, 
                                        alignment=TA_CENTER, fontName='Helvetica-Bold')
            story.append(Spacer(1, 2*inch))
            story.append(Paragraph("PENETRATION TEST REPORT", title_style))
            story.append(Spacer(1, 0.5*inch))
            
            # Cover info
            meta = self.report_data['metadata']
            summary = self.report_data['executive_summary']
            
            cover_data = [
                ['Target:', meta['target']],
                ['Report ID:', meta['report_id']],
                ['Date:', meta['generated_at']],
                ['Risk Level:', summary['risk_level']],
                ['Status:', 'CONFIDENTIAL']
            ]
            
            cover_table = Table(cover_data, colWidths=[2*inch, 4*inch])
            cover_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('PADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(cover_table)
            story.append(PageBreak())
            
            # Executive Summary
            heading_style = ParagraphStyle('Heading', parent=styles['Heading1'], fontSize=18, 
                                          textColor=colors.HexColor('#667eea'), fontName='Helvetica-Bold')
            story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
            story.append(Spacer(1, 0.3*inch))
            
            summary_text = f"Assessment of <b>{meta['target']}</b> identified " \
                          f"<b>{summary['total_vulnerabilities']}</b> vulnerabilities, " \
                          f"<b>{summary['exploitable_vulnerabilities']}</b> exploitable."
            story.append(Paragraph(summary_text, styles['BodyText']))
            story.append(Spacer(1, 0.3*inch))
            
            # Risk metrics
            risk_data = [
                ['Metric', 'Count'],
                ['Total Vulnerabilities', str(summary['total_vulnerabilities'])],
                ['Exploitable', str(summary['exploitable_vulnerabilities'])],
                ['Critical', str(summary['critical_count'])],
                ['High', str(summary['high_count'])],
                ['Medium', str(summary['medium_count'])],
                ['Low', str(summary['low_count'])]
            ]
            
            risk_table = Table(risk_data, colWidths=[3*inch, 2*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('PADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER')
            ]))
            story.append(risk_table)
            story.append(PageBreak())
            
            # Target Profile
            story.append(Paragraph("TARGET PROFILE", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            profile = self.report_data['target_profile']
            profile_text = f"<b>Type:</b> {profile.get('type', 'Unknown')}<br/>"
            if profile.get('cms'):
                profile_text += f"<b>CMS:</b> {profile['cms']}<br/>"
            if profile.get('web_server'):
                profile_text += f"<b>Web Server:</b> {profile['web_server']}<br/>"
            if profile.get('waf'):
                profile_text += f"<b>WAF:</b> {profile['waf']}<br/>"
            if profile.get('cdn'):
                profile_text += f"<b>CDN:</b> {profile['cdn']}<br/>"
            
            story.append(Paragraph(profile_text, styles['BodyText']))
            story.append(Spacer(1, 0.3*inch))
            
            # Findings
            story.append(Paragraph("DETAILED FINDINGS", heading_style))
            story.append(Spacer(1, 0.2*inch))
            
            findings = self.report_data['findings']
            if not findings:
                story.append(Paragraph("No vulnerabilities detected.", styles['BodyText']))
            else:
                for idx, finding in enumerate(findings, 1):
                    finding_title = f"<b>Finding {idx}: {finding['title']}</b>"
                    if finding.get('exploitable'):
                        finding_title += " <font color='red'>[EXPLOITABLE]</font>"
                    
                    story.append(Paragraph(finding_title, styles['Heading2']))
                    story.append(Spacer(1, 0.1*inch))
                    
                    finding_text = f"<b>Severity:</b> {finding['severity']}<br/>"
                    finding_text += f"<b>Category:</b> {finding['category']}<br/>"
                    finding_text += f"<b>Description:</b> {finding['description']}<br/>"
                    if finding.get('url'):
                        finding_text += f"<b>URL:</b> {finding['url']}<br/>"
                    if finding.get('impact'):
                        finding_text += f"<b>Impact:</b> {finding['impact']}<br/>"
                    if finding.get('recommendation'):
                        finding_text += f"<b>Recommendation:</b> {finding['recommendation']}<br/>"
                    
                    story.append(Paragraph(finding_text, styles['BodyText']))
                    story.append(Spacer(1, 0.2*inch))
            
            # Footer
            story.append(Spacer(1, 1*inch))
            footer_text = "<i>This report is confidential and intended for authorized personnel only.</i><br/>"
            footer_text += f"<i>Generated by {meta['generated_by']}</i>"
            story.append(Paragraph(footer_text, styles['BodyText']))
            
            doc.build(story)
            self.logger.info(f"[REPORT] ✓ PDF generated successfully")
            return output_file
        except Exception as e:
            self.logger.error(f"[REPORT] ✗ PDF generation failed: {e}")
            return None
