from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import json
import os

def generate_pdf_report(analyses):
    """Generate a PDF report for IOC analyses"""
    
    # Validate input
    if not analyses or len(analyses) == 0:
        raise ValueError("No IOC analyses provided for PDF generation")
    
    # Create temporary file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/tmp/ioc_report_{timestamp}.pdf"
    
    # Create PDF document
    doc = SimpleDocTemplate(filename, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    # Title
    title = Paragraph("IOC Analysis Report", title_style)
    story.append(title)
    
    # Report metadata
    report_info = [
        ['Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ['Total IOCs Analyzed:', str(len(analyses))],
        ['Report ID:', timestamp]
    ]
    
    info_table = Table(report_info, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7'))
    ]))
    
    story.append(info_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Summary table
    summary_heading = Paragraph("Executive Summary", heading_style)
    story.append(summary_heading)
    
    summary_data = [['IOC', 'Type', 'Threat Score', 'Severity', 'Category']]
    
    for analysis in analyses:
        summary_data.append([
            Paragraph(analysis.ioc[:50], styles['Normal']),
            analysis.ioc_type,
            str(analysis.threat_score),
            analysis.severity,
            analysis.threat_category
        ])
    
    summary_table = Table(summary_data, colWidths=[2.5*inch, 0.8*inch, 1*inch, 0.8*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
    ]))
    
    story.append(summary_table)
    story.append(PageBreak())
    
    # Detailed analysis for each IOC
    for idx, analysis in enumerate(analyses, 1):
        # IOC heading
        ioc_heading = Paragraph(f"IOC #{idx}: {analysis.ioc}", heading_style)
        story.append(ioc_heading)
        
        # Basic info
        basic_info = [
            ['IOC:', analysis.ioc],
            ['Type:', analysis.ioc_type],
            ['Analyzed At:', analysis.analyzed_at.strftime("%Y-%m-%d %H:%M:%S")],
            ['Threat Score:', f"{analysis.threat_score}/100"],
            ['Severity:', analysis.severity],
            ['Threat Category:', analysis.threat_category],
            ['Threat Type:', analysis.threat_type]
        ]
        
        basic_table = Table(basic_info, colWidths=[1.5*inch, 5*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7'))
        ]))
        
        story.append(basic_table)
        story.append(Spacer(1, 0.2*inch))
        
        # AI Summary
        if analysis.ai_summary:
            summary_heading = Paragraph("<b>AI Analysis Summary:</b>", styles['Normal'])
            story.append(summary_heading)
            summary_text = Paragraph(analysis.ai_summary, styles['Normal'])
            story.append(summary_text)
            story.append(Spacer(1, 0.1*inch))
        
        # AI Recommendation
        if analysis.ai_recommendation:
            rec_heading = Paragraph("<b>AI Recommendation:</b>", styles['Normal'])
            story.append(rec_heading)
            # Handle multi-line recommendations
            rec_formatted = analysis.ai_recommendation.replace('\n', '<br/>')
            rec_formatted = rec_formatted.replace('•', '&bull;')
            rec_text = Paragraph(rec_formatted, styles['Normal'])
            story.append(rec_text)
            story.append(Spacer(1, 0.2*inch))
        
        # Detailed results from tools
        try:
            details = json.loads(analysis.detailed_results)
            if details:
                details_heading = Paragraph("<b>Tool Analysis Results:</b>", styles['Normal'])
                story.append(details_heading)
                story.append(Spacer(1, 0.1*inch))
                
                for tool, data in details.items():
                    if isinstance(data, dict) and not data.get('error'):
                        tool_text = f"<b>{tool.upper()}:</b> "
                        
                        # Detection counts
                        if 'malicious' in data:
                            tool_text += f"Malicious: {data['malicious']}, "
                        if 'suspicious' in data:
                            tool_text += f"Suspicious: {data['suspicious']}, "
                        if 'harmless' in data:
                            tool_text += f"Harmless: {data['harmless']}, "
                        if 'abuse_confidence_score' in data:
                            tool_text += f"Abuse Score: {data['abuse_confidence_score']}%, "
                        
                        # ViewDNS links
                        if 'reverse_ip' in data:
                            tool_text += f"Reverse IP: {data['reverse_ip']}, "
                        if 'dns_record' in data:
                            tool_text += f"DNS: {data['dns_record']}, "
                        if 'whois' in data:
                            tool_text += f"WHOIS: {data['whois']}, "
                        
                        # Palo Alto
                        if 'search' in data:
                            tool_text += f"Search: {data['search']}, "
                        
                        # Zscaler
                        if 'url_to_check' in data:
                            tool_text += f"URL: {data['url_to_check']}, "
                        
                        # Generic link
                        if 'link' in data:
                            tool_text += f"Link: {data['link']}, "
                        
                        # Note
                        if 'note' in data:
                            tool_text += f"Note: {data['note']}"
                        
                        # Remove trailing comma and space
                        tool_text = tool_text.rstrip(', ')
                        
                        tool_para = Paragraph(tool_text, styles['Normal'])
                        story.append(tool_para)
                        story.append(Spacer(1, 0.05*inch))
        except:
            pass
        
        # Add page break between IOCs (except for the last one)
        if idx < len(analyses):
            story.append(PageBreak())
    
    # Build PDF
    doc.build(story)
    
    return filename
