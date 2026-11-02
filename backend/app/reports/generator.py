import os
from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_incident_pdf(incident: dict, evidence: list, notes: list) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']
    
    elements = []
    
    # 1. Header
    elements.append(Paragraph(f"SecureLog AI - Incident Report", title_style))
    elements.append(Spacer(1, 12))
    
    # 2. Metadata
    elements.append(Paragraph("1. Executive Summary & Metadata", subtitle_style))
    data = [
        ["Incident ID:", incident.get("incident_number", "UNKNOWN")],
        ["Title:", incident.get("title", "UNKNOWN")],
        ["Severity:", incident.get("severity", "UNKNOWN")],
        ["Priority:", incident.get("priority", "UNKNOWN")],
        ["Status:", incident.get("status", "UNKNOWN")],
        ["Date Created:", str(incident.get("created_at", "UNKNOWN"))],
    ]
    t = Table(data, colWidths=[120, 400])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))
    
    # Description
    elements.append(Paragraph("Description:", styles['Heading3']))
    elements.append(Paragraph(incident.get("description", "No description provided."), normal_style))
    elements.append(Spacer(1, 20))
    
    # 3. Evidence
    elements.append(Paragraph("2. Evidence Collected", subtitle_style))
    if evidence:
        ev_data = [["Type", "Reference", "Description", "Time"]]
        for e in evidence:
            ev_data.append([
                str(e.get("evidence_type", "")),
                str(e.get("source_reference", "")),
                Paragraph(str(e.get("description", "")), normal_style),
                str(e.get("collected_at", ""))
            ])
        ev_table = Table(ev_data, colWidths=[60, 80, 260, 120])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(ev_table)
    else:
        elements.append(Paragraph("No evidence collected.", normal_style))
    
    elements.append(Spacer(1, 20))
    
    # 4. Analyst Notes
    elements.append(Paragraph("3. Analyst Investigation Notes", subtitle_style))
    if notes:
        for n in notes:
            elements.append(Paragraph(f"<b>Time:</b> {n.get('created_at')} | <b>Analyst ID:</b> {n.get('user_id')}", normal_style))
            elements.append(Paragraph(str(n.get("note_text", "")), normal_style))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No notes available.", normal_style))

    # 5. Footer
    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"<i>Report generated at: {datetime.utcnow().isoformat()} UTC</i>", normal_style))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_events_csv(events: list) -> str:
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Event Type", "Source IP", "Severity", "Message"])
    for e in events:
        writer.writerow([e.id, e.event_time, e.event_type, e.source_ip, e.severity, e.message])
    return output.getvalue()
