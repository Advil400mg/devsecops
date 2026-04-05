from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
import json
import os

# Configuration des chemins
dir = os.path.dirname(__file__)
sonar_json = os.path.join(dir, "sonar-report.json")
docker_json = os.path.join(dir, "docker-scan.json")
pdf_path = os.path.join(dir, "scans-report.pdf")

### 1. Chargement des Données
def load_json(path):
    try:
        with open(path) as f: return json.load(f)
    except: return None

sonar_data = load_json(sonar_json)
docker_data = load_json(docker_json)

### 2. Configuration du PDF
doc = SimpleDocTemplate(pdf_path, pagesize=A4)
styles = getSampleStyleSheet()
content = []

# Styles personnalisés
title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=22, textColor=colors.navy, spaceAfter=20)
h1_style = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=16, textColor=colors.darkblue, spaceBefore=15)
h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, textColor=colors.darkblue)

### 3. Section SonarQube (Code & Qualité)
if sonar_data:
    content.append(Paragraph("1. Analyse du Code Source (SonarQube)", h1_style))
    issues = sonar_data.get("issues", [])
    open_issues = [i for i in issues if i["status"] == "OPEN"]
    
    # Tableau résumé Code
    summary_code = [
        ["Total Issues", "Ouvertes", "Dette Technique"],
        [len(issues), len(open_issues), f"{sonar_data.get('effortTotal', 0)} min"]
    ]
    t = Table(summary_code, colWidths=[5*cm]*3)
    t.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('BACKGROUND',(0,0),(-1,0), colors.whitesmoke)]))
    content.append(t)
    content.append(Spacer(1, 15))

### 4. Section Docker (Image & OS)
if docker_data:
    content.append(Paragraph("2. Analyse de l'Image Docker (Trivy)", h1_style))
    
    # Métadonnées de l'image
    meta = docker_data.get("Metadata", {})
    img_name = docker_data.get("ArtifactName", "N/A")
    os_info = f"{meta.get('OS', {}).get('Family', 'N/A')} {meta.get('OS', {}).get('Name', '')}"
    
    content.append(Paragraph(f"<b>Image :</b> {img_name} | <b>OS :</b> {os_info}", styles["Normal"]))
    content.append(Spacer(1, 10))

    # Extraction des vulnérabilités
    vulnerabilities = []
    for result in docker_data.get("Results", []):
        vulnerabilities.extend(result.get("Vulnerabilities", []))

    if vulnerabilities:
        content.append(Paragraph(f"Vulnérabilités détectées : {len(vulnerabilities)}", h2_style))
        
        # En-tête du tableau Docker
        data_vuls = [["ID", "Package", "Sévérité", "Titre"]]
        
        for v in vulnerabilities[:15]:  # Limité aux 15 premières pour la lisibilité
            sev = v.get("Severity", "UNKNOWN")
            # Couleur selon sévérité
            color = colors.red if sev in ["CRITICAL", "HIGH"] else colors.orange if sev == "MEDIUM" else colors.black
            
            data_vuls.append([
                Paragraph(f"<font color='blue'>{v.get('VulnerabilityID')}</font>", styles["Normal"]),
                v.get("PkgName"),
                Paragraph(f"<b>{sev}</b>", ParagraphStyle('Sev', parent=styles['Normal'], textColor=color)),
                Paragraph(v.get("Title", "N/A")[:50] + "...", styles["Normal"])
            ])

        t_vuls = Table(data_vuls, colWidths=[4*cm, 3*cm, 3*cm, 7*cm])
        t_vuls.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        content.append(t_vuls)
    else:
        content.append(Paragraph("Aucune vulnérabilité détectée dans l'image.", styles["Normal"]))

### 5. Génération
content.insert(0, Paragraph("Rapport de Sécurité Consolidé DevSecOps", title_style))
doc.build(content)
print(f"✅ Rapport consolidé généré : {pdf_path}")