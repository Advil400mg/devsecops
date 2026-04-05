from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
import json
import os

# Configuration des chemins
dir = os.path.dirname(__file__)
json_path = os.path.join(dir, "sonar-report.json")
pdf_path = os.path.join(dir, "report.pdf")

### 1. Chargement et Traitement des Données
try:
    with open(json_path) as f:
        data = json.load(f)
except Exception as e:
    print(f"Erreur de lecture : {e}")
    exit()

issues = data.get("issues", [])
open_issues = [i for i in issues if i["status"] == "OPEN"]
closed_issues = [i for i in issues if i["status"] == "CLOSED"]

# Calcul du score et des statistiques [1, 2]
score = 100
total_effort = 0
for issue in open_issues:
    effort_min = int(issue.get("effort", "0min").replace("min", "")) # [3, 4]
    total_effort += effort_min
    if issue["severity"] == "BLOCKER": score -= 30
    elif issue["severity"] == "MAJOR": score -= 10
    elif issue["severity"] == "MINOR": score -= 2
score = max(score, 0)

### 2. Configuration du PDF
doc = SimpleDocTemplate(pdf_path, pagesize=A4)
styles = getSampleStyleSheet()
content = []

# Styles personnalisés
title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=24, spaceAfter=20, textColor=colors.navy)
header_style = ParagraphStyle('CustomHeader', parent=styles['Heading1'], fontSize=16, spaceAfter=10, color=colors.darkblue)

def add_spacer():
    content.append(Spacer(1, 12))

### 3. Fonctions de Construction
def create_summary_table():
    """Crée un tableau récapitulatif visuel."""
    table_data = [
        ["Indicateur", "Valeur"],
        ["Score de Sécurité", f"{score}/100"],
        ["Total des problèmes", len(issues)],
        ["Problèmes Ouverts", len(open_issues)],
        ["Dette technique (Effort)", f"{total_effort} min"],
        ["Problèmes Résolus", len(closed_issues)]
    ]
    t = Table(table_data, colWidths=[6*cm, 4*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.red if score < 50 else colors.green),
    ]))
    content.append(t)

def print_enhanced_issues(title, issues_list, color):
    """Affiche les problèmes sous forme de blocs d'information riches."""
    content.append(Paragraph(title, header_style))
    if not issues_list:
        content.append(Paragraph("Aucun problème détecté.", styles["Normal"]))
        return

    for i in issues_list:
        # Extraction des impacts [5, 6]
        impacts_str = ", ".join([f"{elm['softwareQuality']} ({elm['severity']})" for elm in i.get('impacts', [])])
        
        # Données du problème [3, 7-9]
        issue_info = [
            [Paragraph(f"<b>{i['message']}</b>", styles["Normal"])],
            [f"Composant : {i['component']} (Ligne {i.get('line', 'N/A')})"],
            [f"Type : {i.get('type', 'N/A')} | Effort : {i.get('effort', 'N/A')}"],
            [f"Impacts : {impacts_str}"]
        ]
        
        t = Table(issue_info, colWidths=[16*cm])
        t.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 1, color),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BACKGROUND', (0, 0), (0, 0), colors.whitesmoke),
        ]))
        content.append(t)
        add_spacer()

### 4. Génération du contenu
content.append(Paragraph("Rapport de Sécurité DevSecOps", title_style))
content.append(Paragraph(f"Date du rapport : 2026-04-05", styles["Normal"]))
add_spacer()

content.append(Paragraph("Résumé Exécutif", styles["Heading2"]))
create_summary_table()
add_spacer()

# Sections par sévérité [10]
blockers = [i for i in open_issues if i["severity"] == "BLOCKER"]
majors = [i for i in open_issues if i["severity"] == "MAJOR"]
minors = [i for i in open_issues if i["severity"] == "MINOR"]

print_enhanced_issues("🚨 Problèmes Critiques (BLOCKER)", blockers, colors.red)
print_enhanced_issues("⚠️ Problèmes Majeurs (MAJOR)", majors, colors.orange)
print_enhanced_issues("ℹ️ Problèmes Mineurs (MINOR)", minors, colors.blue)

content.append(PageBreak())
content.append(Paragraph("Historique des Corrections", styles["Heading1"]))
print_enhanced_issues("✅ Problèmes Résolus", closed_issues, colors.green)

### 5. Construction finale [11]
doc.build(content)
print(f"✅ Rapport amélioré généré : {pdf_path}")