from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import json
import os
from datetime import datetime

dir = os.path.dirname(__file__)

# ======================
# 🎨 PALETTE
# ======================
PRIMARY = colors.HexColor("#AAAAF7FF")
SECONDARY = colors.HexColor("#000000")
ACCENT = colors.HexColor("#4FC3F7")

RED = colors.HexColor("#FF4C4C")
ORANGE = colors.HexColor("#FFA726")
YELLOW = colors.HexColor("#FFD54F")
GREEN = colors.HexColor("#66BB6A")

# ======================
# 📂 LOAD DATA
# ======================
try:
    with open(os.path.join(dir, "sonar-report.json")) as f:
        sonar_data = json.load(f)
    with open(os.path.join(dir, "trivy-report.json")) as f:
        trivy_data = json.load(f)
except Exception as e:
    print(f"Erreur de chargement : {e}")
    exit()

# ======================
# 🔍 SONAR PROCESSING
# ======================
issues = sonar_data.get("issues", [])
open_issues = [i for i in issues if i["status"] == "OPEN"]
resolved_issues = [i for i in issues if i["status"] == "CLOSED" or i.get("resolution") == "FIXED"]

score = 100
for issue in open_issues:
    if issue["severity"] == "BLOCKER":
        score -= 30
    elif issue["severity"] == "CRITICAL":
        score -= 20
    elif issue["severity"] == "MAJOR":
        score -= 10
    elif issue["severity"] == "MINOR":
        score -= 2
score = max(score, 0)

# ======================
# 🐳 TRIVY PROCESSING
# ======================
artifact_name = trivy_data.get("ArtifactName", "N/A")
os_info = trivy_data.get("Metadata", {}).get("OS", {}).get("Name", "Inconnu")

vulnerabilities = []
for result in trivy_data.get("Results", []):
    vulnerabilities.extend(result.get("Vulnerabilities", []))

trivy_critical = [v for v in vulnerabilities if v["Severity"] == "CRITICAL"]
trivy_high = [v for v in vulnerabilities if v["Severity"] == "HIGH"]
trivy_medium = [v for v in vulnerabilities if v["Severity"] == "MEDIUM"]

# ======================
# 🎨 STYLES
# ======================
styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="HeaderTech",
    fontSize=16,
    textColor=ACCENT,
    spaceAfter=10
))

styles.add(ParagraphStyle(
    name="SectionTech",
    fontSize=12,
    textColor=colors.white,
    backColor=SECONDARY,
    leftIndent=5,
    spaceBefore=10,
    spaceAfter=10
))

styles.add(ParagraphStyle(
    name="NormalTech",
    fontSize=9,
    leading=12,
    spaceAfter=6
))

styles.add(ParagraphStyle(
    name="Mono",
    fontName="Courier",
    fontSize=8,
    leading=10
))

# ======================
# 📄 PDF INIT
# ======================
doc = SimpleDocTemplate(os.path.join(dir, "consolidated_security_report.pdf"))
content = []

# ======================
# 🧱 HELPERS
# ======================
def add_header(text):
    content.append(Paragraph(text, styles["HeaderTech"]))

def add_section(text):
    content.append(Paragraph(text, styles["SectionTech"]))

def add_text(text, mono=False):
    style = styles["Mono"] if mono else styles["NormalTech"]
    content.append(Paragraph(text, style))

def add_separator():
    content.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    content.append(Spacer(1, 10))

def severity_color(sev):
    return {
        "CRITICAL": RED,
        "HIGH": ORANGE,
        "MEDIUM": YELLOW,
        "LOW": GREEN,
        "BLOCKER": RED,
        "MAJOR": ORANGE,
        "MINOR": YELLOW
    }.get(sev, colors.white)

# ======================
# 🧾 HEADER
# ======================
add_header("🛡️ DEVSECOPS SECURITY REPORT")
add_text(f"<font size=8>{datetime.now().strftime('%Y-%m-%d %H:%M')}</font>")
add_text(f"<font name='Courier'>Image: {artifact_name} | OS: {os_info}</font>")

add_separator()

# ======================
# 📊 KPI
# ======================
kpi_data = [
    ["Score", "Open Issues", "Critical Vulns", "Total Vulns"],
    [
        str(score),
        str(len(open_issues)),
        str(len(trivy_critical)),
        str(len(vulnerabilities))
    ]
]

t = Table(kpi_data, colWidths=[120]*4)

t.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), SECONDARY),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),

    ('BACKGROUND', (0, 1), (-1, 1), PRIMARY),

    ('TEXTCOLOR', (0, 1), (0, 1), GREEN if score > 80 else ORANGE if score > 50 else RED),
    ('TEXTCOLOR', (2, 1), (2, 1), RED),

    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),

    ('BOX', (0, 0), (-1, -1), 1, colors.grey),
]))

content.append(t)
content.append(Spacer(1, 15))

add_separator()

# ======================
# 🚨 SCA (TRIVY)
# ======================
add_section("🔥 CRITICAL & HIGH VULNERABILITIES")

if trivy_critical or trivy_high:
    for v in trivy_critical + trivy_high:
        color = severity_color(v["Severity"])
        add_text(
            f"<font color='{color.hexval()}'><b>[{v['Severity']}]</b></font> "
            f"{v['PkgName']}:{v['InstalledVersion']} → {v['VulnerabilityID']}<br/>"
            f"<font size=7>{v.get('Title','')}</font>"
        )
else:
    add_text("No critical/high vulnerabilities detected.")

add_separator()

add_section("⚠️ MEDIUM VULNERABILITIES")

if trivy_medium:
    for v in trivy_medium[:30]:
        add_text(
            f"[MEDIUM] {v['PkgName']} → {v['VulnerabilityID']}",
            mono=True
        )
else:
    add_text("No medium vulnerabilities.")

add_separator()
content.append(PageBreak())
# ======================
# 💻 SAST ANALYSIS
# ======================
add_section("💻 SAST ANALYSIS")

if open_issues:

    # ----------------------
    # 📊 KPI SAST
    # ----------------------
    total = len(open_issues)
    blocker = len([i for i in open_issues if i["severity"] == "BLOCKER"])
    critical = len([i for i in open_issues if i["severity"] == "CRITICAL"])
    major = len([i for i in open_issues if i["severity"] == "MAJOR"])
    minor = len([i for i in open_issues if i["severity"] == "MINOR"])

    critical_ratio = int(((blocker + critical) / total) * 100) if total > 0 else 0

    sast_kpi = [
        ["Metric", "Value"],
        ["Total Issues", str(total)],
        ["Blocker", str(blocker)],
        ["Critical", str(critical)],
        ["Major", str(major)],
        ["Minor", str(minor)],
        ["Critical %", f"{critical_ratio}%"]
    ]

    t = Table(sast_kpi, colWidths=[180, 120])

    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SECONDARY),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),

        ('BACKGROUND', (0, 1), (-1, -1), PRIMARY),

        # Couleurs dynamiques
        ('TEXTCOLOR', (1, 2), (1, 2), RED),       # Blocker
        ('TEXTCOLOR', (1, 3), (1, 3), RED),       # Critical
        ('TEXTCOLOR', (1, 4), (1, 4), ORANGE),    # Major
        ('TEXTCOLOR', (1, 5), (1, 5), YELLOW),    # Minor

        ('TEXTCOLOR', (1, 6), (1, 6),
            RED if critical_ratio > 20 else ORANGE if critical_ratio > 10 else GREEN),

        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))

    content.append(t)
    content.append(Spacer(1, 15))

    # ----------------------
    # 📁 Top fichiers
    # ----------------------
    file_count = {}
    for i in open_issues:
        f = i.get("component", "unknown")
        file_count[f] = file_count.get(f, 0) + 1

    top_files = sorted(file_count.items(), key=lambda x: x[1], reverse=True)[:5]

    add_text("<b>Top impacted files:</b>")
    for f, count in top_files:
        add_text(f"<font name='Courier'>{f} → {count} issues</font>")

    add_separator()

    # ----------------------
    # 🚨 PRIORITY ISSUES
    # ----------------------
    add_text("<b>🚨 Priority issues (Blocker / Critical)</b>")

    priority = [i for i in open_issues if i["severity"] in ["BLOCKER", "CRITICAL"]]

    if priority:
        for i in priority[:15]:
            color = severity_color(i["severity"])
            add_text(
                f"<font color='{color.hexval()}'><b>[{i['severity']}]</b></font> "
                f"{i['component']}:{i.get('line','?')}<br/>"
                f"<font size=8>{i['message']}</font>"
            )
    else:
        add_text("No priority issues.")

    add_separator()

    # ----------------------
    # ⚠️ MAJOR
    # ----------------------
    add_text("<b>⚠️ Major issues</b>")

    majors = [i for i in open_issues if i["severity"] == "MAJOR"]

    for i in majors[:20]:
        add_text(
            f"[MAJOR] {i['component']}:{i.get('line','?')} → {i['message']}",
            mono=True
        )

    add_separator()

    # ----------------------
    # 🧾 REST
    # ----------------------
    others = total - len(priority) - len(majors)
    add_text(f"<b>Other issues (minor/info):</b> {others}")

else:
    add_text("No SAST issues detected.")

add_separator()

# ======================
# ✅ RESOLVED
# ======================
add_section("✅ RESOLVED ISSUES")

if resolved_issues:
    for i in resolved_issues[:20]:
        add_text(
            f"[FIXED] {i['component']} → {i['message']}",
            mono=True
        )
else:
    add_text("No resolved issues.")

# ======================
# 📄 BUILD
# ======================
doc.build(content)

print(f"✅ Rapport généré : {os.path.join(dir, 'scans-report.pdf')}")