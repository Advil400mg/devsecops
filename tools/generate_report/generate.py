from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import json
import os

dir = os.path.dirname(__file__)

# Load data
try:
    with open(os.path.join(dir,"sonar-report.json")) as f:
        data = json.load(f)
except:
    ...


issues = data["issues"]

# Filter open issues
open_issues = [i for i in issues if i["status"] == "OPEN"]

# Score calculation
score = 100
for issue in open_issues:
    if issue["severity"] == "BLOCKER":
        score -= 30
    elif issue["severity"] == "MAJOR":
        score -= 10
    elif issue["severity"] == "MINOR":
        score -= 2

score = max(score, 0)

# Split by severity
blockers = [i for i in open_issues if i["severity"] == "BLOCKER"]
majors = [i for i in open_issues if i["severity"] == "MAJOR"]
minors = [i for i in open_issues if i["severity"] == "MINOR"]

# PDF
doc = SimpleDocTemplate(os.path.join(dir,"report.pdf"))
styles = getSampleStyleSheet()
content = []

def add_title(text):
    content.append(Paragraph(f"<b>{text}</b>", styles["Title"]))
    content.append(Spacer(1, 12))


def add_chapter(text):
    content.append(Paragraph(f"<b>{text}</b>", styles["Heading1"]))
    content.append(Spacer(1, 11))

def add_section(text):
    content.append(Paragraph(f"<b>{text}</b>", styles["Heading2"]))
    content.append(Spacer(1, 10))

def add_text(text):
    content.append(Paragraph(text, styles["Normal"]))
    content.append(Spacer(1, 8))

# Title
add_title("DevSecOps Security Report")

# Summary
add_section("Summary")
add_text(f"Total issues: {len(issues)}")
add_text(f"Open issues: {len(open_issues)}")
add_text(f"Security Score: {score}/100")

# Function to print issues
def print_issues(title, issues_list):
    add_section(title)
    if not issues_list:
        add_text("No issues")
        return
    for i in issues_list:
        add_text(
            f"[{i['severity']}] {i['component']}:{i.get('line','?')}<br/>"
            f"{i['message']}"
        )
        #f"Issue on {i['impacts']['softwareQuality']} with severity {i['impacts']['severity']}"
        for elm in i['impacts']:
            add_text(
                f"Impact on {elm['softwareQuality']} with severity {elm['severity']}"
            )

# Sections
print_issues("Critical Issues (BLOCKER)", blockers)
print_issues("Medium Issues (MAJOR)", majors)
print_issues("Low Issues (MINOR)", minors)


open_issues = [i for i in issues if i["status"] == "CLOSED"]


# Split by severity
blockers = [i for i in open_issues if i["severity"] == "BLOCKER"]
majors = [i for i in open_issues if i["severity"] == "MAJOR"]
minors = [i for i in open_issues if i["severity"] == "MINOR"]

add_chapter("Resolved issues")
# Sections
print_issues("Critical Issues (BLOCKER)", blockers)
print_issues("Medium Issues (MAJOR)", majors)
print_issues("Low Issues (MINOR)", minors)
# Build PDF
doc.build(content)

print("✅ PDF generated")