"""Paginated PDF reports with escaped user-supplied labels and paths."""
import io
from html import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, KeepTogether, PageBreak

STYLES = getSampleStyleSheet()
STYLES["Heading3"].fontName = "Helvetica-Bold"
STYLES.add(ParagraphStyle(name="SmallCell", fontName="Helvetica", fontSize=8, leading=11, spaceAfter=2,
    wordWrap="CJK", alignment=TA_LEFT))

def clean(value):
    # Built-in PDF fonts use WinAnsi. Replace unsupported characters explicitly.
    return str(value if value is not None else "-").encode("cp1252", "replace").decode("cp1252")

def p(value, style="SmallCell"):
    return Paragraph(escape(clean(value)).replace("\n", "<br/>"), STYLES[style])

def table(headers, rows, widths):
    cells = [[p(h) for h in headers]] + [[p(c) for c in row] for row in rows]
    item = LongTable(cells, colWidths=[w*mm for w in widths], repeatRows=1, hAlign="LEFT")
    item.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8edf2")),
        ("VALIGN", (0,0), (-1,-1), "TOP"), ("LINEBELOW", (0,0), (-1,0), .5, colors.HexColor("#aab4c0")),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7), ("TOPPADDING", (0,0), (-1,-1), 7),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f7f8fa")]),
    ]))
    return item

def document(story, title):
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=(210*mm,297*mm), rightMargin=18*mm, leftMargin=18*mm,
        topMargin=18*mm, bottomMargin=19*mm, title=title, author="FirmGuard")
    def footer(canvas, doc):
        canvas.saveState(); canvas.setFont("Helvetica",8); canvas.setFillColor(colors.HexColor("#5b6471"))
        canvas.drawString(18*mm, 11*mm, "FirmGuard | Static security analysis")
        canvas.drawRightString(192*mm,11*mm,f"Page {doc.page}"); canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()

def finding_story(findings):
    story = []
    if not findings: return [p("No supported patterns were detected. This does not prove security.")]
    # Individual paragraphs can split across pages, unlike an oversized table cell.
    for index, f in enumerate(findings,1):
        block = [p(f"{index}. [{f['severity']}] {f['type']}", "Heading3"),
            p(f"Rule: {f['rule_id']} | File: {f['filename']} | Line: {f.get('line') or '-'}"),
            p(f["explanation"]), p("Action: " + f["remediation"])]
        if f.get("key"): block.append(p(f"Assignment: {f['key']}=********"))
        if f.get("reference"): block.append(p("Reference: " + f["reference"]))
        block.append(Spacer(1,3*mm))
        story.append(KeepTogether(block))
    return story

def scan_pdf(record):
    r = record["result"]
    story = [p("FirmGuard security report", "Title"), p("Scan summary", "Heading2")]
    rows = [("Device", record["device"]), ("Version / revision", f"{record['version']} / {record['revision']}"),
        ("Scan / created (UTC)", f"{record['id']} / {record['created_at']}"), ("Input / bytes", f"{r['filename']} / {r['size_bytes']}"),
        ("Scanner / advisory rules", f"{r['scanner_version']} / {r['advisory_revision']}"),
        ("Extraction / coverage", f"{r['extraction']['method']} / {r['coverage']}"),
        ("Files / text / binary", f"{r['files_scanned']} / {r['text_files']} / {r['binary_files']}"),
        ("Findings", str(r["finding_count"]))]
    story += [table(["Field","Value"],rows,[48,126]), p("Integrity", "Heading2"),
        p("SHA-256: " + r["integrity"]["sha256"]), p("Reference status: " + r["integrity"]["status"]),
        p("Expected digest: " + str(r["integrity"]["expected_sha256"] or "not supplied")),
        p("Scope and limitations", "Heading2"), p(r["notice"])]
    for warning in r["warnings"]: story.append(p("Coverage note: " + warning))
    story += [p("Software inventory", "Heading2")]
    if r["components"]:
        story.append(table(["Component","Version","File / evidence","Check"],
            [(c["product"],c["version"],c["filename"] + " / " + c["source"],c["check_status"]) for c in r["components"]], [28,30,80,36]))
    else: story.append(p("No supported component version evidence was found."))
    story.append(p("ELF security properties", "Heading2"))
    for binary in r["elf"]:
        story += [p(binary["filename"], "Heading3"), p("; ".join(f"{k}: {v}" for k,v in binary.items() if k != "filename"))]
    if not r["elf"]: story.append(p("No ELF files found."))
    story += [PageBreak(), p("Findings and actions", "Heading2"), *finding_story(r["findings"]), p("File manifest", "Heading2")]
    story.append(table(["Path","Bytes / mode","SHA-256"], [(f["path"],f"{f['size_bytes']} / {f['mode']}",f["sha256"]) for f in r["manifest"]], [65,30,79]))
    return document(story, "FirmGuard security report")

def comparison_pdf(result):
    story = [p("FirmGuard version comparison", "Title"), p(result["device"], "Heading2"),
        p(f"Baseline: #{result['baseline_id']} ({result['baseline_version']})"),
        p(f"Candidate: #{result['candidate_id']} ({result['candidate_version']})"), p(result["notice"]),
        p("Finding changes", "Heading2"), p("; ".join(f"{k}: {v}" for k,v in result["counts"].items())),
        p("File changes", "Heading2"), p("; ".join(f"{k}: {v}" for k,v in result["file_counts"].items()))]
    for category in ["added","removed","changed"]:
        story.append(p(category.title(), "Heading3"))
        for item in result["files"][category]:
            story.append(p(item if isinstance(item,str) else f"{item['path']} | {item['baseline_sha256']} -> {item['candidate_sha256']} | mode {item['baseline_mode']} -> {item['candidate_mode']}"))
    story.append(p("Software changes", "Heading2"))
    for item in result["software_changes"]:
        story.append(p(f"{item['product']}: {', '.join(item['baseline_versions']) or '-'} -> {', '.join(item['candidate_versions']) or '-'}"))
    for category in ["new","still_present","no_longer_detected"]:
        story += [p(category.replace("_"," ").title(), "Heading2"), *finding_story(result[category])]
    return document(story, "FirmGuard version comparison")
