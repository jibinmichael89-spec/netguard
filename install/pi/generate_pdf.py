#!/usr/bin/env python3
"""Convert NetGuard-Pi-Install-Guide.md to PDF."""

from pathlib import Path

import markdown
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
MD_PATH = HERE / "NetGuard-Pi-Install-Guide.md"
PDF_PATH = HERE / "NetGuard-Pi-Install-Guide.pdf"

CSS = """
@page { margin: 20mm 18mm; }
body {
  font-family: "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 11pt;
  line-height: 1.5;
  color: #111;
  max-width: 100%;
}
h1 {
  font-size: 24pt;
  color: #1a365d;
  border-bottom: 2px solid #2b6cb0;
  padding-bottom: 8px;
  margin-top: 0;
}
h2 { font-size: 16pt; color: #2c5282; margin-top: 24px; page-break-after: avoid; }
h3 { font-size: 13pt; color: #2d3748; margin-top: 16px; page-break-after: avoid; }
p, li { margin: 5px 0; }
ul, ol { margin: 8px 0 8px 20px; }
code {
  font-family: Consolas, "Courier New", monospace;
  font-size: 9.5pt;
  background: #f4f4f4;
  padding: 1px 4px;
  border-radius: 3px;
}
pre {
  font-family: Consolas, "Courier New", monospace;
  font-size: 9pt;
  background: #f7fafc;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  padding: 10px 12px;
  white-space: pre-wrap;
  word-break: break-word;
  page-break-inside: avoid;
}
table {
  border-collapse: collapse;
  width: 100%;
  margin: 12px 0;
  font-size: 10pt;
  page-break-inside: avoid;
}
th, td { border: 1px solid #cbd5e0; padding: 7px 10px; text-align: left; }
th { background: #edf2f7; font-weight: 600; }
hr { border: none; border-top: 1px solid #e2e8f0; margin: 20px 0; }
strong { color: #1a202c; }
a { color: #2b6cb0; text-decoration: none; }
.footer {
  margin-top: 32px;
  padding-top: 12px;
  border-top: 1px solid #e2e8f0;
  font-size: 9pt;
  color: #718096;
  text-align: center;
}
"""


def build_html(markdown_text: str) -> str:
    body = markdown.markdown(markdown_text, extensions=["tables", "fenced_code", "nl2br"])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NetGuard Pi Install Guide</title>
  <style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>"""


def main() -> None:
    markdown_text = MD_PATH.read_text(encoding="utf-8")
    html = build_html(markdown_text)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_content(html, wait_until="networkidle")
        page.pdf(
            path=str(PDF_PATH),
            format="A4",
            print_background=True,
            margin={"top": "18mm", "right": "16mm", "bottom": "18mm", "left": "16mm"},
        )
        browser.close()

    print(f"Wrote {PDF_PATH} ({PDF_PATH.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
