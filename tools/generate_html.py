#!/usr/bin/env python3
"""
generate_html.py
Convert JSON output from scan_and_report.py to a simple HTML page.
Usage:
  python3 generate_html.py reports/nmap_target_...json -o reports/report.html
"""

import json
from pathlib import Path
import argparse
import html

def risk_level(entry):
    if entry.get("state") != "open":
        return "Info"
    s = (entry.get("service") or "").lower()
    if entry.get("port") in (21,22,23,25,143,3389):
        return "High"
    if any(x in s for x in ["ssh","telnet","ftp"]):
        return "High"
    if any(x in s for x in ["http","https","apache","nginx","tomcat"]):
        return "Medium"
    return "Low"

def generate(json_path, out_html):
    data = json.load(open(json_path))
    rows = []
    for r in data:
        rows.append((
            html.escape(r.get("host","")),
            str(r.get("port","")),
            html.escape(r.get("protocol","")),
            html.escape(r.get("state","")),
            html.escape(r.get("service","")),
            html.escape(r.get("product","") + " " + r.get("version","")),
            risk_level(r)
        ))
    # build html
    html_lines = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>Nmap Report</title>",
        "<style>table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:6px}</style>",
        "</head><body>",
        "<h1>Nmap Report</h1>",
        f"<p>Source JSON: {html.escape(json_path)}</p>",
        "<table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product</th><th>Risk</th></tr></thead><tbody>"
    ]
    for r in rows:
        html_lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    html_lines.append("</tbody></table></body></html>")
    Path(out_html).write_text("\n".join(html_lines), encoding="utf-8")
    print("Saved HTML report to:", out_html)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonfile", help="JSON file produced by scan_and_report.py")
    ap.add_argument("-o","--out", default="reports/report.html", help="output HTML path")
    args = ap.parse_args()
    generate(args.jsonfile, args.out)
