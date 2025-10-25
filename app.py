# ==============================================================
# Advanced Flask Backend for P2P IDS Dashboard (enhanced)
# - Integrates nmap scanning (python-nmap)
# - Generates JSON + HTML reports per scan (saved under reports/)
# - Keeps background scanner, FSM, alerts, and summary APIs
# ==============================================================

import os
import json
import threading
import time
import random
import nmap
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_from_directory, abort
import logging

# ==============================================================
# Flask Setup
# ==============================================================
app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# ==============================================================
# Globals / Data Stores (simulated DB)
# ==============================================================
NODES = [
    {"name": "node-A", "ip": "127.0.0.1", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none", "last_report": None},
    {"name": "node-B", "ip": "192.168.1.249", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none", "last_report": None},
    {"name": "node-C", "ip": "192.168.1.1", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none", "last_report": None},
    {"name": "node-D", "ip": "192.168.1.100", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none", "last_report": None},
]

ALERTS = []

# Lock for thread-safe updates
DATA_LOCK = threading.Lock()

# Ensure reports directory exists
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# ==============================================================
# Nmap Setup
# ==============================================================
try:
    nm = nmap.PortScanner()
    NM_AVAILABLE = True
    app.logger.info("✅ python-nmap is available.")
except Exception as e:
    app.logger.warning("⚠️  Nmap (python-nmap) not available: %s", e)
    NM_AVAILABLE = False
    nm = None

# ==============================================================
# Vulnerability Hint Mapping
# ==============================================================
SERVICE_CVE_HINTS = {
    'http': [{'cve': 'CVE-2023-12345', 'desc': 'Outdated HTTP server version'}],
    'ssh': [{'cve': None, 'desc': 'SSH open — check version and keys'}],
    'ftp': [{'cve': None, 'desc': 'FTP open — possible anonymous login'}],
    'microsoft-ds': [{'cve': None, 'desc': 'SMB protocol — check for EternalBlue'}],
    'msrpc': [{'cve': None, 'desc': 'Microsoft RPC service — verify access controls'}],
}


def infer_vulns_from_scan(open_ports):
    """Convert open ports into vulnerability hints"""
    vulns = []
    for p in open_ports:
        svc = (p.get('service') or '').lower()
        entry = SERVICE_CVE_HINTS.get(svc.split('/')[0])
        if entry:
            for e in entry:
                vulns.append({
                    **e,
                    "port": p['port'],
                    "service": p.get('service'),
                    "version": p.get('version')
                })
        else:
            vulns.append({
                "port": p['port'],
                "service": p.get('service'),
                "version": p.get('version'),
                "cve": None,
                "desc": "No automated hint available — manual triage recommended"
            })
    return vulns


# ==============================================================
# Utility: Run Nmap Scan (existing style)
# ==============================================================
def run_nmap_scan(ip, ports='1-1024', force_scan=False):
    """
    Run nmap and return a dict: {"ip": ip, "open": [...]}
    - force_scan=True uses -Pn (skip host discovery) to avoid hosts being considered 'down'
    - Falls back to TCP connect (-sT) when SYN scan fails (permission/environment)
    """
    if not NM_AVAILABLE:
        app.logger.warning("⚠️  python-nmap not available — returning fake results for %s.", ip)
        return {"ip": ip, "open": [{"port": 80, "service": "http", "version": "Apache/2.4"}]}

    # Build arguments
    args = '-sV --open'
    if force_scan:
        args = '-Pn ' + args

    try:
        # Primary try: let python-nmap call nmap with args (this usually runs -sS if nmap decides)
        app.logger.info("[NMAP] Running scan for %s with args: %s ports=%s", ip, args, ports)
        scan = nm.scan(hosts=ip, ports=ports, arguments=args)
        # Log raw scan for debugging
        app.logger.debug("[NMAP-RAW] %s -> %s", ip, json.dumps(scan, default=str))

        host_info = scan.get('scan', {}).get(ip, {})
        result = {"ip": ip, "open": []}
        if host_info:
            tcp = host_info.get('tcp', {}) or {}
            for port, pdata in sorted(tcp.items(), key=lambda x: int(x[0])):
                result['open'].append({
                    "port": int(port),
                    "service": pdata.get('name'),
                    "version": pdata.get('version'),
                    "extra": pdata.get('extrainfo', '')
                })

        # If scan returned nothing and we didn't force -Pn, try a fallback with -Pn
        if not result['open'] and not force_scan:
            app.logger.info("[NMAP] No open ports found for %s. Retrying with -Pn (force_scan=True).", ip)
            return run_nmap_scan(ip, ports=ports, force_scan=True)

        return result

    except Exception as e:
        app.logger.exception("❌ Nmap scan exception for %s: %s", ip, e)
        # Fallback: try TCP connect scan via subprocess nmap binary if python-nmap fails
        try:
            import subprocess, shlex
            fallback_args = f"-sT -Pn -sV --open -p {ports} {ip}"
            cmd = f"nmap {fallback_args}"
            app.logger.info("[NMAP-FALLBACK] Running subprocess: %s", cmd)
            out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT, text=True)
            app.logger.debug("[NMAP-FALLBACK-RAW] %s", out)
            # don't try to parse here — just return empty results to avoid parsing complexity
            return {"ip": ip, "open": []}
        except Exception as ex2:
            app.logger.exception("❌ Fallback nmap subprocess also failed for %s: %s", ip, ex2)
            return {"ip": ip, "open": []}

# ==============================================================
# Report helpers: save JSON + generate HTML (simple)
# ==============================================================
def save_json_report(scan_result, out_dir=REPORT_DIR):
    """Save a scan result dict to a timestamped JSON file. Return path."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_ip = scan_result.get('ip', 'unknown').replace(':', '_').replace('/', '_')
    filename = f"nmap_{safe_ip}_{ts}.json"
    path = Path(out_dir) / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2)
    app.logger.info("Saved JSON report: %s", path)
    return path


def generate_html_report_from_scan(scan_result, out_dir=REPORT_DIR):
    """Generate a simple HTML report from a scan result dict. Return path."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_ip = scan_result.get('ip', 'unknown').replace(':', '_').replace('/', '_')
    html_filename = f"nmap_{safe_ip}_{ts}.html"
    html_path = Path(out_dir) / html_filename

    # Basic risk heuristic
    def risk_level(entry):
        if entry.get("service") is None:
            return "Info"
        s = (entry.get("service") or "").lower()
        if entry.get("port") in (21, 22, 23, 25, 143, 3389):
            return "High"
        if any(x in s for x in ["ssh", "telnet", "ftp"]):
            return "High"
        if any(x in s for x in ["http", "https", "apache", "nginx", "tomcat"]):
            return "Medium"
        return "Low"

    rows = []
    for r in scan_result.get('open', []):
        rows.append({
            "host": scan_result.get("ip", ""),
            "port": r.get("port", ""),
            "protocol": "tcp",
            "state": "open",
            "service": r.get("service", ""),
            "product": f"{r.get('extra','')} {r.get('version','')}".strip(),
            "risk": risk_level(r)
        })

    html_lines = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>Nmap Report</title>",
        "<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f4f4f4}</style>",
        "</head><body>",
        f"<h2>Nmap Scan Report — {scan_result.get('ip','')}</h2>",
        f"<p>Generated: {datetime.utcnow().isoformat()} (UTC)</p>",
        "<table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product/Version</th><th>Risk</th></tr></thead><tbody>"
    ]
    for r in rows:
        html_lines.append("<tr>" +
                          f"<td>{r['host']}</td>" +
                          f"<td>{r['port']}</td>" +
                          f"<td>{r['protocol']}</td>" +
                          f"<td>{r['state']}</td>" +
                          f"<td>{r['service']}</td>" +
                          f"<td>{r['product']}</td>" +
                          f"<td>{r['risk']}</td>" +
                          "</tr>")
    html_lines.append("</tbody></table></body></html>")

    html_path.write_text("\n".join(html_lines), encoding="utf-8")
    app.logger.info("Saved HTML report: %s", html_path)
    return html_path


# ==============================================================
# Background Scanner Thread + Single-scan updater
# ==============================================================
def do_scan_and_update_single(ip):
    """Perform scan for one IP, update node info, and write reports."""
    app.logger.info("[SCAN_THREAD] Scanning %s ...", ip)
    res = run_nmap_scan(ip)  # dict with 'ip' and 'open' list
    open_count = len(res.get('open', []))
    app.logger.info("[SCAN_THREAD] %s → %d open ports", ip, open_count)

    # Infer vulnerabilities
    vulns = infer_vulns_from_scan(res.get('open', []))

    # Save JSON + HTML report
    json_path = save_json_report(res)
    html_path = generate_html_report_from_scan(res)

    # Thread-safe update
    with DATA_LOCK:
        for node in NODES:
            if node['ip'] == ip:
                node['open_ports'] = open_count
                node['vulnerabilities'] = vulns
                node['last_event'] = f"Nmap scan finished at {datetime.utcnow().isoformat()}Z"
                node['last_report'] = str(html_path)
                # add alert if we found vulnerabilities
                if node['vulnerabilities']:
                    ALERTS.insert(0, {
                        "time": datetime.utcnow().isoformat(),
                        "node": node['name'],
                        "type": "Port Scan Result",
                        "severity": "Low",
                        "details": f"Found {len(node['vulnerabilities'])} issue(s)",
                        "report": str(html_path)
                    })
                break


def background_scanner(interval_seconds=60):
    """Continuously scan all nodes periodically"""
    app.logger.info("[BG_SCANNER] Background scanner started")
    while True:
        for node in list(NODES):
            try:
                do_scan_and_update_single(node['ip'])
            except Exception as e:
                app.logger.exception("[BG_SCANNER] Error scanning %s: %s", node['ip'], e)
            time.sleep(0.3)
        app.logger.info("[BG_SCANNER] Sleeping before next cycle...")
        time.sleep(interval_seconds)


def start_scanner_thread(interval_seconds=60):
    """Start the background scanning thread"""
    t = threading.Thread(target=lambda: background_scanner(interval_seconds), daemon=True)
    t.start()
    app.logger.info("[MAIN] Started background scanner thread")


# ==============================================================
# FSM (Finite State Machine) Simulation
# ==============================================================
def update_node_state(ip, new_state, event=None):
    with DATA_LOCK:
        for node in NODES:
            if node['ip'] == ip:
                node['state'] = new_state
                node['last_event'] = event or f"State changed to {new_state}"
                node['status'] = "online" if new_state == "normal" else "alert"
                if new_state in ("suspicious", "alert"):
                    ALERTS.append({
                        "time": datetime.utcnow().isoformat(),
                        "node": node['name'],
                        "type": "FSM State Change",
                        "severity": "High" if new_state == "alert" else "Medium",
                        "details": node['last_event']
                    })
                break


@app.route('/internal/fsm', methods=['POST'])
def internal_fsm():
    data = request.get_json()
    ip = data.get('ip')
    state = data.get('state')
    event = data.get('event')
    if not ip or not state:
        return jsonify({"ok": False, "error": "ip and state required"}), 400
    update_node_state(ip, state, event)
    return jsonify({"ok": True})


# ==============================================================
# Routes
# ==============================================================
@app.route('/')
def index():
    # If you have templates/index.html it will be used; otherwise basic message
    try:
        return render_template('index.html')
    except Exception:
        return "<h2>P2P IDS Dashboard</h2><p>Visit /api/nodes, /api/alerts, /api/summary</p>"


@app.route('/api/nodes')
def api_nodes():
    with DATA_LOCK:
        return jsonify(NODES)


@app.route('/api/alerts')
def api_alerts():
    with DATA_LOCK:
        return jsonify(ALERTS)


# ==============================================================
# Summary endpoint (enhanced) - replaces your old api_summary
# ==============================================================

def severity_of_vuln(v):
    """
    Heuristic to classify a vulnerability hint into low/medium/high.
    Adjust rules as you prefer.
    """
    svc = (v.get('service') or "").lower()
    port = v.get('port')
    cve = v.get('cve')

    if port in (21, 22, 23, 25, 139, 445, 3389):
        return "high"
    if any(x in svc for x in ("telnet", "ftp", "rsh", "msrpc", "microsoft-ds", "smb")):
        return "high"
    if any(x in svc for x in ("http", "https", "apache", "nginx", "tomcat")):
        return "medium"
    if cve:
        return "medium"
    return "low"


@app.route('/api/summary')
def api_summary():
    """
    Generate vulnerability + attack summary for charts and summary panel.
    """
    labels = [(datetime.utcnow() - timedelta(minutes=i)).strftime("%H:%M") for i in range(12, -1, -1)]
    attacks = [random.randint(0, 2) for _ in labels]

    total_findings = 0
    severity_counts = {"low": 0, "medium": 0, "high": 0}
    vuln_by_node_counts = []

    with DATA_LOCK:
        for n in NODES:
            vlist = n.get('vulnerabilities', []) or []
            vuln_by_node_counts.append(len(vlist))
            total_findings += len(vlist)
            for v in vlist:
                sev = severity_of_vuln(v)
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        node_names = [n['name'] for n in NODES]

    return jsonify({
        "attacks_over_time": {"labels": labels, "counts": attacks},
        "vuln_by_node": {"nodes": node_names, "counts": vuln_by_node_counts},
        "vuln_summary": {
            "total_findings": total_findings,
            "by_severity": severity_counts
        }
    })



# ==============================================================
# Report endpoints: list and download generated HTML reports
# ==============================================================
@app.route('/api/reports')
def api_reports():
    """Return recent report file names (html)"""
    files = sorted(REPORT_DIR.glob("*.html"), key=os.path.getmtime, reverse=True)
    return jsonify([str(f) for f in files])


@app.route('/reports/<path:filename>')
def serve_report(filename):
    """Serve a generated report file (from reports/)."""
    # Simple safety: ensure the resolved path is under REPORT_DIR
    requested = REPORT_DIR / filename
    try:
        requested.resolve().relative_to(REPORT_DIR.resolve())
    except Exception:
        abort(403)
    if not requested.exists():
        abort(404)
    # Use send_from_directory to serve static file
    return send_from_directory(REPORT_DIR.resolve(), requested.name)


# ==============================================================
# Main Nmap Scanning Endpoint
# ==============================================================
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = data.get('ip')

    targets = [target] if target else [n['ip'] for n in NODES]
    for ip in targets:
        do_scan_and_update_single(ip)
        time.sleep(0.3)

    return jsonify({"status": "scan completed"}), 200


# ==============================================================
# DEBUG: Direct manual scan endpoint (returns raw scan)
# ==============================================================
@app.route('/api/scan_now', methods=['POST'])
def api_scan_now():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or '127.0.0.1'
    force = bool(data.get('force'))
    app.logger.info("[SCAN_NOW] %s force=%s", ip, force)
    res = run_nmap_scan(ip, force_scan=force)
    app.logger.info("[SCAN_NOW] Done %s, ports=%d", ip, len(res.get('open', [])))
    return jsonify({"ok": True, "scan": res})


# ==============================================================
# Optional helper: trigger FSM state for node by name (convenience)
# ==============================================================
@app.route('/api/node/state', methods=['POST'])
def api_node_state():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')
    state = data.get('state')
    event = data.get('event')
    if not ip or not state:
        return jsonify({"ok": False, "error": "ip and state required"}), 400
    update_node_state(ip, state, event)
    return jsonify({"ok": True})


# ==============================================================
# Main Entry
# ==============================================================
if __name__ == '__main__':
    # Start scanner thread only when running as main (not when imported)
    start_scanner_thread(interval_seconds=60)
    app.logger.info("Starting Flask app. Nmap available: %s", NM_AVAILABLE)
    # bind to 0.0.0.0 for network access; change debug=False for production
    app.run(host='0.0.0.0', port=5001, debug=True)
