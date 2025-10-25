# tools

Scripts:
- scan_and_report.py : run nmap and produce XML + JSON
- generate_html.py : convert JSON to a simple HTML report
- scan_automata.py : helper DFA model for sequences

Requirements:
- nmap (system package)
- Python 3.8+

Example:
  python3 tools/scan_and_report.py --target 127.0.0.1 --top 100
  python3 tools/generate_html.py reports/nmap_127.0.0.1_2025...json -o reports/report.html

NOTE: Only scan hosts you own or have permission to scan.
