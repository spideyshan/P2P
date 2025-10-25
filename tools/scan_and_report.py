#!/usr/bin/env python3
"""
scan_and_report.py
Run nmap and parse the XML output into a simple JSON report.
Usage:
  python3 scan_and_report.py --target 192.168.1.10 --top 100
"""

import os
import subprocess
import xml.etree.ElementTree as ET
import datetime
import argparse
import json
from pathlib import Path

def run_nmap(target, output_dir="reports", top_ports=1000):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestr = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    base = Path(output_dir) / f"nmap_{safe_target}_{timestr}"
    xml_file = str(base) + ".xml"
    # Use SYN scan, version detection, top ports (fast)
    cmd = ["nmap", "-sS", "-sV", "--top-ports", str(top_ports), "-oX", xml_file, target]
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd)
    return xml_file

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    results = []
    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        addr = addr_elem.attrib.get("addr", "unknown")
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            portnum = int(p.attrib.get("portid", 0))
            protocol = p.attrib.get("protocol","")
            state_elem = p.find("state")
            state = state_elem.attrib.get("state","unknown") if state_elem is not None else "unknown"
            service_elem = p.find("service")
            svc_name = service_elem.attrib.get("name","") if service_elem is not None else ""
            svc_product = service_elem.attrib.get("product","") if service_elem is not None else ""
            svc_version = service_elem.attrib.get("version","") if service_elem is not None else ""
            results.append({
                "host": addr,
                "port": portnum,
                "protocol": protocol,
                "state": state,
                "service": svc_name,
                "product": svc_product,
                "version": svc_version
            })
    return results

def save_json_report(results, xml_file):
    json_path = xml_file.replace(".xml", ".json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    return json_path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", required=True, help="IP or host to scan (you must own/permit scanning)")
    parser.add_argument("--top", type=int, default=100, help="Use --top-ports N (default 100)")
    parser.add_argument("--outdir", "-o", default="reports", help="output directory")
    args = parser.parse_args()

    xml = run_nmap(args.target, output_dir=args.outdir, top_ports=args.top)
    results = parse_nmap_xml(xml)
    j = save_json_report(results, xml)
    print("JSON report saved to:", j)

if __name__ == "__main__":
    main()
