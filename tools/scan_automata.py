"""
scan_automata.py
Simple DFA to model scanning sequence events.
This is a light helper you can import or run tests with.
"""

class ScanDFA:
    def __init__(self):
        self.state = "START"
        self.transitions = {
            ("START","host_discovery"):"HOST_DISCOVERY",
            ("HOST_DISCOVERY","port_scan"):"PORT_SCAN",
            ("PORT_SCAN","service_probe"):"SERVICE_PROBE",
            ("SERVICE_PROBE","banner_grab"):"BANNER_GRAB",
            ("BANNER_GRAB","finish"):"END",
            ("SERVICE_PROBE","service_probe"):"SERVICE_PROBE",
            ("PORT_SCAN","port_scan"):"PORT_SCAN"
        }

    def step(self, event):
        key = (self.state, event)
        if key in self.transitions:
            self.state = self.transitions[key]
            return True
        else:
            self.state = "ANOMALY"
            return False

    def is_anomaly(self):
        return self.state == "ANOMALY"

if __name__ == "__main__":
    d = ScanDFA()
    events = ["host_discovery","port_scan","service_probe","banner_grab","finish"]
    for e in events:
        ok = d.step(e)
        print(e, "->", d.state, "ok:", ok)
