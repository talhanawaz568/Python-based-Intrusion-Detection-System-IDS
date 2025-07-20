
import os
import json
from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import init, Fore
from email_alert import send_alert_email  # 📧 Import your email sender

# Initialize colorama
init(autoreset=True)

# File paths
LOG_FILE = "logs/network_log.txt"
RULE_FILE = "rules.txt"
ALERT_FILE = "alerts/signature_alerts.txt"

# Ensure alerts directory exists
os.makedirs("alerts", exist_ok=True)

# Load detection rules
def load_rules():
    rules = []
    with open(RULE_FILE, "r") as f:
        for line in f:
            if line.strip() == "" or line.startswith("#"):
                continue
            parts = line.strip().split(" | ")
            if len(parts) == 3:
                condition, desc, severity = parts
                rules.append({
                    "condition": condition.strip(),
                    "description": desc.strip(),
                    "severity": severity.strip()
                })
    return rules

# Match a packet with all rules
def match_packet(packet, rules):
    alerts = []

    for rule in rules:
        condition = rule["condition"]
        desc = rule["description"]
        severity = rule["severity"]

        if condition.startswith("TCP_PORT="):
            port = int(condition.split("=")[1])
            if packet.get("protocol") == "TCP" and int(packet.get("dst_port", 0)) == port:
                alerts.append((desc, severity))

        elif condition.startswith("DST_PORT="):
            port = int(condition.split("=")[1])
            if int(packet.get("dst_port", 0)) == port:
                alerts.append((desc, severity))

        elif condition.startswith("DST_IP="):
            ip = condition.split("=")[1]
            if packet.get("dst_ip") == ip:
                alerts.append((desc, severity))

    return alerts

# Color-coded terminal alert
def print_colored(desc, severity):
    if severity.lower() == "high":
        print(Fore.RED + f"[HIGH] {desc}")
    elif severity.lower() == "medium":
        print(Fore.YELLOW + f"[MEDIUM] {desc}")
    elif severity.lower() == "low":
        print(Fore.GREEN + f"[LOW] {desc}")
    else:
        print(f"[UNKNOWN] {desc}")

# File system event handler
class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.rules = load_rules()
        self.last_size = 0

    def on_modified(self, event):
        if event.src_path.endswith("network_log.txt"):
            current_size = os.path.getsize(LOG_FILE)
            if current_size < self.last_size:
                self.last_size = 0  # File was cleared
            with open(LOG_FILE, "r") as f:
                f.seek(self.last_size)
                new_lines = f.readlines()
                self.last_size = f.tell()

            for line in new_lines:
                try:
                    packet = json.loads(line.strip())
                    matches = match_packet(packet, self.rules)
                    for desc, severity in matches:
                        print_colored(desc, severity)

                        alert = {
                            "timestamp": packet.get("timestamp", ""),
                            "src_ip": packet.get("src_ip", ""),
                            "dst_ip": packet.get("dst_ip", ""),
                            "protocol": packet.get("protocol", ""),
                            "description": desc,
                            "severity": severity
                        }

                        # Save to alert log
                        with open(ALERT_FILE, "a") as alert_file:
                            alert_file.write(json.dumps(alert) + "\n")

                        # 📧 Send email for ALL alerts (or filter if needed)
                        send_alert_email(alert)

                except json.JSONDecodeError:
                    continue

# Run the monitor
if __name__ == "__main__":
    print("🔍 Watching network_log.txt for real-time alerts...\n")
    observer = Observer()
    event_handler = LogHandler()
    observer.schedule(event_handler, path="logs/", recursive=False)
    observer.start()

    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopped monitoring.")
    observer.join()
