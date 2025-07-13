import json
import re
import os
from colorama import Fore, Style, init

init(autoreset=True)

log_file = "logs/network_log.txt"
rule_file = "rules.txt"
alert_file = "alerts/signature_alerts.txt"

os.makedirs("alerts", exist_ok=True)

def load_rules():
    rules = []
    with open(rule_file, "r") as file:
        for line in file:
            if line.strip() == "" or line.startswith("#"):
                continue
            parts = line.strip().split(" | ")
            if len(parts) == 3:
                condition, description, severity = parts
                rules.append({
                    "condition": condition.strip(),
                    "description": description.strip(),
                    "severity": severity.strip()
                })
    return rules

def match_rules(packet, rules):
    matches = []

    for rule in rules:
        condition = rule["condition"]
        desc = rule["description"]
        severity = rule["severity"]

        if condition.startswith("TCP_PORT="):
            port = int(condition.split("=")[1])
            if packet.get("protocol") == "TCP" and int(packet.get("dst_port", 0)) == port:
                matches.append((desc, severity))

        elif condition.startswith("DST_PORT="):
            port = int(condition.split("=")[1])
            if int(packet.get("dst_port", 0)) == port:
                matches.append((desc, severity))

        elif condition.startswith("DST_IP="):
            ip = condition.split("=")[1]
            if packet.get("dst_ip") == ip:
                matches.append((desc, severity))

    return matches

def detect_icmp_flood(packets, threshold=100):
    icmp_count = sum(1 for pkt in packets if pkt.get("protocol") == "ICMP")
    if icmp_count > threshold:
        return [("Possible ICMP Flood", "Medium")]
    return []

def print_colored_alert(description, severity):
    if severity.lower() == "high":
        print(Fore.RED + f"[HIGH] {description}")
    elif severity.lower() == "medium":
        print(Fore.YELLOW + f"[MEDIUM] {description}")
    elif severity.lower() == "low":
        print(Fore.GREEN + f"[LOW] {description}")
    else:
        print(f"[UNKNOWN] {description}")

def run_rule_engine():
    rules = load_rules()

    if not os.path.exists(log_file):
        print("No log file found. Run packet_sniffer.py first.")
        return

    with open(log_file, "r") as f:
        packets = [json.loads(line) for line in f if line.strip()]

    alerts = []

    for packet in packets:
        matches = match_rules(packet, rules)
        for desc, severity in matches:
            alert = {
                "timestamp": packet["timestamp"],
                "src_ip": packet.get("src_ip", ""),
                "dst_ip": packet.get("dst_ip", ""),
                "protocol": packet.get("protocol", ""),
                "description": desc,
                "severity": severity
            }
            alerts.append(alert)
            print_colored_alert(desc, severity)

    icmp_alerts = detect_icmp_flood(packets)
    for desc, severity in icmp_alerts:
        alert = {
            "timestamp": packets[-1]["timestamp"],
            "src_ip": "-",
            "dst_ip": "-",
            "protocol": "ICMP",
            "description": desc,
            "severity": severity
        }
        alerts.append(alert)
        print_colored_alert(desc, severity)

    with open(alert_file, "w") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")

    print(f"\n {len(alerts)} alerts written to {alert_file}")

if __name__ == "__main__":
    run_rule_engine()


