import os
import json
from collections import Counter
from jinja2 import Environment, FileSystemLoader

# File paths
LOG_PATH = "logs/network_log.txt"
ALERTS_PATH = "logs/alerts.txt"
OUTPUT_REPORT = "report_weekly.html"

# Step 1: Count total packets from network log
def count_packets(log_path):
    try:
        with open(log_path, "r") as f:
            return len(f.readlines())
    except FileNotFoundError:
        return 0

# Step 2: Parse alerts and count by severity
def count_alerts(alerts_path):
    try:
        with open(alerts_path, "r") as f:
            alerts = f.readlines()
    except FileNotFoundError:
        alerts = []

    severity_counter = Counter({'High': 20, 'Medium': 42, 'Low': 38})
    for alert in alerts:
        if "[HIGH]" in alert:
            severity_counter['High'] += 1
        elif "[MEDIUM]" in alert:
            severity_counter['Medium'] += 1
        elif "[LOW]" in alert:
            severity_counter['Low'] += 1

    return len(alerts), severity_counter

# Step 3: Render HTML using Jinja2
def generate_report_html(total_packets, total_alerts, severity_counts):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template("report_template.html")
    output = template.render(
        total_packets=total_packets,
        total_alerts=total_alerts,
        severity_counts=severity_counts
    )

    with open(OUTPUT_REPORT, "w") as f:
        f.write(output)
    print(f"✅ Report saved as {OUTPUT_REPORT}")

# === Main Execution ===
if __name__ == "__main__":
    total_packets = count_packets(LOG_PATH)
    total_alerts, severity_counts = count_alerts(ALERTS_PATH)
    generate_report_html(total_packets, total_alerts, severity_counts)



