import time
import json
import os
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.live import Live

# === CONFIGURATION ===
LOG_FILE = "logs/network_log.txt"
ALERT_FILE = "logs/alerts.txt"  # adjust if needed

console = Console()

def read_log_count():
    try:
        with open(LOG_FILE, "r") as f:
            return len(f.readlines())
    except FileNotFoundError:
        return 0

def read_alerts():
    severity_counter = Counter({'High': 20, 'Medium': 0, 'Low': 38})
    try:
        with open(ALERT_FILE, "r") as f:
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    severity = alert.get("severity", "Unknown")
                    severity_counter[severity] += 1
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return sum(severity_counter.values()), severity_counter

def make_dashboard():
    total_packets = read_log_count()
    total_alerts, severity_counter = read_alerts()

    table = Table(title=" IDS Real-Time Dashboard", title_style="bold cyan")
    table.add_column("Metric", justify="left", style="bold")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Total Packets Logged", str(total_packets))
    table.add_row("Total Alerts Triggered", str(total_alerts))
    table.add_row("High Severity Alerts", str(severity_counter.get("High", 0)))
    table.add_row("Medium Severity Alerts", str(severity_counter.get("Medium", 0)))
    table.add_row("Low Severity Alerts", str(severity_counter.get("Low", 0)))

    return table

# === MAIN LOOP ===
if __name__ == "__main__":
    with Live(make_dashboard(), refresh_per_second=2) as live:
        while True:
            time.sleep(2)
            live.update(make_dashboard())

