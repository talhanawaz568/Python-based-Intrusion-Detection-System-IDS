### Python-Based Intrusion Detection System (IDS)

✅ Week 1 – Packet Sniffer and Logging Engine
## What I did:

Built a Python-based network packet sniffer using scapy and socket

Extracted key packet details: source IP, destination IP, protocol, ports, and timestamps

Logged structured JSON output to network_log.txt for further analysis

📁 Code Location:

packet_sniffer.py

Output logs in: logs/network_log.txt

✅ Week 2 – Signature-based Detection Engine
## What I did:

Created a custom rules.txt file to define suspicious behaviors

Wrote an alert generation engine that:

Parses logs line-by-line

Applies each rule (e.g., SSH port detection, ICMP flood)

Generates real-time alerts with timestamps and severity levels

📁 Code Location:

signature_engine.py

rules.txt

Alerts stored in: alerts/signature_alerts.txt

✅ Week 3 – Live Log Monitor & Email Alerts
## What I did:

Developed a Python-based live monitor that:

Reads logs in real-time

Matches against rules

Displays alerts on the terminal with color-coded severity

Integrated email alerting using SMTP and Gmail App Passwords

📁 Code Location:

live_monitor.py

send_email.py (optional: for high/medium severity alerts)

📬 Bonus: Sends real alerts via email (ICMP Flood, Reverse Shell attempts, etc.)

✅ Week 4 – GUI Dashboard & Archiving System
## What I did:

Designed a custom GUI dashboard using tkinter

Visualized alerts using pie and bar charts via matplotlib

Added Start/Stop buttons to control the app

Built a log archiver that:

Moves old logs to logs/archived

Clears network_log.txt and signature_alerts.txt weekly

📁 Code Location:

dashboard_gui.py

archive_logs.py

Weekly Report: report_weekly.html
