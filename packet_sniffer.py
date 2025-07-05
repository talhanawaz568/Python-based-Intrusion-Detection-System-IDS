from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import json
import csv
import os

log_file = "logs/network_log.txt"
suspicious_log = "logs/suspicious.txt"
csv_log_file = "logs/network_log.csv"

os.makedirs("logs", exist_ok=True)

if not os.path.exists(csv_log_file):
    with open(csv_log_file, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port"])
        writer.writeheader()

def is_suspicious(packet):
    if ICMP in packet:
        return True
    if TCP in packet and packet[TCP].flags == "S":
        return True
    return False

def process_packet(packet):
    if IP in packet:
        log_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto
        }

        if TCP in packet:
            log_data["src_port"] = packet[TCP].sport
            log_data["dst_port"] = packet[TCP].dport
            log_data["protocol"] = "TCP"
        elif UDP in packet:
            log_data["src_port"] = packet[UDP].sport
            log_data["dst_port"] = packet[UDP].dport
            log_data["protocol"] = "UDP"
        elif ICMP in packet:
            log_data["protocol"] = "ICMP"

        with open(log_file, "a") as f:
            f.write(json.dumps(log_data) + "\n")

        with open(csv_log_file, "a", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port"])
            writer.writerow({
                "timestamp": log_data["timestamp"],
                "src_ip": log_data["src_ip"],
                "dst_ip": log_data["dst_ip"],
                "protocol": log_data["protocol"],
                "src_port": log_data.get("src_port", ""),
                "dst_port": log_data.get("dst_port", "")
            })

        if is_suspicious(packet):
            with open(suspicious_log, "a") as f:
                f.write(json.dumps(log_data) + "\n")

print("Sniffing started... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)

