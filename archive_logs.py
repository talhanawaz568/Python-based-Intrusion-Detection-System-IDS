import os
import shutil
from datetime import datetime

# === File Paths ===
network_log = "logs/network_log.txt"
alerts_log = "alerts/signature_alerts.txt"
archive_dir = "logs/archived"

# === Ensure Archive Directory Exists ===
os.makedirs(archive_dir, exist_ok=True)

def archive_log_file(file_path, log_type):
    if not os.path.exists(file_path):
        print(f"[!] {log_type} log file not found: {file_path}")
        return
    
    today = datetime.now().strftime("%Y-%m-%d")
    filename = f"{log_type}_log_{today}.txt"
    destination = os.path.join(archive_dir, filename)

    # Move and rename
    shutil.copy(file_path, destination)
    print(f"[✓] {log_type.capitalize()} log archived to {destination}")

    # Clear original log
    open(file_path, 'w').close()
    print(f"[✓] {log_type.capitalize()} log cleared")

# === Run Archiving ===
archive_log_file(network_log, "network")
archive_log_file(alerts_log, "alerts")


