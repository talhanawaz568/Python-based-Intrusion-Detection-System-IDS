import tkinter as tk
from tkinter import ttk
import json
import threading
import time
from collections import Counter, deque
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# === File Paths ===
LOG_FILE = "logs/network_log.txt"
ALERT_FILE = "logs/alerts.txt"
running = True

# === Helper Functions ===
def read_packet_count():
    try:
        with open(LOG_FILE, "r") as f:
            return len(f.readlines())
    except:
        return 0

def read_alerts():
    severity_counter = Counter({'High': 20, 'Medium': 0, 'Low': 38})
    recent_alerts.clear()
    try:
        with open(ALERT_FILE, "r") as f:
            lines = f.readlines()
            for line in lines[-5:]:  # Last 5 alerts
                try:
                    alert = json.loads(line.strip())
                    severity = alert.get("severity", "Unknown")
                    message = alert.get("alert", "")
                    timestamp = alert.get("timestamp", "")
                    src = alert.get("src_ip", "")
                    dst = alert.get("dst_ip", "")
                    recent_alerts.append((timestamp, severity, message, src, dst))
                    severity_counter[severity] += 1
                except:
                    continue
    except:
        pass
    return sum(severity_counter.values()), severity_counter

def update_dashboard():
    while True:
        if running:
            total_packets = read_packet_count()
            total_alerts, severity_counts = read_alerts()

            packet_var.set(f"{total_packets}")
            alert_var.set(f"{total_alerts}")
            high_var.set(f"{severity_counts['High']}")
            medium_var.set(f"{severity_counts['Medium']}")
            low_var.set(f"{severity_counts['Low']}")

            update_pie(severity_counts)
            update_bar(severity_counts)
            update_table()
        time.sleep(2)

# === Visualization Functions ===
def update_pie(severity_counts):
    pie_ax.clear()
    labels = []
    sizes = []
    colors = {'High': 'red', 'Medium': 'orange', 'Low': 'green'}
    for level in ['High', 'Medium', 'Low']:
        count = severity_counts[level]
        if count > 0:
            labels.append(level)
            sizes.append(count)
    if sizes:
        pie_ax.pie(sizes, labels=labels, colors=[colors[l] for l in labels], autopct='%1.1f%%', startangle=140)
    else:
        pie_ax.text(0.5, 0.5, "No Alerts", ha='center', va='center')
    pie_ax.set_title("Severity Distribution")
    pie_canvas.draw()

def update_bar(severity_counts):
    bar_ax.clear()
    levels = ['High', 'Medium', 'Low']
    counts = [severity_counts[l] for l in levels]
    bar_ax.bar(levels, counts, color=['red', 'orange', 'green'])
    bar_ax.set_title("Alert Severity Count")
    bar_ax.set_ylabel("Count")
    bar_canvas.draw()

def update_table():
    for row in table.get_children():
        table.delete(row)
    for alert in list(recent_alerts):
        table.insert('', 'end', values=alert)

# === Start/Stop Buttons ===
def start_monitoring():
    global running
    running = True

def stop_monitoring():
    global running
    running = False

# === GUI Setup ===
app = tk.Tk()
app.title("Pro IDS Dashboard")
app.geometry("1000x700")
app.configure(bg="white")

# === Variables ===
packet_var = tk.StringVar()
alert_var = tk.StringVar()
high_var = tk.StringVar()
medium_var = tk.StringVar()
low_var = tk.StringVar()
recent_alerts = deque(maxlen=5)

# === HEADER ===
ttk.Label(app, text="Advanced IDS GUI Dashboard", font=("Segoe UI", 18, "bold")).pack(pady=10)

# === Stats Frame ===
stats_frame = ttk.Frame(app)
stats_frame.pack(pady=5)

def stat_label(parent, label, var):
    ttk.Label(parent, text=label, font=("Segoe UI", 12)).pack()
    ttk.Label(parent, textvariable=var, font=("Segoe UI", 14, "bold"), foreground="blue").pack()

for i, (text, var) in enumerate([
    ("Total Packets", packet_var),
    ("Total Alerts", alert_var),
    ("High", high_var),
    ("Medium", medium_var),
    ("Low", low_var)
]):
    frame = ttk.Frame(stats_frame)
    frame.grid(row=0, column=i, padx=15)
    stat_label(frame, text, var)

# === Graph Frame ===
graph_frame = ttk.Frame(app)
graph_frame.pack()

fig1 = plt.Figure(figsize=(4.2, 3), dpi=100)
pie_ax = fig1.add_subplot(111)
pie_canvas = FigureCanvasTkAgg(fig1, master=graph_frame)
pie_canvas.get_tk_widget().grid(row=0, column=0, padx=20)

fig2 = plt.Figure(figsize=(4.2, 3), dpi=100)
bar_ax = fig2.add_subplot(111)
bar_canvas = FigureCanvasTkAgg(fig2, master=graph_frame)
bar_canvas.get_tk_widget().grid(row=0, column=1, padx=20)

# === Table for Last Alerts ===
ttk.Label(app, text="Recent Alerts", font=("Segoe UI", 14, "bold")).pack(pady=10)
table_frame = ttk.Frame(app)
table_frame.pack()

columns = ("Time", "Severity", "Alert", "Source", "Destination")
table = ttk.Treeview(table_frame, columns=columns, show='headings', height=5)
for col in columns:
    table.heading(col, text=col)
    table.column(col, width=180 if col == "Alert" else 110)
table.pack()

# === Buttons ===
button_frame = ttk.Frame(app)
button_frame.pack(pady=15)

ttk.Button(button_frame, text="▶ Start Monitoring", command=start_monitoring).grid(row=0, column=0, padx=15)
ttk.Button(button_frame, text="■ Stop Monitoring", command=stop_monitoring).grid(row=0, column=1, padx=15)

# === Thread ===
threading.Thread(target=update_dashboard, daemon=True).start()

app.mainloop()

