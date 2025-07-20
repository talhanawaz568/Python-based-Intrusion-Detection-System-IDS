import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ✅ Change sender email and app password
sender_email = "alnafi789@gmail.com"
sender_password = "gmce polr qsee fsxb"  # Replace with your Gmail App Password
receiver_email = "alnafi789@gmail.com"  # or any other recipient

def send_alert_email(alert_data):
    subject = f"🚨 IDS Alert: {alert_data['description']} ({alert_data['severity']})"
    body = f"""
    Alert Details:

    Timestamp: {alert_data['timestamp']}
    Source IP: {alert_data['src_ip']}
    Destination IP: {alert_data['dst_ip']}
    Protocol: {alert_data['protocol']}
    Description: {alert_data['description']}
    Severity: {alert_data['severity']}
    """

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
            print("📧 Email alert sent successfully.")
    except Exception as e:
        print("❌ Failed to send email:", e)


