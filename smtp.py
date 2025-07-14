# using SendGrid's Python Library
# https://github.com/sendgrid/sendgrid-python
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import smtplib
from email.mime.text import MIMEText

# Email content
sender_email = "thapasushma3021@gmail.com"
receiver_email = "shresthasuprim0@gmail.com"
subject = "Sending with Gmail SMTP is Fun"
body = "<strong>and easy to do anywhere, even with Python</strong>"

# Create MIMEText object
msg = MIMEText(body, "html")
msg["Subject"] = subject
msg["From"] = sender_email
msg["To"] = receiver_email

# Gmail SMTP server configuration
smtp_server = "smtp.gmail.com"
smtp_port = 587
app_password = "fsxt kgol zhkt zgjr"  # Use your Gmail App Password

try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure the connection
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Email sent successfully!")
except Exception as e:
    print(f"Error: {e}")