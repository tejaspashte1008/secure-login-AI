"""
Email Alert Service Module
===========================
Handles sending SMTP security alerts when suspicious theft or brute-force
login attempts are detected by the application firewall.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from config import Config

logger = logging.getLogger("SecureLoginAI.EmailService")

def send_security_alert_email(recipient_email: str, recipient_name: str, failed_count: int,
                              ip_address: str, user_agent: str = "Unknown") -> bool:
    """
    Sends a security alert email via SMTP.
    Safely catches exceptions and logs status without terminating the application.
    """
    # 1. Check if SMTP credentials are configured
    if not Config.SMTP_USERNAME or not Config.SMTP_PASSWORD:
        logger.warning(
            "SMTP credentials not fully configured in .env. Skipping real email dispatch. "
            f"(Target: {recipient_email}, Failed attempts: {failed_count})"
        )
        return False

    try:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # 2. Compose Email Content
        subject = "SECURITY ALERT: Suspicious Login Attempts Detected on SecureLogin AI"
        
        # Plain text fallback
        text_body = f"""
SECURITY ALERT - SecureLogin AI
--------------------------------------------------
Dear {recipient_name},

We detected {failed_count} consecutive unsuccessful login attempts on your account.
As a security precaution, your account has been temporarily LOCKED for {Config.LOCKOUT_DURATION_MINUTES} minutes.

Incident Details:
- Timestamp: {now_str}
- Consecutive Failed Attempts: {failed_count}
- Originating IP Address: {ip_address}
- Device / User Agent: {user_agent}

If this was YOU, please wait {Config.LOCKOUT_DURATION_MINUTES} minutes before attempting to log in again.
If this was NOT YOU, someone may be attempting unauthorized access to your account. We recommend reviewing your security practices.

Stay safe,
SecureLogin AI Security Operations Center (SOC)
"""

        # HTML formatted email
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
  <style>
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }}
    .card {{ background-color: #1e293b; border-radius: 8px; max-width: 600px; margin: 0 auto; padding: 25px; border-left: 5px solid #ef4444; }}
    .badge {{ background-color: #ef4444; color: #ffffff; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
    .details {{ background-color: #0f172a; border-radius: 6px; padding: 15px; margin: 15px 0; border: 1px solid #334155; }}
    .details table {{ width: 100%; border-collapse: collapse; }}
    .details td {{ padding: 6px; font-size: 14px; color: #cbd5e1; }}
    .details td.label {{ font-weight: bold; width: 35%; color: #94a3b8; }}
    .footer {{ font-size: 12px; color: #64748b; margin-top: 20px; text-align: center; }}
  </style>
</head>
<body>
  <div class="card">
    <div style="margin-bottom: 15px;">
      <span class="badge">CRITICAL SECURITY ALERT</span>
    </div>
    <h2 style="color: #f8fafc; margin-top: 0;">Suspicious Login Theft Activity Detected</h2>
    <p>Dear <strong>{recipient_name}</strong>,</p>
    <p>Our intelligent Application Security Firewall detected <strong>{failed_count} consecutive failed login attempts</strong> targeting your account. In accordance with safety policies, your account has been <strong>temporarily locked for {Config.LOCKOUT_DURATION_MINUTES} minutes</strong>.</p>
    
    <div class="details">
      <table>
        <tr>
          <td class="label">Incident Timestamp</td>
          <td>{now_str}</td>
        </tr>
        <tr>
          <td class="label">Failed Attempts</td>
          <td><span style="color: #ef4444; font-weight: bold;">{failed_count} attempts</span></td>
        </tr>
        <tr>
          <td class="label">Originating IP</td>
          <td><code>{ip_address}</code></td>
        </tr>
        <tr>
          <td class="label">Client User-Agent</td>
          <td><small>{user_agent}</small></td>
        </tr>
        <tr>
          <td class="label">Enforced Action</td>
          <td>Temporary Lockout ({Config.LOCKOUT_DURATION_MINUTES} mins)</td>
        </tr>
      </table>
    </div>

    <p style="font-size: 14px; line-height: 1.5;">
      <strong>Action Required:</strong><br>
      • If this was you, wait for the lockout window to expire before retrying.<br>
      • If this was NOT you, an unauthorized actor may have attempted to crack your password. No passwords or plaintext hashes are ever compromised.
    </p>

    <div class="footer">
      This is an automated security advisory from <strong>SecureLogin AI</strong>.<br>
      Protecting user credentials with AI & Application Firewall.
    </div>
  </div>
</body>
</html>
"""

        # 3. Create MIME Message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = Config.ALERT_SENDER_EMAIL or Config.SMTP_USERNAME
        message["To"] = recipient_email
        message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))

        # 4. Connect to SMTP Server
        if Config.SMTP_USE_TLS:
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=10)

        server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
        server.sendmail(Config.ALERT_SENDER_EMAIL, recipient_email, message.as_string())
        server.quit()

        logger.info(f"Security alert email dispatched successfully to {recipient_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send security alert email to {recipient_email}: {str(e)}")
        return False
