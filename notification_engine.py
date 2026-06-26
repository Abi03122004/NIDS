# controller/notification_engine.py
# Engine for dispatching alerts to Email and Telegram with alert throttling

import os
import json
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "alert_config.json")
COOLDOWN_SECONDS = 60.0

# In-memory store to track the last sent timestamp for each alert type to prevent alert spam
last_sent_timestamps: Dict[str, float] = {}

def load_config() -> Dict[str, Any]:
    """Loads alert configurations from the config file."""
    if not os.path.exists(CONFIG_PATH):
        # Return disabled template if config doesn't exist
        return {
            "email": {"smtp_server": "smtp.gmail.com", "smtp_port": 587, "sender_email": "", "sender_password": "", "recipient_email": "", "enabled": False},
            "telegram": {"bot_token": "", "chat_id": "", "enabled": False}
        }
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_config(config: Dict[str, Any]):
    """Saves alert configurations to the config file."""
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

def send_telegram_message(token: str, chat_id: str, message: str) -> bool:
    """Sends a Telegram markdown message using the Telegram Bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        r = requests.post(url, json=payload, timeout=5.0)
        return r.status_code == 200
    except Exception:
        return False

def send_email_message(email_cfg: Dict[str, Any], subject: str, html_body: str) -> bool:
    """Sends a secure HTML email using smtplib."""
    server_addr = email_cfg.get("smtp_server", "")
    port = int(email_cfg.get("smtp_port", 587))
    sender = email_cfg.get("sender_email", "")
    password = email_cfg.get("sender_password", "")
    recipient = email_cfg.get("recipient_email", "")
    
    if not all([server_addr, sender, password, recipient]):
        return False

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))
    
    try:
        # Check port for appropriate SMTP connection mode
        if port == 465:
            server = smtplib.SMTP_SSL(server_addr, port, timeout=5.0)
        else:
            server = smtplib.SMTP(server_addr, port, timeout=5.0)
            server.starttls()
            
        server.login(sender, password)
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()
        return True
    except Exception:
        return False

def dispatch_alert(alert_type: str, severity: str, message: str) -> Dict[str, Any]:
    """
    Evaluates configurations and dispatches alerts to enabled channels.
    Enforces a 60-second cooldown per alert_type to prevent notifications spam.
    """
    current_time = time.time()
    last_sent = last_sent_timestamps.get(alert_type, 0.0)
    
    # Throttling Check
    if current_time - last_sent < COOLDOWN_SECONDS:
        return {"status": "throttled", "cooldown_remaining": int(COOLDOWN_SECONDS - (current_time - last_sent))}
        
    config = load_config()
    timestamp_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    telegram_success = None
    email_success = None
    
    # 1. Dispatch Telegram Alert
    tg_cfg = config.get("telegram", {})
    if tg_cfg.get("enabled") and tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
        # Format Telegram Alert in markdown
        tg_message = (
            f"⚠️ *[IDS SECURITY ALERT]*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🚨 *Severity:* `{severity.upper()}`\n"
            f"🔍 *Type:* `{alert_type}`\n"
            f"📅 *Timestamp:* `{timestamp_str} UTC`\n\n"
            f"💬 *Details:* {message}"
        )
        telegram_success = send_telegram_message(tg_cfg["bot_token"], tg_cfg["chat_id"], tg_message)

    # 2. Dispatch Email Alert
    em_cfg = config.get("email", {})
    if em_cfg.get("enabled"):
        color = "#c62828" if severity == "CRITICAL" else ("#e65100" if severity == "HIGH" else "#f57f17")
        subject = f"⚠️ [IDS ALERT - {severity.upper()}] {alert_type} Triggered"
        
        email_html = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background-color: #f5f5f5; padding: 20px; margin: 0;">
            <div style="max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);">
                <div style="background-color: {color}; color: #ffffff; padding: 24px; text-align: center;">
                    <h2 style="margin: 0; font-size: 24px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px;">{severity.upper()} Threat Alert</h2>
                </div>
                <div style="padding: 24px; color: #333333; line-height: 1.6;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; width: 30%;">Alert Rule:</td>
                            <td style="padding: 8px 0; color: #555555;">{alert_type}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Timestamp:</td>
                            <td style="padding: 8px 0; color: #555555;">{timestamp_str} UTC</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; vertical-align: top;">Description:</td>
                            <td style="padding: 8px 0; color: #555555;">{message}</td>
                        </tr>
                    </table>
                    <hr style="border: 0; border-top: 1px solid #eeeeee; margin: 24px 0;">
                    <p style="font-size: 12px; color: #888888; text-align: center; margin: 0;">
                        This is an automated alert generated by your Multi-Class Network Intrusion Detection System.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        email_success = send_email_message(em_cfg, subject, email_html)
        
    # Update last sent timestamp on successful sending (or attempt)
    last_sent_timestamps[alert_type] = current_time
    
    return {
        "status": "dispatched",
        "telegram": "sent" if telegram_success else ("failed" if telegram_success is False else "disabled"),
        "email": "sent" if email_success else ("failed" if email_success is False else "disabled")
    }
