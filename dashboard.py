# dashboard.py
# Real-time Flask + SocketIO Web SOC Portal for Network Intrusion Detection System (NIDS)

import os
import sys
import time
import secrets
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit

# Ensure local directories are in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import NIDS backend components
from database import get_statistics, get_history, get_incidents, init_db, DB_PATH
from user_model import User
from severity_engine import evaluate_threat_state
from notification_engine import load_config, save_config, send_telegram_message, send_email_message
import live_sniffer
import incident_manager

# Auto-initialize database if users table is missing
def check_db_initialized():
    import sqlite3
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users LIMIT 1")
        conn.close()
    except sqlite3.OperationalError:
        try:
            init_db()
            print("[*] SQLite database initialized successfully.")
        except Exception as e:
            print(f"[ERROR] Database initialization failed: {e}")

check_db_initialized()

# Initialize Flask and SocketIO
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(24))
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Bind SocketIO instance to background threads to allow direct broadcasts
live_sniffer.socketio_instance = socketio
incident_manager.socketio_instance = socketio

# Helper functions
def get_current_user():
    if "user_id" in session:
        return User.get(session["user_id"])
    return None

def is_admin_email(email: str) -> bool:
    if not email:
        return False
    email_clean = email.strip().lower()
    return email_clean.startswith("admin@") or email_clean == "abinesharjunan850@gmail.com"

# -------------------------------------------------------------
# HTTP Page Routes
# -------------------------------------------------------------
@app.route("/")
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    is_admin = is_admin_email(user.email)
    
    # Check if sniffer is running (heartbeat check)
    sniffer_active = live_sniffer.sniffer_instance is not None and live_sniffer.sniffer_instance.running
    is_render = "RENDER" in os.environ
    
    return render_template("index.html", user=user, is_admin=is_admin, sniffer_active=sniffer_active, is_render=is_render)

@app.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect(url_for("index"))
        
    error = None
    email_val = ""
    
    if request.method == "POST":
        email_val = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        if not email_val or not password:
            error = "Both email and password are required."
        else:
            user = User.get_by_email(email_val)
            if not user:
                error = "No account found with this email."
            elif not user.check_password(password):
                error = "Invalid password."
            else:
                session["user_id"] = user.id
                return redirect(url_for("index"))
                
    return render_template("login.html", error=error, email_val=email_val)

@app.route("/register", methods=["GET", "POST"])
def register():
    if get_current_user():
        return redirect(url_for("index"))
        
    error = None
    email_val = ""
    username_val = ""
    
    if request.method == "POST":
        username_val = request.form.get("username", "").strip()
        email_val = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        
        if not username_val or not email_val or not password:
            error = "All fields are required."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            existing = User.get_by_email(email_val)
            if existing:
                error = "An account with that email already exists."
            else:
                user_id = User.create(username_val, email_val, password)
                if user_id:
                    session["user_id"] = user_id
                    return redirect(url_for("index"))
                else:
                    error = "Registration failed. Try again."
                    
    return render_template("register.html", error=error, email_val=email_val, username_val=username_val)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------
@app.route("/api/stats")
def api_stats():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 401
    stats = get_statistics()
    threat_level, alerts = evaluate_threat_state()
    active_incidents = incident_manager.get_active_incidents()
    
    return jsonify({
        "stats": stats,
        "threat_level": threat_level,
        "active_incidents_count": len(active_incidents)
    })

@app.route("/api/history")
def api_history():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 401
    limit = request.args.get("limit", default=50, type=int)
    history = get_history(limit=limit)
    return jsonify(history)

@app.route("/api/incidents")
def api_incidents():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 401
        
    active = incident_manager.get_active_incidents()
    resolved = get_incidents("RESOLVED", limit=20)
    return jsonify({
        "active": active,
        "resolved": resolved
    })

@app.route("/api/operators")
def api_operators():
    user = get_current_user()
    if not user or not is_admin_email(user.email):
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        users = User.get_all()
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/sniffer/status")
def api_sniffer_status():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 401
    active = live_sniffer.sniffer_instance is not None and live_sniffer.sniffer_instance.running
    return jsonify({"active": active})

@app.route("/api/settings/config")
def api_settings_config():
    user = get_current_user()
    if not user or not is_admin_email(user.email):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(load_config())

# -------------------------------------------------------------
# HTMX POST Actions
# -------------------------------------------------------------
@app.route("/action/settings/save", methods=["POST"])
def action_settings_save():
    user = get_current_user()
    if not user or not is_admin_email(user.email):
        return "<div class='text-red-500 font-semibold'>Error: Unauthorized access.</div>", 401
        
    cfg = load_config()
    
    smtp_host = request.form.get("smtp_host", "").strip()
    smtp_port = int(request.form.get("smtp_port", 587))
    sender_email = request.form.get("sender_email", "").strip()
    sender_password = request.form.get("sender_password", "")
    recipient_email = request.form.get("recipient_email", "").strip()
    email_enabled = request.form.get("email_enabled") == "on"
    
    tg_token = request.form.get("tg_token", "")
    tg_chat_id = request.form.get("tg_chat_id", "").strip()
    tg_enabled = request.form.get("tg_enabled") == "on"
    
    # Restore passwords if masked
    if sender_password == "********":
        sender_password = cfg.get("email", {}).get("sender_password", "")
    if tg_token == "********":
        tg_token = cfg.get("telegram", {}).get("bot_token", "")
        
    new_cfg = {
        "email": {
            "smtp_server": smtp_host,
            "smtp_port": smtp_port,
            "sender_email": sender_email,
            "sender_password": sender_password,
            "recipient_email": recipient_email,
            "enabled": email_enabled
        },
        "telegram": {
            "bot_token": tg_token,
            "chat_id": tg_chat_id,
            "enabled": tg_enabled
        }
    }
    
    save_config(new_cfg)
    return "<div class='text-green-500 font-semibold'>✅ Configuration saved successfully!</div>"

@app.route("/action/settings/test/email", methods=["POST"])
def action_settings_test_email():
    user = get_current_user()
    if not user or not is_admin_email(user.email):
        return "Unauthorized", 401
        
    em_cfg = load_config().get("email", {})
    if em_cfg.get("sender_email") and em_cfg.get("recipient_email"):
        timestamp_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        email_html = f"""
        <html>
        <body style="font-family: sans-serif; padding: 20px; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: auto; border: 1px solid #007bff; border-radius: 8px; background-color: #ffffff; padding:24px;">
                <h2>IDS Connection Test</h2>
                <p>This is a manual connection test generated by your SOC dashboard settings.</p>
                <p><strong>Timestamp:</strong> {timestamp_str} UTC</p>
            </div>
        </body>
        </html>
        """
        success = send_email_message(em_cfg, "🛡️ [IDS TEST ALERT]", email_html)
        if success:
            return "<span class='text-green-400 font-semibold'>✉️ Test email dispatched successfully!</span>"
        else:
            return "<span class='text-red-400 font-semibold'>❌ Dispatch failed. Verify SMTP server configurations.</span>"
    return "<span class='text-yellow-400 font-semibold'>⚠️ Email configuration values are incomplete.</span>"

@app.route("/action/settings/test/telegram", methods=["POST"])
def action_settings_test_telegram():
    user = get_current_user()
    if not user or not is_admin_email(user.email):
        return "Unauthorized", 401
        
    tg_cfg = load_config().get("telegram", {})
    if tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
        timestamp_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        tg_msg = (
            f"🛡️ *[IDS TEST ALERT]*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"This is a manual connection test from your SOC Web dashboard.\n"
            f"📅 *Timestamp:* `{timestamp_str} UTC`"
        )
        success = send_telegram_message(tg_cfg["bot_token"], tg_cfg["chat_id"], tg_msg)
        if success:
            return "<span class='text-green-400 font-semibold'>💬 Telegram test message dispatched successfully!</span>"
        else:
            return "<span class='text-red-400 font-semibold'>❌ Dispatch failed. Verify Token ID and target Chat ID.</span>"
    return "<span class='text-yellow-400 font-semibold'>⚠️ Telegram configuration values are incomplete.</span>"

@app.route("/action/operators/delete/<int:user_id>", methods=["DELETE"])
def action_operators_delete(user_id):
    user = get_current_user()
    if not user or not is_admin_email(user.email):
        return "Unauthorized", 401
        
    if user_id == user.id:
        return "Cannot delete your active session.", 400
        
    if User.delete(user_id):
        # Return empty response so HTMX deletes the table row from DOM
        return ""
    return "Failed to delete operator.", 500

@app.route("/action/sniffer/toggle", methods=["POST"])
def action_sniffer_toggle():
    user = get_current_user()
    if not user:
        return "Unauthorized", 401
        
    # Check if sniffer is running
    active = live_sniffer.sniffer_instance is not None and live_sniffer.sniffer_instance.running
    if active:
        live_sniffer.stop_sniffer_thread()
        return jsonify({"active": False})
    else:
        success = live_sniffer.start_sniffer_thread()
        return jsonify({"active": success})

# -------------------------------------------------------------
# WebSocket Events
# -------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    print(f"[*] Client connected to WebSockets. ID: {request.sid}")

@socketio.on("disconnect")
def on_disconnect():
    print(f"[*] Client disconnected. ID: {request.sid}")

# -------------------------------------------------------------
# Application Execution
# -------------------------------------------------------------
if __name__ == "__main__":
    # Autostart the sniffer locally if not on Render
    if not os.environ.get("RENDER"):
        try:
            live_sniffer.start_sniffer_thread()
        except Exception as e:
            print(f"[WARNING] Could not autostart sniffer thread: {e}")
            
    port = int(os.environ.get("PORT", 8501))
    print(f"[*] Starting SOC Web Portal on http://localhost:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
