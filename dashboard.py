# dashboard.py
# Real-time Streamlit SOC Dashboard for Network Intrusion Detection System (NIDS)

import os
import sys
import time
import threading
import datetime
import requests
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="KryptaFlow NIDS SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Pure Streamlit application (Flask removed). Ingestion writes directly to SQLite.

# Import models and engines (since they share the same SQLite database)
from database import get_statistics, get_history, DB_PATH, get_incidents, resolve_stale_incidents
from user_model import User
from severity_engine import evaluate_threat_state
from notification_engine import load_config, save_config, send_telegram_message, send_email_message

# Initialize session state variables
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "register_mode" not in st.session_state:
    st.session_state.register_mode = False
if "login_error" not in st.session_state:
    st.session_state.login_error = None
if "email_val" not in st.session_state:
    st.session_state.email_val = ""
if "auto_started" not in st.session_state:
    st.session_state.auto_started = False
if "explicitly_stopped" not in st.session_state:
    st.session_state.explicitly_stopped = False

import subprocess
import sys

def is_sniffer_running() -> bool:
    """Checks if the sniffer heartbeat file is being actively updated."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    hb_path = os.path.join(base_dir, "logs", "sniffer.heartbeat")
    if not os.path.exists(hb_path):
        return False
    try:
        mtime = os.path.getmtime(hb_path)
        # Heartbeat is written every second; 6 seconds threshold is safe
        return (time.time() - mtime) < 6.0
    except Exception:
        return False

def start_sniffer() -> bool:
    """Spawns the live_sniffer.py script in the background."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Remove any existing stop file
    stop_path = os.path.join(log_dir, "sniffer.stop")
    if os.path.exists(stop_path):
        try:
            os.remove(stop_path)
        except Exception:
            pass
            
    # Spawn sniffer as background process
    try:
        log_file = open(os.path.join(log_dir, "live_sniffer_auto.log"), "w")
        creationflags = 0
        if sys.platform == "win32":
            # CREATE_NO_WINDOW = 0x08000000
            creationflags = 0x08000000
            
        subprocess.Popen(
            [sys.executable, "live_sniffer.py"],
            stdout=log_file,
            stderr=log_file,
            creationflags=creationflags,
            close_fds=True
        )
        return True
    except Exception:
        return False

def stop_sniffer() -> bool:
    """Signals the sniffer to stop by writing a stop file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    stop_path = os.path.join(base_dir, "logs", "sniffer.stop")
    try:
        with open(stop_path, "w") as f:
            f.write("stop")
        
        # Delete heartbeat file to update UI immediately
        hb_path = os.path.join(base_dir, "logs", "sniffer.heartbeat")
        if os.path.exists(hb_path):
            try:
                os.remove(hb_path)
            except Exception:
                pass
        return True
    except Exception:
        return False

# Inject custom global CSS styles (glowing components, clean styling)
st.markdown("""
<style>
    /* Dark glassmorphic background & panel tweaks */
    .stApp {
        background-color: #0a0c10;
        background-image: 
            radial-gradient(circle at 10% 20%, rgba(9, 132, 227, 0.04) 0%, transparent 40%),
            radial-gradient(circle at 90% 80%, rgba(214, 48, 49, 0.03) 0%, transparent 45%);
    }
    
    /* Center the login / register panels */
    div.block-container {
        padding-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# VIEW: Login Screen
# -------------------------------------------------------------
if not st.session_state.logged_in and not st.session_state.register_mode:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align: center; margin-bottom: 1rem;">
            <h1 style="font-weight: 800; font-size: 2.2rem; background: linear-gradient(135deg, #74b9ff, #0984e3); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                🛡️ KRYPTAFLOW NIDS
            </h1>
            <p style="color: #a4b0be; font-size: 1rem; margin-top: -0.5rem;">Security Operations Center Sign In</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            email_input = st.text_input("Email Address", value=st.session_state.email_val, placeholder="operator@security.local")
            password_input = st.text_input("Password", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Sign In", use_container_width=True)
            
            if submit:
                email = email_input.strip().lower()
                st.session_state.email_val = email
                
                if not email or not password_input:
                    st.session_state.login_error = "missing_fields"
                else:
                    user = User.get_by_email(email)
                    if not user:
                        st.session_state.login_error = "no_account"
                    elif not user.check_password(password_input):
                        st.session_state.login_error = "invalid_password"
                    else:
                        st.session_state.logged_in = True
                        st.session_state.user = user
                        st.session_state.login_error = None
                        st.success("Access Granted! Loading SOC Dashboard...")
                        st.rerun()

        # Handle login error states
        if st.session_state.login_error == "missing_fields":
            st.error("❌ Both email and password are required.")
        elif st.session_state.login_error == "invalid_password":
            st.error("❌ Invalid email or password.")
        elif st.session_state.login_error == "no_account":
            st.warning("⚠️ No account found with this email.")
            if st.button("Register New Account", use_container_width=True):
                st.session_state.register_mode = True
                st.session_state.login_error = None
                st.rerun()
                
        st.markdown("<hr style='border-color: rgba(255,255,255,0.08); margin: 2rem 0 1rem 0;'>", unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align: center; font-size: 0.9rem; color: #a4b0be;">
            New Operator? <a href="#" onclick="parent.window.location.reload();" style="color: #0984e3; text-decoration: none; font-weight: 600;">Use Register Form</a>
        </div>
        """, unsafe_allow_html=True)
        
        # Plain button to toggle registration mode directly
        if st.button("Open Registration Form", key="toggle_reg_direct", use_container_width=True):
            st.session_state.register_mode = True
            st.session_state.login_error = None
            st.rerun()

# -------------------------------------------------------------
# VIEW: Registration Screen
# -------------------------------------------------------------
elif not st.session_state.logged_in and st.session_state.register_mode:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align: center; margin-bottom: 1rem;">
            <h1 style="font-weight: 800; font-size: 2.2rem; background: linear-gradient(135deg, #74b9ff, #0984e3); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                OPERATOR SIGN UP
            </h1>
            <p style="color: #a4b0be; font-size: 1rem; margin-top: -0.5rem;">Create a secure access account</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("register_form"):
            reg_username = st.text_input("Username", placeholder="Operator Name")
            reg_email = st.text_input("Email Address", value=st.session_state.email_val, placeholder="operator@security.local")
            reg_password = st.text_input("Password", type="password", placeholder="••••••••")
            reg_confirm = st.text_input("Confirm Password", type="password", placeholder="••••••••")
            submit_reg = st.form_submit_button("Create Operator Account", use_container_width=True)
            
            if submit_reg:
                username = reg_username.strip()
                email = reg_email.strip().lower()
                st.session_state.email_val = email
                
                if not username or not email or not reg_password:
                    st.error("❌ All fields are required.")
                elif reg_password != reg_confirm:
                    st.error("❌ Passwords do not match.")
                else:
                    existing = User.get_by_email(email)
                    if existing:
                        st.error("❌ An account with that email already exists.")
                    else:
                        user_id = User.create(username, email, reg_password)
                        if user_id:
                            st.success("🎉 Registration successful! Redirecting to login...")
                            time.sleep(1.5)
                            st.session_state.register_mode = False
                            st.session_state.login_error = None
                            st.rerun()
                        else:
                            st.error("❌ Registration failed. Please try again.")
                            
        if st.button("Back to Sign In", use_container_width=True):
            st.session_state.register_mode = False
            st.session_state.login_error = None
            st.rerun()

# -------------------------------------------------------------
# VIEW: Protected SOC Dashboard
# -------------------------------------------------------------
else:
    # Auto-start sniffer if not running, not explicitly stopped, and not already tried
    if not is_sniffer_running() and not st.session_state.explicitly_stopped and not st.session_state.auto_started:
        start_sniffer()
        st.session_state.auto_started = True

    # Pre-fetch history records to calculate sniffer status and populate widgets
    history_records = get_history(limit=100)

    # Sidebar: Diagnostics, Sniffer State, Auto Refresh
    with st.sidebar:
        st.markdown(f"""
        <div style="padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 1.5rem;">
            <h3 style="margin: 0; font-weight: 700; color: #fff;">🛡️ KryptaFlow NIDS</h3>
            <span style="font-size: 0.8rem; color: #a4b0be;">Security Operations Control</span>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"**Operator**: `{st.session_state.user.username}`")
        st.markdown(f"**Email**: `{st.session_state.user.email}`")
        
        # Check sniffer status
        sniffer_active = is_sniffer_running()
        status_color = "#00b894" if sniffer_active else "#d63031"
        status_text = "ONLINE" if sniffer_active else "OFFLINE"
        
        st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 8px; margin: 1rem 0 0.5rem 0;">
            <div style="width: 10px; height: 10px; border-radius: 50%; background-color: {status_color}; box-shadow: 0 0 8px {status_color}"></div>
            <span style="font-weight: 600; font-size: 0.9rem;">Live Sniffer: <span style="color: {status_color}">{status_text}</span></span>
        </div>
        """, unsafe_allow_html=True)
        
        # Start/Stop Action Buttons in the Sidebar
        if sniffer_active:
            if st.button("🛑 Stop Live Analysis", use_container_width=True, key="sidebar_stop_sniffer"):
                stop_sniffer()
                st.session_state.explicitly_stopped = True
                st.success("Stop signal dispatched.")
                time.sleep(1.0)
                st.rerun()
        else:
            if st.button("🚀 Start Live Analysis", use_container_width=True, key="sidebar_start_sniffer"):
                start_sniffer()
                st.session_state.explicitly_stopped = False
                st.session_state.auto_started = True
                st.success("Launching sniffer...")
                time.sleep(1.5)
                st.rerun()
            st.warning("⚠️ Run terminal/Streamlit as Administrator to allow live sniffing.")
            
        st.markdown("<hr style='border-color: rgba(255,255,255,0.08);'>", unsafe_allow_html=True)
        
        # Real-time Auto-Refresh
        st.markdown("##### Real-Time Updates")
        refresh_enabled = st.checkbox("Enable Auto Refresh (5s)", value=True)
        
        st.markdown("<br><br>", unsafe_allow_html=True)
        
        if st.button("Logout Session", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.success("Session closed.")
            st.rerun()

    # Load statistics and threat state
    try:
        resolve_stale_incidents()
    except Exception:
        pass
    stats = get_statistics()
    threat_level, alerts = evaluate_threat_state()

    # Title header
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <h1 style="font-weight: 800; font-size: 2rem; margin: 0;">SOC SECURITY OPERATIONS CENTER</h1>
        <span style="color: #a4b0be; font-size: 0.85rem;">Ingestion Mode: Direct SQLite WAL</span>
    </div>
    """, unsafe_allow_html=True)

    # Critical Warning if Live Sniffer is Offline
    if not sniffer_active:
        col_warn_text, col_warn_btn = st.columns([4, 1])
        with col_warn_text:
            st.error(
                "🚨 **CRITICAL NOTICE: Live Network Sniffer is Offline.**  \n"
                "The background packet capture agent is currently inactive. Visualized charts are based on historical data only."
            )
        with col_warn_btn:
            if st.button("Analyse Live Traffic", use_container_width=True, key="main_panel_start_sniffer"):
                start_sniffer()
                st.session_state.explicitly_stopped = False
                st.session_state.auto_started = True
                st.success("Starting sniffer...")
                time.sleep(1.5)
                st.rerun()

    # 1. Dynamic Glowing Threat Banner
    colors = {
        "LOW": ("#00b894", "rgba(0, 184, 148, 0.2)"),
        "MEDIUM": ("#fdcb6e", "rgba(253, 203, 110, 0.2)"),
        "HIGH": ("#ff7675", "rgba(255, 118, 117, 0.2)"),
        "CRITICAL": ("#d63031", "rgba(214, 48, 49, 0.3)")
    }
    banner_color, banner_glow = colors.get(threat_level, ("#74b9ff", "rgba(116, 185, 255, 0.2)"))
    
    st.markdown(f"""
    <div style="background: rgba(18, 22, 31, 0.75); border: 1px solid {banner_color}; box-shadow: 0 0 15px {banner_glow}; padding: 0.9rem 1.5rem; border-radius: 8px; font-weight: 800; font-size: 1.15rem; color: {banner_color}; display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; letter-spacing: 0.5px;">
        <span>SYSTEM THREAT LEVEL: {threat_level}</span>
        <span style="font-size: 0.85rem; font-weight: 600; background: {banner_glow}; padding: 4px 8px; border-radius: 4px; border: 1px solid {banner_color}">🛡️ {"LIVE PROTECTION ACTIVE" if sniffer_active else "HISTORICAL DATA MODE"}</span>
    </div>
    """, unsafe_allow_html=True)

    # Tabbed Views: Monitoring vs Settings
    tab_monitoring, tab_settings = st.tabs([" Live Monitoring", " Alert Settings"])

    with tab_monitoring:
        # 2. KPI Cards Row
        try:
            active_inc_count = len(get_incidents("ACTIVE"))
        except Exception:
            active_inc_count = 0
            
        kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
        
        with kpi1:
            st.metric(label="Total Flows", value=f"{stats['total_records']:,}")
        with kpi2:
            st.metric(label="Active Incidents", value=f"{active_inc_count:,}")
        with kpi3:
            st.metric(label="Attacks Last Hour", value=f"{stats['attacks_last_hour']:,}")
        with kpi4:
            st.metric(label="Avg Latency", value=f"{stats['average_latency_ms']:.2f} ms")
        with kpi5:
            st.metric(label="Imputed Features", value=f"{stats['total_imputed_features']:,}")

        # history_records are pre-fetched at the beginning of block
        
        # 3. Charts Area
        chart_col1, chart_col2 = st.columns([2, 1])
        
        with chart_col1:
            # Timeline Line Chart (aggregates flow counts in 10-second buckets)
            if history_records:
                df_hist = pd.DataFrame(history_records)
                df_hist['datetime'] = pd.to_datetime(df_hist['timestamp'])
                # Group by 10s buckets
                df_hist['time_bucket'] = df_hist['datetime'].dt.round('10s')
                timeline_df = df_hist.groupby('time_bucket').size().reset_index(name='Captured Flows')
                timeline_df['time_str'] = timeline_df['time_bucket'].dt.strftime('%H:%M:%S')
                
                fig_timeline = px.line(
                    timeline_df,
                    x='time_str',
                    y='Captured Flows',
                    title="Captured Flows Timeline (10s intervals)",
                    labels={"time_str": "Time Stamp", "Captured Flows": "Packets Count"}
                )
                fig_timeline.update_layout(
                    template="plotly_dark",
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=320,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
            else:
                st.info("No flow timeline data available. Waiting for sniffer traffic...")

        with chart_col2:
            # Class Distribution Pie Chart
            class_dist = stats.get("class_distribution", {})
            if class_dist:
                df_class = pd.DataFrame(list(class_dist.items()), columns=['Intrusion Class', 'Count'])
                fig_pie = px.pie(
                    df_class,
                    values='Count',
                    names='Intrusion Class',
                    hole=0.4,
                    title="Intrusion Distribution"
                )
                fig_pie.update_layout(
                    template="plotly_dark",
                    paper_bgcolor='rgba(0,0,0,0)',
                    height=320,
                    margin=dict(l=10, r=10, t=40, b=10)
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("Waiting for threat class distributions...")

        # Severity distribution Bar Chart
        sev_dist = stats.get("severity_distribution", {})
        if sev_dist:
            df_sev = pd.DataFrame(list(sev_dist.items()), columns=['Severity', 'Count'])
            # Ensure proper index order
            df_sev['Severity'] = pd.Categorical(df_sev['Severity'], categories=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], ordered=True)
            df_sev = df_sev.sort_values('Severity')
            
            fig_bar = px.bar(
                df_sev,
                x='Severity',
                y='Count',
                color='Severity',
                title="Severity Level Analysis",
                color_discrete_map={"LOW": "#00b894", "MEDIUM": "#fdcb6e", "HIGH": "#ff7675", "CRITICAL": "#d63031"}
            )
            fig_bar.update_layout(
                template="plotly_dark",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=240,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # 3.2 Hybrid system analysis and top attacker IPs
        st.markdown("<hr style='border-color: rgba(255,255,255,0.08);'>", unsafe_allow_html=True)
        col_hybrid1, col_hybrid2 = st.columns([1, 1])
        
        with col_hybrid1:
            # Top attacker IPs
            top_attackers = stats.get("top_attackers", [])
            if top_attackers:
                df_attackers = pd.DataFrame(top_attackers)
                fig_attackers = px.bar(
                    df_attackers,
                    x='count',
                    y='src_ip',
                    orientation='h',
                    title="Top Attacking Source IPs",
                    labels={"count": "Threats Blocked", "src_ip": "Source IP Address"},
                    color_discrete_sequence=["#ff7675"]
                )
                fig_attackers.update_layout(
                    template="plotly_dark",
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=260,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_attackers, use_container_width=True)
            else:
                st.info("No external threats detected yet. Attacker list is empty.")
                
        with col_hybrid2:
            # Signature vs Behavior
            method_breakdown = stats.get("detection_method_breakdown", {"BEHAVIOR": 0, "SIGNATURE": 0})
            if any(method_breakdown.values()):
                df_method = pd.DataFrame(list(method_breakdown.items()), columns=['Method', 'Detections'])
                fig_method = px.pie(
                    df_method,
                    values='Detections',
                    names='Method',
                    hole=0.4,
                    title="Hybrid Detection Breakdown (Signature vs. ML)",
                    color='Method',
                    color_discrete_map={"BEHAVIOR": "#0984e3", "SIGNATURE": "#6c5ce7"}
                )
                fig_method.update_layout(
                    template="plotly_dark",
                    paper_bgcolor='rgba(0,0,0,0)',
                    height=260,
                    margin=dict(l=10, r=10, t=40, b=10)
                )
                st.plotly_chart(fig_method, use_container_width=True)
            else:
                st.info("No detections registered. Ingestion breakdown is empty.")

        # 3.5 Incidents Feed Section
        st.markdown("<hr style='border-color: rgba(255,255,255,0.08);'>", unsafe_allow_html=True)
        st.markdown("####  Aggregated Incidents Feed (Throttled Alerts)")
        
        col_inc1, col_inc2 = st.columns(2)
        
        with col_inc1:
            st.markdown("##### Active Incidents")
            try:
                active_incidents = get_incidents("ACTIVE")
            except Exception:
                active_incidents = []
                
            if active_incidents:
                for inc in active_incidents[:10]:
                    st.error(
                        f"**{inc['attack_type']} Incident** from `{inc['src_ip']}` to `{inc['dst_ip']}`  \n"
                        f"Count: `{inc['event_count']}` anomalous flows | "
                        f"Severity: `{inc['severity']}` | "
                        f"First Seen: `{datetime.datetime.fromisoformat(inc['start_time']).strftime('%H:%M:%S')}` | "
                        f"Last Seen: `{datetime.datetime.fromisoformat(inc['last_update']).strftime('%H:%M:%S')}`"
                    )
            else:
                st.success("No active security incidents detected. System healthy.")
                
        with col_inc2:
            st.markdown("##### Recently Resolved Incidents")
            try:
                resolved_incidents = get_incidents("RESOLVED")
            except Exception:
                resolved_incidents = []
                
            if resolved_incidents:
                for inc in resolved_incidents[:10]:
                    st.info(
                        f"**{inc['attack_type']} Incident** from `{inc['src_ip']}` resolved.  \n"
                        f"Total Count: `{inc['event_count']}` events | "
                        f"Duration: `{inc['start_time'][11:19]} to {inc['last_update'][11:19]}`"
                    )
            else:
                st.text("No resolved incidents recorded yet.")

        # 4. Live predictions feed table
        st.markdown("<hr style='border-color: rgba(255,255,255,0.08);'>", unsafe_allow_html=True)
        st.markdown("#### Live Ingestion Feed (Last 50 Logs)")
        if history_records:
            # Construct a beautiful custom HTML/CSS table matching the dark theme
            table_html = (
                '<div style="overflow-x: auto; max-height: 380px; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px;">\n'
                '<table style="width:100%; border-collapse: collapse; text-align: left; background: rgba(18, 22, 31, 0.7); font-family: sans-serif;">\n'
                '<thead>\n'
                '<tr style="background: rgba(0, 0, 0, 0.3); border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 0.85rem; color: #a4b0be;">\n'
                '<th style="padding: 0.8rem 1rem;">ID</th>\n'
                '<th style="padding: 0.8rem 1rem;">Timestamp</th>\n'
                '<th style="padding: 0.8rem 1rem;">Source IP</th>\n'
                '<th style="padding: 0.8rem 1rem;">Dest IP</th>\n'
                '<th style="padding: 0.8rem 1rem;">Prediction</th>\n'
                '<th style="padding: 0.8rem 1rem;">Method</th>\n'
                '<th style="padding: 0.8rem 1rem;">Confidence</th>\n'
                '<th style="padding: 0.8rem 1rem;">Details</th>\n'
                '</tr>\n'
                '</thead>\n'
                '<tbody>\n'
            )
            for rec in history_records[:50]:
                date = datetime.datetime.fromisoformat(rec['timestamp'])
                local_time = date.strftime("%H:%M:%S %d-%m-%Y")
                
                # Severity styling
                sev = rec['severity']
                if sev == 'LOW':
                    badge_style = "background: rgba(0, 184, 148, 0.15); color: #00b894; border: 1px solid rgba(0, 184, 148, 0.3);"
                elif sev == 'MEDIUM':
                    badge_style = "background: rgba(253, 203, 110, 0.15); color: #fdcb6e; border: 1px solid rgba(253, 203, 110, 0.3);"
                elif sev == 'HIGH':
                    badge_style = "background: rgba(255, 118, 117, 0.15); color: #ff7675; border: 1px solid rgba(255, 118, 117, 0.3);"
                else:
                    badge_style = "background: rgba(214, 48, 49, 0.15); color: #d63031; border: 1px solid rgba(214, 48, 49, 0.3);"
                
                method_badge = "background: rgba(9, 132, 227, 0.15); color: #0984e3; border: 1px solid rgba(9, 132, 227, 0.3);" if rec.get('detection_method', 'BEHAVIOR') == 'BEHAVIOR' else "background: rgba(108, 92, 231, 0.15); color: #6c5ce7; border: 1px solid rgba(108, 92, 231, 0.3);"
                
                table_html += (
                    f'<tr style="border-bottom: 1px solid rgba(255,255,255,0.02); font-size: 0.85rem; color: #f5f6fa;">\n'
                    f'<td style="padding: 0.7rem 1rem;">#{rec["id"]}</td>\n'
                    f'<td style="padding: 0.7rem 1rem; color: #a4b0be;">{local_time}</td>\n'
                    f'<td style="padding: 0.7rem 1rem; font-weight: 500;">{rec.get("src_ip", "127.0.0.1")}</td>\n'
                    f'<td style="padding: 0.7rem 1rem; color: #a4b0be;">{rec.get("dst_ip", "127.0.0.1")}:{rec.get("dst_port", 0)}</td>\n'
                    f'<td style="padding: 0.7rem 1rem;"><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-weight:700; font-size: 0.75rem; text-transform:uppercase; {badge_style}">{rec["prediction"]}</span></td>\n'
                    f'<td style="padding: 0.7rem 1rem;"><span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-weight:600; font-size: 0.7rem; {method_badge}">{rec.get("detection_method", "BEHAVIOR")}</span></td>\n'
                    f'<td style="padding: 0.7rem 1rem; font-weight: 600;">{rec["confidence"]*100:.1f}%</td>\n'
                    f'<td style="padding: 0.7rem 1rem; font-size: 0.8rem; color: #a4b0be;">{rec.get("details", "")}</td>\n'
                    f'</tr>\n'
                )
            table_html += "</tbody></table></div>"
            st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.info("No flow prediction records found in the database. Run live_sniffer.py to trigger captures.")

    with tab_settings:
        st.markdown("### Alert & Dispatcher Configurations")
        
        # Load active config
        cfg = load_config()
        
        with st.form("settings_form"):
            st.markdown("##### ✉️ SMTP Email Dispatcher")
            smtp_host = st.text_input("SMTP Server Host", value=cfg.get("email", {}).get("smtp_server", ""))
            smtp_port = st.number_input("SMTP Port", value=int(cfg.get("email", {}).get("smtp_port", 587)))
            email_enabled = st.checkbox("Enable Email Alerting", value=bool(cfg.get("email", {}).get("enabled", False)))
            sender_email = st.text_input("Sender Email Address", value=cfg.get("email", {}).get("sender_email", ""))
            
            # Mask existing password if loaded
            saved_password = cfg.get("email", {}).get("sender_password", "")
            masked_password = "********" if saved_password else ""
            sender_password = st.text_input("Sender Password / Application Key", type="password", value=masked_password)
            
            recipient_email = st.text_input("Recipient Email Address", value=cfg.get("email", {}).get("recipient_email", ""))
            
            st.markdown("<hr style='border-color: rgba(255,255,255,0.08);'>", unsafe_allow_html=True)
            
            st.markdown("#####  Telegram Bot API Dispatcher")
            saved_token = cfg.get("telegram", {}).get("bot_token", "")
            masked_token = "********" if saved_token else ""
            tg_token = st.text_input("Bot Token ID", type="password", value=masked_token)
            
            tg_chat_id = st.text_input("Channel/Chat Target ID", value=cfg.get("telegram", {}).get("chat_id", ""))
            tg_enabled = st.checkbox("Enable Telegram Alerting", value=bool(cfg.get("telegram", {}).get("enabled", False)))
            
            save_btn = st.form_submit_button("Commit Alert Configurations")
            
            if save_btn:
                # Prepare saved configs, restoring masked inputs
                email_pwd = saved_password if sender_password == "********" else sender_password
                tg_bot_token = saved_token if tg_token == "********" else tg_token
                
                new_cfg = {
                    "email": {
                        "smtp_server": smtp_host.strip(),
                        "smtp_port": int(smtp_port),
                        "sender_email": sender_email.strip(),
                        "sender_password": email_pwd,
                        "recipient_email": recipient_email.strip(),
                        "enabled": email_enabled
                    },
                    "telegram": {
                        "bot_token": tg_bot_token.strip(),
                        "chat_id": tg_chat_id.strip(),
                        "enabled": tg_enabled
                    }
                }
                save_config(new_cfg)
                st.success("✅ Configurations saved successfully!")
                time.sleep(1.0)
                st.rerun()

        # Manual test buttons outside the commit form
        test_col1, test_col2 = st.columns(2)
        
        with test_col1:
            if st.button(" Send Test Email Alert", use_container_width=True):
                timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                email_html = f"""
                <html>
                <body style="font-family: sans-serif; padding: 20px; background-color: #f5f5f5;">
                    <div style="max-width: 600px; margin: auto; border: 1px solid #007bff; border-radius: 8px; background-color: #ffffff; padding:24px;">
                        <h2>IDS Connection Test</h2>
                        <p>This is a manual connection test generated by your Streamlit NIDS settings.</p>
                        <p><strong>Timestamp:</strong> {timestamp_str} UTC</p>
                    </div>
                </body>
                </html>
                """
                # Fetch fresh configurations for the test
                em_cfg = load_config().get("email", {})
                if em_cfg.get("sender_email") and em_cfg.get("recipient_email"):
                    success = send_email_message(em_cfg, "🛡️ [IDS TEST ALERT]", email_html)
                    if success:
                        st.success("✉️ Test email dispatched successfully!")
                    else:
                        st.error("❌ Test email dispatch failed. Verify your SMTP credentials.")
                else:
                    st.warning("⚠️ Email configurations are missing.")
                    
        with test_col2:
            if st.button("🚀 Send Test Telegram Message", use_container_width=True):
                timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                tg_msg = (
                    f"🛡️ *[IDS TEST ALERT]*\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"This is a manual connection test from your Streamlit dashboard.\n"
                    f"📅 *Timestamp:* `{timestamp_str} UTC`"
                )
                tg_cfg = load_config().get("telegram", {})
                if tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
                    success = send_telegram_message(tg_cfg["bot_token"], tg_cfg["chat_id"], tg_msg)
                    if success:
                        st.success("💬 Telegram test message dispatched successfully!")
                    else:
                        st.error("❌ Telegram dispatch failed. Verify token and chat ID.")
                else:
                    st.warning("⚠️ Telegram configurations are missing.")

    # 5. Handle Auto Refresh Rerun Trigger
    if refresh_enabled:
        time.sleep(5)
        st.rerun()
