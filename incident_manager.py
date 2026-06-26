# incident_manager.py
# Aggregates anomalous flows into Incidents in-memory and dispatches throttled urgent alerts

import os
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from database import get_connection
from notification_engine import dispatch_alert

# Incident aggregation thresholds
ANOMALY_THRESHOLD = 5  # Number of related anomalies to trigger an urgent notification
WINDOW_SECONDS = 120.0  # Sliding time window lookback (2 minutes to catch low-and-slow)
STALE_TIMEOUT_SECONDS = 30.0  # Seconds of inactivity before resolving an incident

# In-memory sliding window tracking databases
anomaly_timestamps = defaultdict(list)
port_scan_history = defaultdict(list)

# Global in-memory dictionary for ongoing active incidents
active_incidents = {}
active_incidents_lock = threading.Lock()
socketio_instance = None

def get_active_incidents() -> List[Dict[str, Any]]:
    """Returns a list of all active incidents currently tracked in memory."""
    with active_incidents_lock:
        return list(active_incidents.values())

def process_anomaly(
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    severity: str,
    timestamp: Optional[str] = None,
    dst_port: Optional[int] = None
):
    """
    Groups a newly detected anomaly into an in-memory active incident.
    If the threshold is crossed, it dispatches an urgent notification.
    """
    if attack_type == "BENIGN":
        return
        
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
        
    now = time.time()
    history_key = (src_ip, attack_type)
    
    # Update in-memory sliding window for threshold checking
    anomaly_timestamps[history_key].append(now)
    anomaly_timestamps[history_key] = [t for t in anomaly_timestamps[history_key] if now - t <= WINDOW_SECONDS]
    
    # Handle PortScan separately to count unique ports hit
    if attack_type == "PortScan" and dst_port is not None:
        port_scan_history[src_ip].append((now, dst_port))
        port_scan_history[src_ip] = [(t, p) for (t, p) in port_scan_history[src_ip] if now - t <= WINDOW_SECONDS]
        recent_count = len(set(p for (t, p) in port_scan_history[src_ip]))
    else:
        recent_count = len(anomaly_timestamps[history_key])
        
    with active_incidents_lock:
        if history_key in active_incidents:
            # Update existing active incident
            inc = active_incidents[history_key]
            inc["event_count"] += 1
            inc["last_update"] = timestamp
            inc["last_activity_time"] = now
            
            # Check if threshold crossed and not yet notified
            if (recent_count >= ANOMALY_THRESHOLD or inc["event_count"] >= ANOMALY_THRESHOLD) and inc["notified"] == 0:
                inc["notified"] = 1
                trigger_incident_notification(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    attack_type=attack_type,
                    severity=severity,
                    count=max(recent_count, inc["event_count"])
                )
            elif inc["notified"] == 1 and inc["event_count"] % 50 == 0:
                # Follow up warning for heavy floods
                trigger_incident_notification(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    attack_type=attack_type,
                    severity="CRITICAL",
                    count=inc["event_count"],
                    is_update=True
                )
        else:
            # Create new active incident in-memory
            inc = {
                "start_time": timestamp,
                "last_update": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "attack_type": attack_type,
                "event_count": 1,
                "severity": severity,
                "status": "ACTIVE",
                "notified": 0,
                "last_activity_time": now
            }
            
            if recent_count >= ANOMALY_THRESHOLD:
                inc["notified"] = 1
                trigger_incident_notification(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    attack_type=attack_type,
                    severity=severity,
                    count=recent_count
                )
                
            active_incidents[history_key] = inc

        # Emit SocketIO real-time update
        if socketio_instance:
            socketio_instance.emit("new_incident", inc)

def trigger_incident_notification(
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    severity: str,
    count: int,
    is_update: bool = False
):
    """Formats and dispatches an aggregated incident alert via Telegram/Email."""
    title = f"🚨 URGENT: Security Incident Alert ({severity})"
    if is_update:
        title = f"🔥 CRITICAL: Ongoing Flood Activity ({severity})"
        
    message = (
        f"{title}\n"
        f"-------------------------------------\n"
        f"Incident: Potential {attack_type} attack pattern\n"
        f"Attacker (Source IP): {src_ip}\n"
        f"Target (Dest IP): {dst_ip}\n"
        f"Anomalies Captured: {count} anomalous flows\n"
        f"Time Window: Last {WINDOW_SECONDS} seconds\n"
        f"Status: ACTIVE / ONGOING\n"
        f"-------------------------------------\n"
        f"Action: Investigate source IP connection rates immediately."
    )
    
    alert_name = f"INCIDENT_{src_ip}_{attack_type}"
    dispatch_alert(alert_type=alert_name, severity=severity, message=message)

def save_resolved_incident_to_db(inc: Dict[str, Any]):
    """Saves a resolved incident to the SQLite database."""
    query = """
    INSERT INTO incidents (start_time, last_update, src_ip, dst_ip, attack_type, event_count, severity, status, notified)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'RESOLVED', ?);
    """
    with get_connection() as conn:
        conn.execute(query, (
            inc["start_time"],
            inc["last_update"],
            inc["src_ip"],
            inc["dst_ip"],
            inc["attack_type"],
            inc["event_count"],
            inc["severity"],
            inc["notified"]
        ))
        conn.commit()

def check_expired_incidents_loop():
    """Background thread loop that evicts active incidents that have cooled down."""
    while True:
        time.sleep(2.0)
        now = time.time()
        expired_keys = []
        
        with active_incidents_lock:
            for key, inc in list(active_incidents.items()):
                if now - inc["last_activity_time"] > STALE_TIMEOUT_SECONDS:
                    expired_keys.append(key)
            
            for key in expired_keys:
                inc = active_incidents.pop(key)
                try:
                    inc["status"] = "RESOLVED"
                    save_resolved_incident_to_db(inc)
                    if socketio_instance:
                        socketio_instance.emit("incident_resolved", {
                            "src_ip": inc["src_ip"],
                            "attack_type": inc["attack_type"]
                        })
                except Exception as e:
                    print(f"[ERROR] Failed to save resolved incident to SQLite: {e}")

# Start background cleanup thread immediately when imported
cleanup_thread = threading.Thread(target=check_expired_incidents_loop, daemon=True)
cleanup_thread.start()
