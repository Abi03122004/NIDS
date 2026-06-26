# incident_manager.py
# Aggregates anomalous flows into Incidents and dispatches throttled urgent alerts

import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from database import (
    get_active_incident_by_ip_and_type,
    create_incident,
    update_incident,
    resolve_stale_incidents
)
from notification_engine import dispatch_alert

# Incident aggregation thresholds
ANOMALY_THRESHOLD = 5  # Number of related anomalies to trigger an urgent notification
WINDOW_SECONDS = 120.0  # Sliding time window lookback (2 minutes to catch low-and-slow)
STALE_TIMEOUT_SECONDS = 30.0  # Seconds of inactivity before resolving an incident

# In-memory sliding window tracking databases
anomaly_timestamps = defaultdict(list)
port_scan_history = defaultdict(list)

def process_anomaly(
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    severity: str,
    timestamp: Optional[str] = None,
    dst_port: Optional[int] = None
):
    """
    Groups a newly detected anomaly into an incident using an in-memory sliding time window.
    Supports low-and-slow port scanning detection by tracking unique ports.
    If the threshold is crossed, it dispatches a single urgent notification.
    """
    if attack_type == "BENIGN":
        return
        
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
        
    # 1. Periodically resolve old stale incidents in the SQLite DB
    try:
        resolve_stale_incidents(timeout_seconds=STALE_TIMEOUT_SECONDS)
    except Exception:
        pass
        
    # 2. Update in-memory sliding window
    now = time.time()
    history_key = (src_ip, attack_type)
    anomaly_timestamps[history_key].append(now)
    # Filter out entries older than WINDOW_SECONDS
    anomaly_timestamps[history_key] = [t for t in anomaly_timestamps[history_key] if now - t <= WINDOW_SECONDS]
    
    # 3. Handle PortScan separately to count unique ports hit
    if attack_type == "PortScan" and dst_port is not None:
        port_scan_history[src_ip].append((now, dst_port))
        port_scan_history[src_ip] = [(t, p) for (t, p) in port_scan_history[src_ip] if now - t <= WINDOW_SECONDS]
        # Count unique destination ports hit
        recent_count = len(set(p for (t, p) in port_scan_history[src_ip]))
    else:
        recent_count = len(anomaly_timestamps[history_key])
        
    # 4. Check if there is an active incident for this IP + Attack Type in the database
    try:
        incident = get_active_incident_by_ip_and_type(
            src_ip=src_ip,
            attack_type=attack_type,
            threshold_seconds=WINDOW_SECONDS
        )
        
        if incident:
            # Existing active incident found: increment database event_count
            new_count = incident["event_count"] + 1
            should_notify = 0
            
            # Trigger notification if unique count crosses threshold
            if (recent_count >= ANOMALY_THRESHOLD or new_count >= ANOMALY_THRESHOLD) and incident["notified"] == 0:
                should_notify = 1
                trigger_incident_notification(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    attack_type=attack_type,
                    severity=severity,
                    count=max(recent_count, new_count)
                )
            elif incident["notified"] == 1:
                should_notify = 1
                # Trigger follow-up warning on multiples of 50 to alert on heavy floods
                if new_count % 50 == 0:
                    trigger_incident_notification(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        attack_type=attack_type,
                        severity="CRITICAL",
                        count=new_count,
                        is_update=True
                    )
                    
            update_incident(
                incident_id=incident["id"],
                event_count=new_count,
                notified=should_notify,
                timestamp=timestamp
            )
            
        else:
            # No active incident in DB: create new one
            create_incident(
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type=attack_type,
                severity=severity,
                timestamp=timestamp
            )
            
            # If the single anomaly is already crossing threshold (e.g. unique ports hit initially)
            if recent_count >= ANOMALY_THRESHOLD:
                new_incident = get_active_incident_by_ip_and_type(src_ip, attack_type, WINDOW_SECONDS)
                if new_incident:
                    trigger_incident_notification(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        attack_type=attack_type,
                        severity=severity,
                        count=recent_count
                    )
                    update_incident(
                        incident_id=new_incident["id"],
                        event_count=recent_count,
                        notified=1,
                        timestamp=timestamp
                    )
            
    except Exception as e:
        print(f"[WARNING] Incident manager failed: {e}")

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
    
    # Send via notification engine
    alert_name = f"INCIDENT_{src_ip}_{attack_type}"
    dispatch_alert(alert_type=alert_name, severity=severity, message=message)
