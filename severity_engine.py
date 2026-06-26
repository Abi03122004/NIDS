# controller/severity_engine.py
# Engine for assessing dynamic threat levels and triggering security alert thresholds

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
from database import DB_PATH

def evaluate_threat_state(db_path: str = DB_PATH) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Evaluates the SQLite predictions log in the last 10 seconds to determine
    the overall system threat level and trigger alert conditions.
    
    Returns:
        tuple: (threat_level, list_of_triggered_alerts)
    """
    if not os.path.exists(db_path):
        return "LOW", []

    now = datetime.now(timezone.utc)
    ten_seconds_ago = (now - timedelta(seconds=10)).isoformat()
    
    query = """
    SELECT prediction, severity, timestamp 
    FROM predictions 
    WHERE timestamp >= ?
    """
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(query, (ten_seconds_ago,))
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        return "LOW", []
        
    if not rows:
        return "LOW", []
        
    # Filter anomalies (non-BENIGN)
    anomalies = [row for row in rows if row[0] != "BENIGN"]
    total_anomalies = len(anomalies)
    
    ddos_events = [row for row in anomalies if row[0] == "DDoS"]
    portscan_events = [row for row in anomalies if row[0] == "PortScan"]
    
    triggered_alerts = []
    
    # 1. Trigger DDoS Alert (Immediate High Alert)
    if ddos_events:
        triggered_alerts.append({
            "type": "DDoS_Detected",
            "severity": "HIGH",
            "message": f"DDoS flow signature identified at {ddos_events[0][2]} UTC."
        })
        
    # 2. Trigger PortScan Spike Alert (If more than 5 PortScans in 10s)
    if len(portscan_events) >= 5:
        triggered_alerts.append({
            "type": "PortScan_Spike",
            "severity": "HIGH",
            "message": f"PortScan spike detected! {len(portscan_events)} PortScan flows registered in the last 10 seconds."
        })
        
    # 3. Trigger Multiple Attacks Alert (If more than 5 total attacks of any type in 10s)
    if total_anomalies >= 5:
        triggered_alerts.append({
            "type": "Multiple_Attacks",
            "severity": "CRITICAL",
            "message": f"Multiple attack vector flood active! {total_anomalies} distinct intrusion anomalies detected in the last 10 seconds."
        })
        
    # Determine the overall dynamic threat level
    if total_anomalies >= 5:
        threat_level = "CRITICAL"
    elif ddos_events or len(portscan_events) >= 5:
        threat_level = "HIGH"
    elif total_anomalies >= 1:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"
        
    return threat_level, triggered_alerts
