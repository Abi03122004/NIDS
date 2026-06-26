# database.py
# Database access layer for storing and querying IDS flow predictions, incidents, and users in SQLite

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "logs", "ids_predictions.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

def get_severity(prediction: str) -> str:
    """Maps predicted intrusion class to a standardized severity level."""
    if prediction == "BENIGN":
        return "LOW"
    elif prediction in ["DoS", "DDoS", "PortScan"]:
        return "HIGH"
    elif prediction in ["Bot", "Brute Force", "Web Attack"]:
        return "MEDIUM"
    return "UNKNOWN"

def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Establishes connection to SQLite with row factory and timeout configurations."""
    dir_name = os.path.dirname(db_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
        
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DB_PATH, schema_path: str = SCHEMA_PATH):
    """Initializes the database schema and configures performance optimizations (WAL mode)."""
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found at: {schema_path}")
        
    with get_connection(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_ddl = f.read()
        conn.executescript(schema_ddl)
        conn.commit()

def log_prediction(
    prediction: str,
    confidence: float,
    latency_ms: float,
    imputed_count: int,
    src_ip: str = "127.0.0.1",
    dst_ip: str = "127.0.0.1",
    src_port: int = 0,
    dst_port: int = 0,
    protocol: int = 0,
    detection_method: str = "BEHAVIOR",
    details: str = "",
    timestamp: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """Persists a single flow prediction record to SQLite with IP details and detection method."""
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
        
    severity = get_severity(prediction)
    
    query = """
    INSERT INTO predictions (
        timestamp, prediction, confidence, severity, latency_ms, imputed_count,
        src_ip, dst_ip, src_port, dst_port, protocol, detection_method, details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (
            timestamp, prediction, confidence, severity, latency_ms, imputed_count,
            src_ip, dst_ip, src_port, dst_port, protocol, detection_method, details
        ))
        conn.commit()
        return cursor.lastrowid

def log_predictions_batch(
    predictions_list: List[Dict[str, Any]],
    db_path: str = DB_PATH
) -> int:
    """Persists a list of prediction records to SQLite in a single transaction."""
    now_str = datetime.now(timezone.utc).isoformat()
    
    records_to_insert = []
    for item in predictions_list:
        ts = item.get("timestamp") or now_str
        pred = item["prediction"]
        conf = item["confidence"]
        lat = item["latency_ms"]
        imp = item["imputed_count"]
        sev = get_severity(pred)
        
        src_ip = item.get("src_ip", "127.0.0.1")
        dst_ip = item.get("dst_ip", "127.0.0.1")
        src_port = item.get("src_port", 0)
        dst_port = item.get("dst_port", 0)
        proto = item.get("protocol", 0)
        det_method = item.get("detection_method", "BEHAVIOR")
        details = item.get("details", "")
        
        records_to_insert.append((
            ts, pred, conf, sev, lat, imp,
            src_ip, dst_ip, src_port, dst_port, proto, det_method, details
        ))
        
    query = """
    INSERT INTO predictions (
        timestamp, prediction, confidence, severity, latency_ms, imputed_count,
        src_ip, dst_ip, src_port, dst_port, protocol, detection_method, details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.executemany(query, records_to_insert)
        conn.commit()
        return cursor.rowcount

def get_history(
    limit: int = 100,
    offset: int = 0,
    prediction: Optional[str] = None,
    severity: Optional[str] = None,
    db_path: str = DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieves sorted, paginated records with detailed IP metadata."""
    query = """
    SELECT id, timestamp, prediction, confidence, severity, latency_ms, imputed_count,
           src_ip, dst_ip, src_port, dst_port, protocol, detection_method, details
    FROM predictions
    """
    conditions = []
    params = []
    
    if prediction:
        conditions.append("prediction = ?")
        params.append(prediction)
        
    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def get_statistics(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Computes aggregated traffic metrics, hybrid methods breakdown, and top attacker IPs."""
    stats = {
        "total_records": 0,
        "class_distribution": {},
        "severity_distribution": {},
        "average_latency_ms": 0.0,
        "total_imputed_features": 0,
        "attacks_last_hour": 0,
        "first_record_time": None,
        "last_record_time": None,
        "detection_method_breakdown": {"BEHAVIOR": 0, "SIGNATURE": 0},
        "top_attackers": [] # List of {"src_ip": str, "count": int}
    }
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Total records and min/max timestamps
        cursor.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM predictions")
        total, min_ts, max_ts = cursor.fetchone()
        stats["total_records"] = total
        stats["first_record_time"] = min_ts
        stats["last_record_time"] = max_ts
        
        if total == 0:
            return stats
            
        # 2. Prediction class breakdown
        cursor.execute("SELECT prediction, COUNT(*) FROM predictions GROUP BY prediction")
        stats["class_distribution"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 3. Severity breakdown
        cursor.execute("SELECT severity, COUNT(*) FROM predictions GROUP BY severity")
        stats["severity_distribution"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 4. Average latency
        cursor.execute("SELECT AVG(latency_ms) FROM predictions")
        avg_lat = cursor.fetchone()[0]
        stats["average_latency_ms"] = float(avg_lat) if avg_lat is not None else 0.0
        
        # 5. Total imputed features
        cursor.execute("SELECT SUM(imputed_count) FROM predictions")
        sum_imp = cursor.fetchone()[0]
        stats["total_imputed_features"] = int(sum_imp) if sum_imp is not None else 0
        
        # 6. Attack rate in the last hour
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM predictions WHERE prediction != 'BENIGN' AND timestamp >= ?",
            (one_hour_ago,)
        )
        stats["attacks_last_hour"] = cursor.fetchone()[0]
        
        # 7. Detection method breakdown
        cursor.execute("SELECT detection_method, COUNT(*) FROM predictions GROUP BY detection_method")
        for row in cursor.fetchall():
            stats["detection_method_breakdown"][row[0]] = row[1]
            
        # 8. Top 5 attacking IPs (excluding BENIGN predictions)
        cursor.execute("""
            SELECT src_ip, COUNT(*) as cnt 
            FROM predictions 
            WHERE prediction != 'BENIGN' 
            GROUP BY src_ip 
            ORDER BY cnt DESC 
            LIMIT 5
        """)
        stats["top_attackers"] = [{"src_ip": row[0], "count": row[1]} for row in cursor.fetchall()]
        
    return stats

# =============================================================
# INCIDENT AGGREGATION QUERIES
# =============================================================

def get_active_incident_by_ip_and_type(
    src_ip: str, 
    attack_type: str, 
    threshold_seconds: float = 15.0,
    db_path: str = DB_PATH
) -> Optional[Dict[str, Any]]:
    """Finds a recently updated active incident matching the source IP and attack type."""
    query = """
    SELECT id, start_time, last_update, src_ip, dst_ip, attack_type, event_count, severity, status, notified
    FROM incidents
    WHERE src_ip = ? AND attack_type = ? AND status = 'ACTIVE'
    ORDER BY last_update DESC LIMIT 1
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (src_ip, attack_type))
        row = cursor.fetchone()
        if not row:
            return None
            
        incident = dict(row)
        # Check if the incident's last update is within the threshold window
        last_dt = datetime.fromisoformat(incident["last_update"])
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
            
        now_dt = datetime.now(timezone.utc)
        if (now_dt - last_dt).total_seconds() <= threshold_seconds:
            return incident
            
    return None

def create_incident(
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    severity: str,
    timestamp: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """Inserts a new active incident into SQLite."""
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
        
    query = """
    INSERT INTO incidents (start_time, last_update, src_ip, dst_ip, attack_type, event_count, severity, status, notified)
    VALUES (?, ?, ?, ?, ?, 1, ?, 'ACTIVE', 0);
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (timestamp, timestamp, src_ip, dst_ip, attack_type, severity))
        conn.commit()
        return cursor.lastrowid

def update_incident(
    incident_id: int,
    event_count: int,
    notified: int,
    timestamp: Optional[str] = None,
    db_path: str = DB_PATH
):
    """Updates the event count, notification status, and last update timestamp of an incident."""
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
        
    query = """
    UPDATE incidents
    SET event_count = ?, notified = ?, last_update = ?
    WHERE id = ?
    """
    with get_connection(db_path) as conn:
        conn.execute(query, (event_count, notified, timestamp, incident_id))
        conn.commit()

def resolve_stale_incidents(timeout_seconds: float = 30.0, db_path: str = DB_PATH) -> int:
    """Resolves active incidents that have had no events in the last timeout_seconds."""
    now_dt = datetime.now(timezone.utc)
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, last_update FROM incidents WHERE status = 'ACTIVE'")
        active_rows = cursor.fetchall()
        
        stale_ids = []
        for row in active_rows:
            inc_id, last_update_str = row[0], row[1]
            last_dt = datetime.fromisoformat(last_update_str)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
                
            if (now_dt - last_dt).total_seconds() > timeout_seconds:
                stale_ids.append(inc_id)
                
        if stale_ids:
            placeholders = ",".join("?" for _ in stale_ids)
            conn.execute(
                f"UPDATE incidents SET status = 'RESOLVED' WHERE id IN ({placeholders})",
                stale_ids
            )
            conn.commit()
            return len(stale_ids)
            
    return 0

def get_incidents(status: str, limit: int = 50, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves list of incidents matching a specific status (ACTIVE or RESOLVED)."""
    query = """
    SELECT id, start_time, last_update, src_ip, dst_ip, attack_type, event_count, severity, status, notified
    FROM incidents
    WHERE status = ?
    ORDER BY last_update DESC
    LIMIT ?
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (status, limit))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
