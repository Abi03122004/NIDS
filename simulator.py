# simulator.py
# CICIDS2017 Real-Time Network Traffic Simulator (with hybrid signature check and incident aggregation)

import os
import sys
import time
import json
import csv
import argparse
import random
import joblib

# Add project root to sys.path to ensure correct imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from ml_model import predict_single, load_assets
from database import log_prediction, init_db, get_severity
from signature_engine import match_port_signature, match_payload_signature
from incident_manager import process_anomaly
from alert_engine import AlertEngine

def load_feature_list():
    """Load the feature ordering list from features.pkl."""
    if not os.path.exists("features.pkl"):
        print("[ERROR] features.pkl is missing from the directory! Cannot map columns.")
        sys.exit(1)
    return joblib.load("features.pkl")

def get_header_mapping(csv_headers):
    """Creates a cleaned-up mapping from CSV header names to their original column names, stripping whitespace."""
    return {col.strip().lower(): col for col in csv_headers}

def csv_traffic_generator(csv_path, features_list):
    """Memory-efficient generator that reads and yields rows from a CICIDS2017 dataset CSV."""
    with open(csv_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        header_map = get_header_mapping(headers)
        
        mappings = {}
        for feat in features_list:
            clean_feat = feat.strip().lower()
            if clean_feat in header_map:
                mappings[feat] = header_map[clean_feat]
                
        for row_idx, row in enumerate(reader):
            features_payload = []
            for feat in features_list:
                orig_col = mappings.get(feat)
                if orig_col and row.get(orig_col) is not None:
                    val = row[orig_col].strip()
                    if val == "" or val.lower() in ["nan", "null", "infinity", "inf"]:
                        features_payload.append(None)
                    else:
                        try:
                            features_payload.append(float(val))
                        except ValueError:
                            features_payload.append(None)
                else:
                    features_payload.append(0.0)
                    
            # Yield simulated metadata for CSV rows
            src_ip = f"192.168.1.{random.randint(100, 200)}"
            dst_ip = "10.0.0.5"
            src_port = random.randint(49152, 65535)
            # Default to destination port from features list if available, or port 80
            dst_port = int(features_payload[0]) if features_payload[0] > 0 else 80
            protocol = 6 # Default to TCP
            payload_str = ""
            
            yield features_payload, row_idx, src_ip, dst_ip, src_port, dst_port, protocol, payload_str

def synthetic_traffic_generator(features_list):
    """Generates continuous synthetic traffic cycling through BENIGN and various attack types with realistic metadata."""
    profiles = {}
    profile_path = "synthetic_profiles.json"
    if os.path.exists(profile_path):
        try:
            with open(profile_path, "r") as f:
                profiles = json.load(f)
            print(f"[*] Loaded high-fidelity attack profiles from {profile_path}.")
        except Exception as e:
            print(f"[WARNING] Failed to load {profile_path}: {e}. Falling back to default heuristics.")
            
    # Define attack sequence cycle
    phases = [
        {"type": "BENIGN", "count": 15},
        {"type": "DDoS", "count": 10},
        {"type": "BENIGN", "count": 10},
        {"type": "PortScan", "count": 12},
        {"type": "BENIGN", "count": 15},
        {"type": "Bot", "count": 6},
        {"type": "BENIGN", "count": 10},
        {"type": "Brute Force", "count": 8},
        {"type": "DoS", "count": 10},
        {"type": "Web Attack", "count": 5}
    ]
    
    phase_idx = 0
    phase_counter = 0
    row_idx = 0
    
    # Pre-select IPs to simulate consistent attackers
    ips = {
        "DDoS_Target": "10.0.0.5",
        "PortScan_Attacker": "192.168.1.150",
        "Bot_Compromised": "192.168.1.180",
        "BruteForce_Attacker": "192.168.1.170",
        "Web_Attacker": "192.168.1.160",
        "DoS_Attacker": "192.168.1.190"
    }
    
    while True:
        current_phase = phases[phase_idx]
        attack_type = current_phase["type"]
        
        # 1. Generate flow vector
        flow = []
        if attack_type in profiles:
            base_flow = profiles[attack_type]
            for idx, val in enumerate(base_flow):
                if val is None:
                    flow.append(None)
                elif val == 0.0:
                    flow.append(0.0)
                else:
                    feat_name = features_list[idx]
                    if any(term in feat_name.lower() for term in ["port", "flags", "win", "count"]):
                        flow.append(val)
                    else:
                        noise = random.uniform(-0.01, 0.01)
                        flow.append(val * (1.0 + noise))
        else:
            # Fallback heuristics
            flow = [0.0] * len(features_list)
            if attack_type == "BENIGN":
                flow[0] = 80.0
                flow[1] = float(random.randint(50000, 150000))
                flow[2] = float(random.randint(3, 10))
                flow[3] = float(random.randint(2, 8))
                flow[4] = float(random.randint(100, 1000))
                flow[5] = float(random.randint(50, 500))
            elif attack_type == "DDoS":
                flow[0] = 80.0
                flow[1] = float(random.randint(500, 2000))
                flow[2] = float(random.randint(1000, 3000))
                flow[3] = float(random.randint(800, 2500))
            elif attack_type == "PortScan":
                flow[0] = float(random.randint(1024, 65535))
                flow[1] = float(random.randint(1, 10))
                flow[2] = 1.0
                flow[3] = 1.0
            elif attack_type == "Bot":
                flow[0] = 8080.0
                flow[1] = 600000.0
            elif attack_type == "Brute Force":
                flow[0] = 22.0
                flow[1] = float(random.randint(1000, 5000))
            elif attack_type == "Web Attack":
                flow[0] = 80.0
                flow[1] = float(random.randint(50000, 100000))
                
        # 2. Generate Metadata (IPs, Ports, Payload)
        src_ip = f"192.168.1.{random.randint(2, 50)}"
        dst_ip = "10.0.0.5"
        src_port = random.randint(49152, 65535)
        dst_port = int(flow[0]) if flow[0] > 0 else 80
        protocol = 6 # TCP
        payload_str = ""
        
        if attack_type == "BENIGN":
            # standard normal traffic
            if random.random() < 0.15:
                # Occasional insecure connection to trigger signatures!
                dst_port = 23 # Telnet signature
            elif random.random() < 0.10:
                dst_port = 21 # FTP signature
        elif attack_type == "DDoS":
            # spoofed random external IPs flooding target
            src_ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_port = 80
        elif attack_type == "PortScan":
            src_ip = ips["PortScan_Attacker"]
            # Target random changing ports sequentially to trigger scan signatures
            dst_port = random.randint(1024, 9000)
        elif attack_type == "Bot":
            src_ip = ips["Bot_Compromised"]
            dst_ip = "8.8.8.8"
            dst_port = 8080
        elif attack_type == "Brute Force":
            src_ip = ips["BruteForce_Attacker"]
            dst_port = 22 # SSH
        elif attack_type == "Web Attack":
            src_ip = ips["Web_Attacker"]
            dst_port = 80
            # Inject SQL injection or Path Traversal payloads to trigger signatures!
            if random.random() < 0.5:
                payload_str = "SELECT * FROM users WHERE username = 'admin' UNION SELECT password FROM users --"
            else:
                payload_str = "GET /index.php?file=../../../../etc/passwd HTTP/1.1"
                
        yield flow, row_idx, src_ip, dst_ip, src_port, dst_port, protocol, payload_str
        
        row_idx += 1
        phase_counter += 1
        if phase_counter >= current_phase["count"]:
            phase_counter = 0
            phase_idx = (phase_idx + 1) % len(phases)

def run_simulator():
    parser = argparse.ArgumentParser(description="CICIDS2017 Real-Time Network Traffic Simulator")
    parser.add_argument("--csv", type=str, default=None, help="Path to CICIDS2017 dataset CSV file")
    parser.add_argument("--speed", type=int, choices=[1, 10, 100], default=1, 
                        help="Simulation speed: 1 (1 packet/s), 10 (10 packets/s), 100 (100 packets/s)")
    args = parser.parse_args()
    
    features_list = load_feature_list()
    alert_engine = AlertEngine(window_size_seconds=5.0, count_threshold=5)
    
    try:
        load_assets()
        print("[*] Successfully loaded RandomForest classifier locally for simulation!")
    except Exception as e:
        print(f"[ERROR] Could not load local model assets: {e}")
        sys.exit(1)
        
    try:
        init_db()
        print("[*] Local database initialized and verified.")
    except Exception as e:
        print(f"[WARNING] Database check failed: {e}")
        
    if args.csv:
        if not os.path.exists(args.csv):
            print(f"[ERROR] CSV file not found: {args.csv}")
            sys.exit(1)
        print(f"[*] Starting Traffic Simulator in CSV mode reading from: {args.csv}")
        traffic_source = csv_traffic_generator(args.csv, features_list)
    else:
        print("[*] No CSV file provided. Starting Traffic Simulator in SYNTHETIC fallback mode.")
        print("[*] The simulator will cycle through normal traffic and periodic attacks.")
        traffic_source = synthetic_traffic_generator(features_list)
        
    delay = 1.0 / args.speed
    print(f"[*] Simulation running at {args.speed} packet(s)/sec (delay: {delay:.3f}s). Press Ctrl+C to stop.\n")
    
    try:
        for flow_vector, idx, src_ip, dst_ip, src_port, dst_port, protocol, payload_str in traffic_source:
            # 1. Check for signatures
            sig = None
            if payload_str:
                sig = match_payload_signature(payload_str, "TCP")
            if not sig:
                sig = match_port_signature(dst_port, "TCP")
                
            is_signature_match = sig is not None
            
            pred = "BENIGN"
            conf = 1.0
            latency = 0.0
            imputed_count = 0
            det_method = "BEHAVIOR"
            details = ""
            severity = "LOW"
            class_probabilities = {"BENIGN": 1.0}
            
            if is_signature_match:
                pred = sig["attack_type"]
                severity = sig["severity"]
                det_method = "SIGNATURE"
                details = f"{sig['name']}: {sig['description']}"
                conf = 1.0
                latency = 0.0
                imputed_count = 0
                class_probabilities = {pred: 1.0}
            else:
                # 2. Run RandomForest behavior checks
                try:
                    res = predict_single(flow_vector)
                    pred = res["prediction"]
                    class_probabilities = res["class_probabilities"]
                    conf = class_probabilities.get(pred, 1.0)
                    latency = res["latency_ms"]
                    imputed_count = res["imputed_count"]
                    det_method = "BEHAVIOR"
                    details = f"Behavioral Anomaly (Conf: {conf:.2%})"
                    severity = get_severity(pred)
                except Exception as e:
                    print(f"[ERROR] Local flow classification failed: {e}")
                    continue
            
            # 3. Log to SQLite
            try:
                log_prediction(
                    prediction=pred,
                    confidence=float(conf),
                    latency_ms=float(latency),
                    imputed_count=int(imputed_count),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    detection_method=det_method,
                    details=details
                )
                
                # 4. Trigger alert aggregator (Incident manager) for malicious events
                if pred != "BENIGN":
                    process_anomaly(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        attack_type=pred,
                        severity=severity,
                        dst_port=dst_port
                    )
                
                # Print status
                alert_engine.process_prediction(pred, class_probabilities)
                
            except Exception as e:
                print(f"[ERROR] Ingestion logging failed: {e}")
                
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\n[*] Traffic simulation stopped by user.")

if __name__ == "__main__":
    run_simulator()
