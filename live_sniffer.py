# live_sniffer.py
# Real-time network packet sniffer and flow feature extractor using Scapy (Async version)

import os
import sys
import time
import queue
import threading
import joblib
import numpy as np
from typing import Dict, Tuple

# Ensure scapy is imported cleanly
try:
    import scapy.all as scapy
except ImportError:
    print("[ERROR] Scapy package is not installed. Please run: pip install scapy")
    sys.exit(1)

# Local imports for in-memory ML inference and SQLite logging
from ml_model import predict_single, load_assets
from database import log_prediction, init_db, get_severity
from severity_engine import evaluate_threat_state
from notification_engine import dispatch_alert
from signature_engine import match_port_signature, match_payload_signature
from incident_manager import process_anomaly

# Flow aging timeouts
TIMEOUT_TCP = 30.0
TIMEOUT_UDP = 10.0
CLEANUP_INTERVAL = 1.0

# Global structures
active_flows = {}
flow_lock = threading.Lock()
features_list = None

# Async threads and queues
inference_queue = queue.Queue()
sniffer_instance = None
worker_thread = None
cleanup_thread = None
stop_sniffer_event = threading.Event()
socketio_instance = None

class NetworkFlow:
    """Tracks state and aggregates packets for a single bidirectional network flow."""
    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.matched_signature = None
        
        self.first_timestamp = time.time()
        self.last_timestamp = self.first_timestamp
        
        self.fwd_packets = []
        self.bwd_packets = []
        
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        
        self.tcp_flags = []
        self.init_win_fwd = 0
        self.init_win_bwd = 0
        self.min_seg_size_fwd = 0
        
        self.last_active_time = self.first_timestamp
        self.active_periods = []
        self.idle_periods = []
        self.is_active = True

    def add_packet(self, packet, direction: str):
        """Adds a packet to the flow and updates aggregated statistics."""
        current_time = time.time()
        pkt_len = len(packet)
        
        gap = current_time - self.last_active_time
        if gap > 1.0:
            self.idle_periods.append(gap * 1000.0)
            active_duration = self.last_active_time - self.first_timestamp if not self.active_periods else self.last_active_time - (self.first_timestamp + sum(self.idle_periods)/1000.0)
            if active_duration > 0:
                self.active_periods.append(active_duration * 1000.0)
            self.first_timestamp = current_time
            
        self.last_active_time = current_time
        self.last_timestamp = current_time
        
        ip_header_len = 20
        if packet.haslayer(scapy.IP):
            ip_header_len = packet[scapy.IP].ihl * 4

        transport_header_len = 0
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            transport_header_len = tcp_layer.dataofs * 4
            self.tcp_flags.append(str(tcp_layer.flags))
            
            if direction == "fwd" and not self.fwd_packets:
                self.init_win_fwd = tcp_layer.window
                self.min_seg_size_fwd = transport_header_len
            elif direction == "bwd" and not self.bwd_packets:
                self.init_win_bwd = tcp_layer.window
                
        elif packet.haslayer(scapy.UDP):
            transport_header_len = 8
            
        total_header_len = ip_header_len + transport_header_len
        
        if direction == "fwd":
            self.fwd_packets.append(pkt_len)
            self.fwd_timestamps.append(current_time)
            self.fwd_header_len += total_header_len
        else:
            self.bwd_packets.append(pkt_len)
            self.bwd_timestamps.append(current_time)
            self.bwd_header_len += total_header_len

        if not self.matched_signature and packet.haslayer(scapy.DNS):
            try:
                from signature_engine import inspect_dns_tunneling
                sig = inspect_dns_tunneling(packet)
                if sig:
                    self.matched_signature = sig
            except Exception:
                pass

        inspectable_ports = {80, 8080, 53, 21, 23, 25, 110, 143}
        if not self.matched_signature and packet.haslayer(scapy.Raw):
            if (self.dst_port in inspectable_ports or self.src_port in inspectable_ports):
                try:
                    raw_payload = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
                    protocol_name = "TCP" if packet.haslayer(scapy.TCP) else "UDP"
                    sig = match_payload_signature(raw_payload, protocol_name)
                    if sig:
                        self.matched_signature = sig
                except Exception:
                    pass

    def get_features(self) -> Dict[str, float]:
        """Computes and returns the 78 flow features mapping to the CICIDS2017 set."""
        duration_sec = self.last_timestamp - self.first_timestamp
        duration_ms = duration_sec * 1000.0
        duration_us = duration_sec * 1000000.0
        if duration_sec <= 0:
            duration_sec = 0.00001
            duration_us = 10.0
            
        fwd_cnt = len(self.fwd_packets)
        bwd_cnt = len(self.bwd_packets)
        total_cnt = fwd_cnt + bwd_cnt
        
        fwd_sum = sum(self.fwd_packets)
        bwd_sum = sum(self.bwd_packets)
        total_sum = fwd_sum + bwd_sum
        
        fwd_mean = np.mean(self.fwd_packets) if fwd_cnt else 0.0
        fwd_std = np.std(self.fwd_packets) if fwd_cnt else 0.0
        fwd_max = max(self.fwd_packets) if fwd_cnt else 0.0
        fwd_min = min(self.fwd_packets) if fwd_cnt else 0.0
        
        bwd_mean = np.mean(self.bwd_packets) if bwd_cnt else 0.0
        bwd_std = np.std(self.bwd_packets) if bwd_cnt else 0.0
        bwd_max = max(self.bwd_packets) if bwd_cnt else 0.0
        bwd_min = min(self.bwd_packets) if bwd_cnt else 0.0
        
        all_timestamps = sorted(self.fwd_timestamps + self.bwd_timestamps)
        flow_iats = np.diff(all_timestamps) * 1000000.0 if len(all_timestamps) > 1 else []
        fwd_iats = np.diff(self.fwd_timestamps) * 1000000.0 if len(self.fwd_timestamps) > 1 else []
        bwd_iats = np.diff(self.bwd_timestamps) * 1000000.0 if len(self.bwd_timestamps) > 1 else []
        
        all_packets = self.fwd_packets + self.bwd_packets
        flags_str = "".join(self.tcp_flags)
        
        def get_stats(periods):
            if not periods:
                return 0.0, 0.0, 0.0, 0.0
            return float(np.mean(periods)), float(np.std(periods)), float(max(periods)), float(min(periods))
            
        act_mean, act_std, act_max, act_min = get_stats(self.active_periods)
        idl_mean, idl_std, idl_max, idl_min = get_stats(self.idle_periods)

        features = {
            "Destination Port": float(self.dst_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(fwd_cnt),
            "Total Backward Packets": float(bwd_cnt),
            "Total Length of Fwd Packets": float(fwd_sum),
            "Total Length of Bwd Packets": float(bwd_sum),
            "Fwd Packet Length Max": float(fwd_max),
            "Fwd Packet Length Min": float(fwd_min),
            "Fwd Packet Length Mean": float(fwd_mean),
            "Fwd Packet Length Std": float(fwd_std),
            "Bwd Packet Length Max": float(bwd_max),
            "Bwd Packet Length Min": float(bwd_min),
            "Bwd Packet Length Mean": float(bwd_mean),
            "Bwd Packet Length Std": float(bwd_std),
            "Flow Bytes/s": float(total_sum / duration_sec),
            "Flow Packets/s": float(total_cnt / duration_sec),
            "Flow IAT Mean": float(np.mean(flow_iats) if len(flow_iats) else 0.0),
            "Flow IAT Std": float(np.std(flow_iats) if len(flow_iats) else 0.0),
            "Flow IAT Max": float(max(flow_iats) if len(flow_iats) else 0.0),
            "Flow IAT Min": float(min(flow_iats) if len(flow_iats) else 0.0),
            "Fwd IAT Total": float(sum(fwd_iats) if len(fwd_iats) else 0.0),
            "Fwd IAT Mean": float(np.mean(fwd_iats) if len(fwd_iats) else 0.0),
            "Fwd IAT Std": float(np.std(fwd_iats) if len(fwd_iats) else 0.0),
            "Fwd IAT Max": float(max(fwd_iats) if len(fwd_iats) else 0.0),
            "Fwd IAT Min": float(min(fwd_iats) if len(fwd_iats) else 0.0),
            "Bwd IAT Total": float(sum(bwd_iats) if len(bwd_iats) else 0.0),
            "Bwd IAT Mean": float(np.mean(bwd_iats) if len(bwd_iats) else 0.0),
            "Bwd IAT Std": float(np.std(bwd_iats) if len(bwd_iats) else 0.0),
            "Bwd IAT Max": float(max(bwd_iats) if len(bwd_iats) else 0.0),
            "Bwd IAT Min": float(min(bwd_iats) if len(bwd_iats) else 0.0),
            "Fwd PSH Flags": float(flags_str.count("P")),
            "Bwd PSH Flags": 0.0,
            "Fwd URG Flags": float(flags_str.count("U")),
            "Bwd URG Flags": 0.0,
            "Fwd Header Length": float(self.fwd_header_len),
            "Bwd Header Length": float(self.bwd_header_len),
            "Fwd Packets/s": float(fwd_cnt / duration_sec),
            "Bwd Packets/s": float(bwd_cnt / duration_sec),
            "Min Packet Length": float(min(all_packets) if all_packets else 0.0),
            "Max Packet Length": float(max(all_packets) if all_packets else 0.0),
            "Packet Length Mean": float(np.mean(all_packets) if all_packets else 0.0),
            "Packet Length Std": float(np.std(all_packets) if all_packets else 0.0),
            "Packet Length Variance": float(np.var(all_packets) if all_packets else 0.0),
            "FIN Flag Count": float(flags_str.count("F")),
            "SYN Flag Count": float(flags_str.count("S")),
            "RST Flag Count": float(flags_str.count("R")),
            "PSH Flag Count": float(flags_str.count("P")),
            "ACK Flag Count": float(flags_str.count("A")),
            "URG Flag Count": float(flags_str.count("U")),
            "CWR Flag Count": float(flags_str.count("C")),
            "ECE Flag Count": float(flags_str.count("E")),
            "Down/Up Ratio": float(bwd_cnt / fwd_cnt if fwd_cnt else 0.0),
            "Average Packet Size": float(total_sum / total_cnt if total_cnt else 0.0),
            "Avg Fwd Segment Size": float(fwd_mean),
            "Avg Bwd Segment Size": float(bwd_mean),
            "Fwd Header Length.1": float(self.fwd_header_len),
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(fwd_cnt),
            "Subflow Fwd Bytes": float(fwd_sum),
            "Subflow Bwd Packets": float(bwd_cnt),
            "Subflow Bwd Bytes": float(bwd_sum),
            "Init_Win_bytes_forward": float(self.init_win_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bwd),
            "act_data_pkt_fwd": float(sum(1 for p in self.fwd_packets if p > 0)),
            "min_seg_size_forward": float(self.min_seg_size_fwd),
            "Active Mean": float(act_mean),
            "Active Std": float(act_std),
            "Active Max": float(act_max),
            "Active Min": float(act_min),
            "Idle Mean": float(idl_mean),
            "Idle Std": float(idl_std),
            "Idle Max": float(idl_max),
            "Idle Min": float(idl_min)
        }
        return features

def extract_and_send_flow(flow: NetworkFlow):
    """Computes features for the finished flow, predicts threat, and logs to database."""
    if not flow.fwd_packets and not flow.bwd_packets:
        return
        
    sig = flow.matched_signature
    if not sig:
        proto_name = "TCP" if flow.protocol == 6 else "UDP"
        sig = match_port_signature(flow.dst_port, proto_name)
        
    is_signature_match = sig is not None
    
    pred = "BENIGN"
    conf = 1.0
    latency = 0.0
    imputed_count = 0
    det_method = "BEHAVIOR"
    details = ""
    severity = "LOW"
    
    if is_signature_match:
        pred = sig["attack_type"]
        severity = sig["severity"]
        det_method = "SIGNATURE"
        details = f"{sig['name']}: {sig['description']}"
        conf = 1.0
        latency = 0.0
        imputed_count = 0
    else:
        try:
            flow_features = flow.get_features()
            payload_vector = []
            for feat in features_list:
                payload_vector.append(flow_features.get(feat, 0.0))
                
            res = predict_single(payload_vector)
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
            return
            
    try:
        row_id = log_prediction(
            prediction=pred,
            confidence=float(conf),
            latency_ms=float(latency),
            imputed_count=int(imputed_count),
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            detection_method=det_method,
            details=details
        )
        
        # Broadcast via WebSockets
        if socketio_instance:
            socketio_instance.emit("new_flow", {
                "id": row_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "prediction": pred,
                "severity": severity,
                "confidence": float(conf),
                "detection_method": det_method,
                "details": details
            })
        
        if pred != "BENIGN":
            process_anomaly(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                attack_type=pred,
                severity=severity,
                dst_port=flow.dst_port
            )
            print(f"[ALERT] [{det_method}] {pred.upper()} threat detected on flow {flow.src_ip} -> {flow.dst_ip}!")
        else:
            print(f"[*] FLOW {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | Method: {det_method} | Prediction: BENIGN")
            
    except Exception as e:
        print(f"[ERROR] Ingestion logging failed: {e}")

def packet_callback(packet):
    """Processes captured packet, mapping it to bidirectional flow states."""
    if not (packet.haslayer(scapy.IP) and (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP))):
        return
        
    ip_layer = packet[scapy.IP]
    proto = ip_layer.proto
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        is_fin = bool(packet[scapy.TCP].flags & 0x01)
        is_rst = bool(packet[scapy.TCP].flags & 0x04)
    else:
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        is_fin = False
        is_rst = False
        
    flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]) + [proto])
    direction = "fwd" if (src_ip == flow_key[0][0] and src_port == flow_key[0][1]) else "bwd"
    
    with flow_lock:
        if flow_key not in active_flows:
            active_flows[flow_key] = NetworkFlow(src_ip, src_port, dst_ip, dst_port, proto)
            
        flow = active_flows[flow_key]
        flow.add_packet(packet, direction)
        
        # Flush TCP immediately on close to minimize latency
        if is_fin or is_rst:
            active_flows.pop(flow_key)
            inference_queue.put(flow)

def inference_worker_loop():
    """Worker loop consuming flows from queue and running ML predictions in the background thread."""
    while not stop_sniffer_event.is_set():
        try:
            flow = inference_queue.get(timeout=1.0)
            extract_and_send_flow(flow)
            inference_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[ERROR] Inference worker failed: {e}")

def cleanup_expired_flows_loop():
    """Periodic cleaner checking for aged flows (TCP > 30s, UDP > 10s idle) and evicting them to the queue."""
    while not stop_sniffer_event.is_set():
        time.sleep(CLEANUP_INTERVAL)
        current_time = time.time()
        
        # Heartbeat sync
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            hb_path = os.path.join(base_dir, "logs", "sniffer.heartbeat")
            os.makedirs(os.path.dirname(hb_path), exist_ok=True)
            with open(hb_path, "w") as f:
                f.write(str(current_time))
        except Exception:
            pass
            
        expired = []
        with flow_lock:
            for key, flow in list(active_flows.items()):
                timeout = TIMEOUT_TCP if flow.protocol == 6 else TIMEOUT_UDP
                if current_time - flow.last_timestamp > timeout:
                    expired.append(key)
                    
            for key in expired:
                flow = active_flows.pop(key)
                inference_queue.put(flow)

def start_sniffer_thread(interface=None):
    """Spawns AsyncSniffer, worker, and cleanup threads. Used inside Flask server."""
    global sniffer_instance, worker_thread, cleanup_thread, features_list, stop_sniffer_event
    
    if os.environ.get("RENDER"):
        print("[*] Skipping sniffer start: disabled inside cloud container sandbox.")
        return False
        
    stop_sniffer_event.clear()
    
    # Load ML assets
    try:
        load_assets()
        print("[*] Local ML assets loaded successfully.")
    except Exception as e:
        print(f"[ERROR] Could not load ML assets: {e}")
        return False
        
    if not os.path.exists("features.pkl"):
        print("[ERROR] features.pkl is missing from root.")
        return False
    features_list = joblib.load("features.pkl")
    
    # Start consumer thread
    worker_thread = threading.Thread(target=inference_worker_loop, daemon=True)
    worker_thread.start()
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_flows_loop, daemon=True)
    cleanup_thread.start()
    
    # Set default interface if none specified
    iface = interface or scapy.conf.iface
    print(f"[*] Starting AsyncSniffer on adapter: {iface}")
    
    try:
        sniffer_instance = scapy.AsyncSniffer(
            iface=iface,
            filter="ip and (tcp or udp)",
            prn=packet_callback,
            store=0
        )
        sniffer_instance.start()
        return True
    except Exception as e:
        print(f"[ERROR] AsyncSniffer failed to start: {e}")
        stop_sniffer_event.set()
        return False

def stop_sniffer_thread():
    """Gracefully terminates background sniffing threads."""
    global sniffer_instance, stop_sniffer_event
    print("[*] Stopping AsyncSniffer background threads...")
    stop_sniffer_event.set()
    
    if sniffer_instance and sniffer_instance.running:
        try:
            sniffer_instance.stop()
        except Exception:
            pass
            
    # Clean up heartbeat file
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        hb_path = os.path.join(base_dir, "logs", "sniffer.heartbeat")
        if os.path.exists(hb_path):
            os.remove(hb_path)
    except Exception:
        pass
    print("[*] Sniffer threads stopped cleanly.")

def main():
    """Executable command-line fallback (runs standalone sniffer if executed directly)."""
    # Initialize DB
    try:
        init_db()
    except Exception:
        pass
        
    success = start_sniffer_thread()
    if not success:
        sys.exit(1)
        
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        stop_sniffer_thread()
        print("[*] Exit.")

if __name__ == "__main__":
    main()
