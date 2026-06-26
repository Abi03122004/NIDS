# live_sniffer.py
# Real-time network packet sniffer and flow feature extractor using Scapy

import os
import sys
import time
import argparse
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
from ml_model import predict_single
from database import log_prediction, init_db, get_severity
from severity_engine import evaluate_threat_state
from notification_engine import dispatch_alert
from signature_engine import match_port_signature, match_payload_signature
from incident_manager import process_anomaly

# Configuration settings
TIMEOUT_FLOW = 5.0  # Seconds of inactivity before flushing a flow
CLEANUP_INTERVAL = 1.0  # How often to check for timed-out flows

# Global structures to track active flows
active_flows = {}
flow_lock = threading.Lock()
features_list = None
stop_sniffing = False

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
        
        # Directions: Forward is src_ip -> dst_ip, Backward is dst_ip -> src_ip
        self.fwd_packets = []  # List of sizes (int)
        self.bwd_packets = []  # List of sizes (int)
        
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        
        self.tcp_flags = []
        self.init_win_fwd = 0
        self.init_win_bwd = 0
        self.min_seg_size_fwd = 0
        
        # Idle/Active calculation
        self.last_active_time = self.first_timestamp
        self.active_periods = []
        self.idle_periods = []
        self.is_active = True

    def add_packet(self, packet, direction: str):
        """Adds a packet to the flow and updates aggregated statistics."""
        current_time = time.time()
        pkt_len = len(packet)
        
        # Idle/Active times detection (1.0s gap threshold)
        gap = current_time - self.last_active_time
        if gap > 1.0:
            # We had an idle period
            self.idle_periods.append(gap * 1000.0)  # Store in ms
            active_duration = self.last_active_time - self.first_timestamp if not self.active_periods else self.last_active_time - (self.first_timestamp + sum(self.idle_periods)/1000.0)
            if active_duration > 0:
                self.active_periods.append(active_duration * 1000.0)
            self.first_timestamp = current_time  # Reset base for next active calculation
            
        self.last_active_time = current_time
        self.last_timestamp = current_time
        
        # Extract IP header length
        ip_header_len = 20
        if packet.haslayer(scapy.IP):
            ip_header_len = packet[scapy.IP].ihl * 4

        # Extract Transport Layer Info
        transport_header_len = 0
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            transport_header_len = tcp_layer.dataofs * 4
            self.tcp_flags.append(str(tcp_layer.flags))
            
            # Check Initial Window Bytes
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

        # Check DNS tunneling signature (if not already matched)
        if not self.matched_signature and packet.haslayer(scapy.DNS):
            try:
                from signature_engine import inspect_dns_tunneling
                sig = inspect_dns_tunneling(packet)
                if sig:
                    self.matched_signature = sig
            except Exception:
                pass

        # Check payload signature (if not already matched, only on unencrypted / inspectable ports)
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
        duration_us = duration_sec * 1000000.0  # Flow Duration in microseconds
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
        
        # Inter-arrival times (IAT)
        all_timestamps = sorted(self.fwd_timestamps + self.bwd_timestamps)
        flow_iats = np.diff(all_timestamps) * 1000000.0 if len(all_timestamps) > 1 else []
        fwd_iats = np.diff(self.fwd_timestamps) * 1000000.0 if len(self.fwd_timestamps) > 1 else []
        bwd_iats = np.diff(self.bwd_timestamps) * 1000000.0 if len(self.bwd_timestamps) > 1 else []
        
        all_packets = self.fwd_packets + self.bwd_packets
        
        # Calculate TCP Flags counts
        flags_str = "".join(self.tcp_flags)
        
        # Helper to compute Active/Idle statistics
        def get_stats(periods):
            if not periods:
                return 0.0, 0.0, 0.0, 0.0
            return float(np.mean(periods)), float(np.std(periods)), float(max(periods)), float(min(periods))
            
        act_mean, act_std, act_max, act_min = get_stats(self.active_periods)
        idl_mean, idl_std, idl_max, idl_min = get_stats(self.idle_periods)

        # Build feature dictionary
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
            "Bwd PSH Flags": 0.0,  # Rarely tracked separately in flows
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
    """Computes features for the finished flow, predicts threat locally, and logs to database."""
    # Ensure the flow has packets to avoid dividing empty lists
    if not flow.fwd_packets and not flow.bwd_packets:
        return
        
    # 1. Check for signatures (Payload signatures checked during add_packet; check Port signatures now)
    sig = flow.matched_signature
    if not sig:
        proto_name = "TCP" if flow.protocol == 6 else "UDP"
        sig = match_port_signature(flow.dst_port, proto_name)
        
    is_signature_match = sig is not None
    
    # Initialize variables for prediction/logging
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
        # 2. Run Random Forest Behavioral Engine if no signature matches
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
            
    # 3. Log to SQLite directly
    try:
        log_prediction(
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
        
        # 4. Aggregate anomaly into an incident and trigger notifications (if non-BENIGN)
        if pred != "BENIGN":
            process_anomaly(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                attack_type=pred,
                severity=severity,
                dst_port=flow.dst_port
            )
            
        # Print status to terminal
        if pred == "BENIGN":
            print(f"[*] FLOW {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | Method: {det_method} | Prediction: BENIGN")
        else:
            print(f"[ALERT] [{det_method}] {pred.upper()} threat detected on flow {flow.src_ip} -> {flow.dst_ip}!")
            
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
        
    # Generate a bidirectional flow key (sorted IPs and ports to group fwd/bwd packets together)
    flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]) + [proto])
    
    direction = "fwd" if (src_ip == flow_key[0][0] and src_port == flow_key[0][1]) else "bwd"
    
    with flow_lock:
        if flow_key not in active_flows:
            # Create new flow (dst_port should generally be the server destination port)
            active_flows[flow_key] = NetworkFlow(src_ip, src_port, dst_ip, dst_port, proto)
            
        flow = active_flows[flow_key]
        flow.add_packet(packet, direction)
        
        # If TCP flow is closed (FIN or RST), flush it immediately for fast analysis
        if is_fin or is_rst:
            active_flows.pop(flow_key)
            threading.Thread(target=extract_and_send_flow, args=(flow,), daemon=True).start()

def cleanup_expired_flows():
    """Background thread that flushes flows that haven't received packets for TIMEOUT_FLOW seconds."""
    global stop_sniffing
    while not stop_sniffing:
        time.sleep(CLEANUP_INTERVAL)
        current_time = time.time()
        
        # Write heartbeat timestamp to file
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            hb_path = os.path.join(base_dir, "logs", "sniffer.heartbeat")
            os.makedirs(os.path.dirname(hb_path), exist_ok=True)
            with open(hb_path, "w") as f:
                f.write(str(current_time))
        except Exception:
            pass
            
        # Check for stop signal file
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            stop_path = os.path.join(base_dir, "logs", "sniffer.stop")
            if os.path.exists(stop_path):
                print("[*] Stop signal detected. Exiting sniffer...")
                stop_sniffing = True
                try:
                    os.remove(stop_path)
                except Exception:
                    pass
                # Delete heartbeat file on clean exit
                try:
                    os.remove(hb_path)
                except Exception:
                    pass
                os._exit(0)
        except Exception:
            pass

        expired = []
        with flow_lock:
            for key, flow in active_flows.items():
                if current_time - flow.last_timestamp > TIMEOUT_FLOW:
                    expired.append(key)
                    
            for key in expired:
                flow = active_flows.pop(key)
                threading.Thread(target=extract_and_send_flow, args=(flow,), daemon=True).start()

def main():
    global features_list, stop_sniffing
    
    parser = argparse.ArgumentParser(description="Live Real-time NIDS Network Packet Sniffer")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on (e.g. Wi-Fi, Ethernet)")
    args = parser.parse_args()
    
    # Load features list
    if not os.path.exists("features.pkl"):
        print("[ERROR] features.pkl is missing from directory. Cannot map flow vectors correctly.")
        sys.exit(1)
    features_list = joblib.load("features.pkl")
    
    # Check Npcap on Windows
    if sys.platform.startswith("win"):
        # Scapy uses conf.use_pcap to detect pcap availability
        if not scapy.conf.use_pcap:
            print(
                "[WARNING] Npcap/WinPcap does not appear to be installed on your Windows device.\n"
                "To capture live network traffic, please download and install Npcap from: https://npcap.com/\n"
                "If it's already installed, try running your command line as Administrator.\n"
            )
            
    # Start cleanup background thread
    cleanup_thread = threading.Thread(target=cleanup_expired_flows, daemon=True)
    cleanup_thread.start()
    
    # Verify local ML assets
    try:
        from ml_model import load_assets
        load_assets()
        print("[*] Successfully loaded RandomForest classifier locally! Model is online.")
    except Exception as e:
        print(f"[ERROR] Could not load local model assets: {e}")
        sys.exit(1)
        
    # Verify database initialization
    try:
        init_db()
        print("[*] Local database initialized and verified.")
    except Exception as e:
        print(f"[WARNING] Database check failed: {e}")
        
    interface = args.iface or scapy.conf.iface
    print(f"[*] Starting live packet sniffing on adapter: {interface}")
    print("[*] Capturing TCP/UDP packets. Press Ctrl+C to stop...\n")
    
    try:
        # Sniff packets continuously
        scapy.sniff(iface=interface, filter="ip and (tcp or udp)", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] An error occurred during packet capture: {e}")
        print("Please run your terminal as Administrator/root if you encountered a permissions error.")
    finally:
        stop_sniffing = True

if __name__ == "__main__":
    main()
