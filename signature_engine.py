# signature_engine.py
# Engine for signature-based threat detection matching ports and packet payloads

import os
import json
import math
from collections import Counter, deque
from typing import Dict, Any, Optional
import scapy.all as scapy

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGNATURES_PATH = os.path.join(BASE_DIR, "signatures.json")

# In-memory signatures cache
signatures_cache = None
automaton_cache = {}  # protocol -> AhoCorasick instance

class AhoCorasick:
    def __init__(self):
        self.trie = [{}]
        self.fail = [0]
        self.out = [[]]
    
    def add_pattern(self, pattern: str, rule_index: int):
        curr = 0
        for char in pattern:
            if char not in self.trie[curr]:
                self.trie[curr][char] = len(self.trie)
                self.trie.append({})
                self.fail.append(0)
                self.out.append([])
            curr = self.trie[curr][char]
        self.out[curr].append(rule_index)
        
    def build(self):
        queue = deque()
        for char, child in self.trie[0].items():
            self.fail[child] = 0
            queue.append(child)
        while queue:
            curr = queue.popleft()
            for char, child in self.trie[curr].items():
                f = self.fail[curr]
                while f > 0 and char not in self.trie[f]:
                    f = self.fail[f]
                if char in self.trie[f]:
                    f = self.trie[f][char]
                self.fail[child] = f
                self.out[child].extend(self.out[f])
                queue.append(child)
                
    def search(self, text: str) -> Optional[int]:
        curr = 0
        for char in text:
            while curr > 0 and char not in self.trie[curr]:
                curr = self.fail[curr]
            if char in self.trie[curr]:
                curr = self.trie[curr][char]
            if self.out[curr]:
                return self.out[curr][0]
        return None

def load_signatures() -> list:
    """Loads signature rules from signatures.json and caches them."""
    global signatures_cache
    if signatures_cache is not None:
        return signatures_cache
        
    if not os.path.exists(SIGNATURES_PATH):
        # Fallback default rules if signatures.json is missing
        return [
            {"id": "SIG-001", "name": "Deprecated Telnet Connection", "type": "port", "protocol": "TCP", "port": 23, "severity": "MEDIUM", "attack_type": "PortScan", "description": "Insecure Telnet traffic detected on port 23."},
            {"id": "SIG-002", "name": "SQL Injection Attempt", "type": "payload", "protocol": "TCP", "pattern": "union select", "severity": "HIGH", "attack_type": "Web Attack", "description": "SQL Injection payload signature 'union select' detected."},
            {"id": "SIG-003", "name": "Path Traversal Attempt", "type": "payload", "protocol": "TCP", "pattern": "../", "severity": "HIGH", "attack_type": "Web Attack", "description": "Directory traversal payload signature '../' detected."},
            {"id": "SIG-004", "name": "Deprecated FTP Connection", "type": "port", "protocol": "TCP", "port": 21, "severity": "MEDIUM", "attack_type": "PortScan", "description": "Insecure FTP traffic detected on port 21."}
        ]
        
    try:
        with open(SIGNATURES_PATH, "r", encoding="utf-8") as f:
            signatures_cache = json.load(f)
            return signatures_cache
    except Exception:
        return []

def get_automaton(protocol_name: str) -> Optional[AhoCorasick]:
    """Gets or builds the Aho-Corasick search tree for the given protocol."""
    global automaton_cache
    proto = protocol_name.upper()
    if proto in automaton_cache:
        return automaton_cache[proto]
        
    rules = load_signatures()
    ac = AhoCorasick()
    has_rules = False
    for i, rule in enumerate(rules):
        if rule.get("type") == "payload" and rule.get("protocol", "").upper() == proto:
            pattern = rule.get("pattern", "").lower()
            if pattern:
                ac.add_pattern(pattern, i)
                has_rules = True
                
    if has_rules:
        ac.build()
        automaton_cache[proto] = ac
        return ac
    return None

def match_port_signature(dst_port: int, protocol_name: str) -> Optional[Dict[str, Any]]:
    """Checks if a destination port and protocol match any port signature rule."""
    rules = load_signatures()
    proto = protocol_name.upper()
    
    for rule in rules:
        if rule.get("type") == "port":
            if rule.get("port") == dst_port and rule.get("protocol", "").upper() == proto:
                return rule
                
    return None

def match_payload_signature(payload_content: str, protocol_name: str) -> Optional[Dict[str, Any]]:
    """Scans packet application payload for pattern signatures using Aho-Corasick multi-pattern search."""
    if not payload_content:
        return None
        
    ac = get_automaton(protocol_name)
    if not ac:
        return None
        
    payload_lower = payload_content.lower()
    matched_index = ac.search(payload_lower)
    if matched_index is not None:
        rules = load_signatures()
        return rules[matched_index]
        
    return None

def calculate_shannon_entropy(s: str) -> float:
    """Calculates the Shannon Entropy of a string to measure its randomness."""
    if not s:
        return 0.0
    s = s.strip(".")
    total_len = len(s)
    if total_len == 0:
        return 0.0
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / total_len
        entropy -= p * math.log2(p)
    return entropy

def inspect_dns_tunneling(packet) -> Optional[Dict[str, Any]]:
    """Inspects DNS queries for tunneling patterns (long subdomains, high entropy)."""
    if not packet.haslayer(scapy.DNS) or not packet[scapy.DNS].qd:
        return None
        
    try:
        qname = packet[scapy.DNS].qd.qname.decode("utf-8", errors="ignore").lower().strip(".")
        qtype = packet[scapy.DNS].qd.qtype
        
        # Split domain into parts
        parts = qname.split(".")
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            subdomain_len = len(subdomain)
        else:
            subdomain = qname
            subdomain_len = len(qname)
            
        entropy = calculate_shannon_entropy(subdomain)
        
        # Heuristic: Subdomain length > 40 and high entropy (> 4.2)
        # OR query is TXT type (16) with length > 25 and entropy > 3.8
        is_suspicious_dns = False
        reason = ""
        
        if subdomain_len > 40 and entropy > 4.2:
            is_suspicious_dns = True
            reason = f"High-entropy long subdomain ({subdomain_len} chars, Entropy: {entropy:.2f})"
        elif qtype == 16 and subdomain_len > 25 and entropy > 3.8:
            is_suspicious_dns = True
            reason = f"Suspicious DNS TXT query ({subdomain_len} chars, Entropy: {entropy:.2f})"
            
        if is_suspicious_dns:
            return {
                "id": "SIG-DNS-TUNNEL",
                "name": "DNS Tunneling Detected",
                "type": "payload",
                "protocol": "UDP",
                "severity": "HIGH",
                "attack_type": "Web Attack",
                "description": f"Potential DNS Tunneling: {reason} on query '{qname}'"
            }
    except Exception:
        pass
        
    return None
