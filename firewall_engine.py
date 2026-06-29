# firewall_engine.py
# AI-Powered Automatic IP Blocking using Windows Firewall (netsh)
# Integrates with KryptaFlow NIDS to provide real-time threat prevention.

import subprocess
import threading
import time
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────────────────
AUTO_BLOCK_ENABLED    = True       # Master switch for auto-blocking
CONFIDENCE_THRESHOLD  = 85.0      # Min ML confidence % to trigger a block
EVENT_THRESHOLD       = 5         # Min confirmed events before blocking
BLOCK_DURATION_SECS   = 3600      # Auto-unblock after 1 hour (0 = permanent)
WHITELIST             = {          # IPs that will NEVER be blocked
    "127.0.0.1",
    "::1",
    "10.75.132.51",   # Your gateway/router — auto-detected
    "10.75.132.237",  # Your own machine IP — never block yourself!
}

# ─── State ───────────────────────────────────────────────────────────────────
_blocked_ips: Dict[str, dict] = {}          # ip → {timestamp, reason, rule_name}
_block_event_counts = defaultdict(int)      # ip → confirmed event count
_lock = threading.Lock()

# ─── Firewall Rule Manager ────────────────────────────────────────────────────
def _rule_name(ip: str) -> str:
    return f"KryptaFlow_BLOCK_{ip.replace('.', '_').replace(':', '_')}"

def _add_firewall_rule(ip: str) -> bool:
    """Adds an inbound Windows Firewall block rule for the given IP."""
    rule = _rule_name(ip)
    try:
        # Block all inbound traffic from this IP
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule}",
             "dir=in",
             "action=block",
             f"remoteip={ip}",
             "enable=yes",
             "profile=any",
             "description=KryptaFlow Auto-Block: AI-confirmed threat"],
            capture_output=True, text=True, timeout=10
        )
        success = result.returncode == 0
        if success:
            logger.info(f"[FIREWALL] ✅ Blocked inbound traffic from {ip}")
        else:
            logger.warning(f"[FIREWALL] ⚠️ Failed to block {ip}: {result.stderr.strip()}")
        return success
    except Exception as e:
        logger.error(f"[FIREWALL] ❌ Error adding rule for {ip}: {e}")
        return False

def _remove_firewall_rule(ip: str) -> bool:
    """Removes the KryptaFlow block rule for the given IP."""
    rule = _rule_name(ip)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
            capture_output=True, text=True, timeout=10
        )
        success = result.returncode == 0
        if success:
            logger.info(f"[FIREWALL] 🔓 Unblocked {ip}")
        return success
    except Exception as e:
        logger.error(f"[FIREWALL] ❌ Error removing rule for {ip}: {e}")
        return False

# ─── Core Block Logic ─────────────────────────────────────────────────────────
def should_block(src_ip: str, attack_type: str, confidence: float, event_count: int) -> bool:
    """Decides whether an IP should be auto-blocked based on AI confidence and event count."""
    if not AUTO_BLOCK_ENABLED:
        return False
    if src_ip in WHITELIST:
        return False
    if src_ip in _blocked_ips:
        return False  # Already blocked
    if attack_type == "BENIGN":
        return False
    if confidence < CONFIDENCE_THRESHOLD:
        return False
    if event_count < EVENT_THRESHOLD:
        return False
    return True

def block_ip(src_ip: str, attack_type: str, confidence: float, reason: str = "") -> bool:
    """
    Blocks an IP via Windows Firewall and records it in memory.
    Returns True if the IP was successfully blocked.
    """
    if src_ip in WHITELIST:
        logger.info(f"[FIREWALL] ⛔ {src_ip} is whitelisted — skipping block.")
        return False

    with _lock:
        if src_ip in _blocked_ips:
            return False  # Already blocked

        success = _add_firewall_rule(src_ip)
        if success:
            _blocked_ips[src_ip] = {
                "ip": src_ip,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "blocked_at_ts": time.time(),
                "attack_type": attack_type,
                "confidence": confidence,
                "reason": reason or f"AI-confirmed {attack_type} (confidence: {confidence:.1f}%)",
                "rule_name": _rule_name(src_ip),
                "status": "BLOCKED"
            }
            # Schedule auto-unblock if duration > 0
            if BLOCK_DURATION_SECS > 0:
                threading.Timer(BLOCK_DURATION_SECS, unblock_ip, args=[src_ip, "auto_expired"]).start()
        return success

def unblock_ip(ip: str, reason: str = "manual") -> bool:
    """Removes a firewall block rule and removes IP from blocked list."""
    with _lock:
        success = _remove_firewall_rule(ip)
        if ip in _blocked_ips:
            del _blocked_ips[ip]
        logger.info(f"[FIREWALL] 🔓 {ip} unblocked. Reason: {reason}")
        return success

def record_event(src_ip: str) -> int:
    """Increments the confirmed-threat event counter for an IP. Returns new count."""
    with _lock:
        _block_event_counts[src_ip] += 1
        return _block_event_counts[src_ip]

# ─── Public API ───────────────────────────────────────────────────────────────
def get_blocked_ips() -> list:
    """Returns a list of all currently blocked IPs with metadata."""
    with _lock:
        return list(_blocked_ips.values())

def is_blocked(ip: str) -> bool:
    """Returns True if an IP is currently in the block list."""
    return ip in _blocked_ips

def process_threat(src_ip: str, attack_type: str, confidence: float, dst_ip: str = "") -> dict:
    """
    Main entry point called by the detection engine for every confirmed threat.
    Decides whether to block and executes it.
    Returns action result dict.
    """
    event_count = record_event(src_ip)

    if should_block(src_ip, attack_type, confidence, event_count):
        reason = (f"AI-confirmed {attack_type} | Confidence: {confidence:.1f}% | "
                  f"Events: {event_count} | Target: {dst_ip}")
        blocked = block_ip(src_ip, attack_type, confidence, reason)
        return {
            "action": "BLOCKED" if blocked else "BLOCK_FAILED",
            "ip": src_ip,
            "reason": reason,
            "event_count": event_count
        }
    elif src_ip in _blocked_ips:
        return {"action": "ALREADY_BLOCKED", "ip": src_ip, "event_count": event_count}
    else:
        return {"action": "MONITORED", "ip": src_ip, "event_count": event_count}
