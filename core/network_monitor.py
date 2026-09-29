"""
Network Monitor Module
Detects bot attacks, port scans, DDoS, and suspicious network activity.
"""

import time
import socket
import struct
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

import psutil


@dataclass
class ConnectionEvent:
    """Represents a single network connection event."""
    timestamp: float
    remote_ip: str
    remote_port: int
    local_port: int
    status: str
    pid: Optional[int] = None


@dataclass
class IPProfile:
    """Tracks behavior profile for a single IP."""
    ip: str
    connections: deque = field(default_factory=lambda: deque(maxlen=1000))
    ports_accessed: Set[int] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    blocked: bool = False
    threat_score: float = 0.0


class NetworkMonitor:
    """Monitors network traffic for bot attacks and anomalies."""

    def __init__(self, config: dict):
        self.config = config
        self.max_connections = config.get("max_connections_per_ip", 20)
        self.port_scan_threshold = config.get("port_scan_threshold", 15)
        self.port_scan_window = config.get("port_scan_window_seconds", 60)
        self.ddos_threshold = config.get("ddos_threshold", 100)
        self.ddos_window = config.get("ddos_window_seconds", 30)
        self.whitelist: Set[str] = set(config.get("whitelist_ips", ["127.0.0.1", "::1"]))

        # IP tracking
        self.ip_profiles: Dict[str, IPProfile] = {}
        self.global_connection_times: deque = deque(maxlen=10000)

        # Statistics
        self.total_connections_checked = 0
        self.suspicious_ips_found: Set[str] = set()

        # Running state
        self._running = False
        self._lock = threading.Lock()

    def start(self):
        """Start network monitoring."""
        self._running = True
        print("[NetworkMonitor] Started monitoring network traffic")

    def stop(self):
        """Stop network monitoring."""
        self._running = False
        print("[NetworkMonitor] Stopped monitoring")

    def check_connections(self) -> List[dict]:
        """
        Check all current network connections for suspicious activity.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return threats

        with self._lock:
            for conn in connections:
                if conn.status != 'ESTABLISHED' and conn.status != 'SYN_SENT':
                    continue

                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0

                # Skip whitelisted IPs
                if remote_ip in self.whitelist:
                    continue

                # Create connection event
                event = ConnectionEvent(
                    timestamp=current_time,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    local_port=local_port,
                    status=conn.status,
                    pid=conn.pid
                )

                # Track globally
                self.global_connection_times.append(current_time)
                self.total_connections_checked += 1

                # Get or create IP profile
                if remote_ip not in self.ip_profiles:
                    self.ip_profiles[remote_ip] = IPProfile(ip=remote_ip)

                profile = self.ip_profiles[remote_ip]
                profile.connections.append(event)
                profile.ports_accessed.add(remote_port)

                # Run detection checks
                threat = self._analyze_profile(profile, current_time)
                if threat:
                    threats.append(threat)
                    self.suspicious_ips_found.add(remote_ip)

        return threats

    def _analyze_profile(self, profile: IPProfile, current_time: float) -> Optional[dict]:
        """Analyze an IP profile for threats. Returns threat dict if found."""

        # Check 1: Too many connections from same IP (DDoS / bot)
        recent_connections = [
            e for e in profile.connections
            if current_time - e.timestamp < self.ddos_window
        ]
        if len(recent_connections) > self.max_connections:
            profile.threat_score = min(1.0, profile.threat_score + 0.3)
            return {
                "type": "ddos",
                "severity": "high",
                "ip": profile.ip,
                "details": f"{len(recent_connections)} connections in {self.ddos_window}s",
                "threat_score": profile.threat_score,
                "timestamp": current_time
            }

        # Check 2: Port scan detection
        recent_ports = set()
        for e in profile.connections:
            if current_time - e.timestamp < self.port_scan_window:
                recent_ports.add(e.local_port)

        if len(recent_ports) > self.port_scan_threshold:
            profile.threat_score = min(1.0, profile.threat_score + 0.4)
            return {
                "type": "port_scan",
                "severity": "high",
                "ip": profile.ip,
                "details": f"Scanned {len(recent_ports)} ports in {self.port_scan_window}s",
                "threat_score": profile.threat_score,
                "timestamp": current_time
            }

        # Check 3: Global DDoS (many connections from multiple IPs)
        recent_global = [
            t for t in self.global_connection_times
            if current_time - t < self.ddos_window
        ]
        if len(recent_global) > self.ddos_threshold:
            return {
                "type": "global_ddos",
                "severity": "critical",
                "ip": "multiple",
                "details": f"{len(recent_global)} total connections in {self.ddos_window}s",
                "threat_score": 0.9,
                "timestamp": current_time
            }

        # Check 4: Connection to known suspicious ports
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 31337, 12345, 54321}
        for e in profile.connections:
            if e.local_port in suspicious_ports:
                profile.threat_score = min(1.0, profile.threat_score + 0.2)
                return {
                    "type": "suspicious_port",
                    "severity": "medium",
                    "ip": profile.ip,
                    "details": f"Connection to suspicious port {e.local_port}",
                    "threat_score": profile.threat_score,
                    "timestamp": current_time
                }

        return None

    def block_ip(self, ip: str) -> bool:
        """Block an IP using Windows Firewall."""
        try:
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            cmd = (
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip}'
            )
            import subprocess
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                # Also add outbound block
                cmd_out = (
                    f'netsh advfirewall firewall add rule name="{rule_name}_out" '
                    f'dir=out action=block remoteip={ip}'
                )
                subprocess.run(cmd_out, shell=True, capture_output=True, text=True)

                if ip in self.ip_profiles:
                    self.ip_profiles[ip].blocked = True
                print(f"[NetworkMonitor] Blocked IP: {ip}")
                return True
            return False
        except Exception as e:
            print(f"[NetworkMonitor] Failed to block IP {ip}: {e}")
            return False

    def get_stats(self) -> dict:
        """Get current monitoring statistics."""
        return {
            "total_connections_checked": self.total_connections_checked,
            "unique_ips_tracked": len(self.ip_profiles),
            "suspicious_ips": list(self.suspicious_ips_found),
            "blocked_ips": [ip for ip, p in self.ip_profiles.items() if p.blocked],
        }
