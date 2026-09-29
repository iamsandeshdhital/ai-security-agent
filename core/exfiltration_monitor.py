"""
Data Exfiltration Monitor Module
Detects unauthorized data transfers, large outbound connections, and data theft.
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

import psutil


@dataclass
class ExfiltrationEvent:
    """Represents a data exfiltration event."""
    timestamp: float
    event_type: str  # "large_transfer", "unusual_connection", "suspicious_process"
    details: str
    threat_score: float = 0.0


@dataclass
class IOCounter:
    """Tracks I/O counters for a process."""
    pid: int
    name: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    last_check: float = 0.0
    sent_history: deque = field(default_factory=lambda: deque(maxlen=100))


class ExfiltrationMonitor:
    """Monitors for data exfiltration and unauthorized data transfers."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 10)

        # Thresholds
        self.max_bytes_per_minute = config.get("max_bytes_per_minute", 100_000_000)  # 100MB
        self.max_connections_per_process = config.get("max_connections_per_process", 50)

        # Suspicious remote ports for exfiltration
        self.suspicious_ports: Set[int] = set(config.get("suspicious_ports", [
            4444, 5555, 6666, 7777, 8888, 9999,  # Common C2 ports
            31337, 12345, 54321,  # Backdoor ports
        ]))

        # Tracking
        self.io_counters: Dict[int, IOCounter] = {}
        self.suspicious_events: List[ExfiltrationEvent] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Start exfiltration monitoring."""
        self._running = True
        self._build_baseline()
        print(f"[ExfiltrationMonitor] Started. Monitoring for data theft")

    def stop(self):
        """Stop exfiltration monitoring."""
        self._running = False
        print("[ExfiltrationMonitor] Stopped")

    def _build_baseline(self):
        """Build baseline of current I/O counters."""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                io = proc.io_counters()
                self.io_counters[pid] = IOCounter(
                    pid=pid,
                    name=proc.info['name'],
                    bytes_sent=io.write_bytes,
                    bytes_recv=io.read_bytes,
                    last_check=time.time()
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                continue

    def check_exfiltration(self) -> List[dict]:
        """
        Check for data exfiltration attempts.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        with self._lock:
            # Check 1: Large data transfers
            threats.extend(self._check_large_transfers(current_time))

            # Check 2: Suspicious network connections
            threats.extend(self._check_suspicious_connections(current_time))

            # Check 3: Unusual process network activity
            threats.extend(self._check_process_network_activity(current_time))

        return threats

    def _check_large_transfers(self, current_time: float) -> List[dict]:
        """Check for unusually large data transfers."""
        threats = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                io = proc.io_counters()

                if pid in self.io_counters:
                    counter = self.io_counters[pid]
                    time_delta = current_time - counter.last_check
                    if time_delta < 1:
                        time_delta = 1

                    bytes_sent_delta = io.write_bytes - counter.bytes_sent
                    bytes_per_minute = (bytes_sent_delta / time_delta) * 60

                    if bytes_per_minute > self.max_bytes_per_minute:
                        event = ExfiltrationEvent(
                            timestamp=current_time,
                            event_type="large_transfer",
                            details=f"Large data transfer: {name} sending {bytes_per_minute/1_000_000:.1f} MB/min",
                            threat_score=0.7
                        )
                        self.suspicious_events.append(event)
                        threats.append({
                            "type": "large_data_transfer",
                            "severity": "high",
                            "pid": pid,
                            "name": name,
                            "details": f"Sending {bytes_per_minute/1_000_000:.1f} MB/min",
                            "threat_score": 0.7,
                            "timestamp": current_time
                        })

                    # Update counter
                    counter.bytes_sent = io.write_bytes
                    counter.bytes_recv = io.read_bytes
                    counter.last_check = current_time
                    counter.sent_history.append(bytes_sent_delta)

                else:
                    self.io_counters[pid] = IOCounter(
                        pid=pid,
                        name=name,
                        bytes_sent=io.write_bytes,
                        bytes_recv=io.read_bytes,
                        last_check=current_time
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                continue

        return threats

    def _check_suspicious_connections(self, current_time: float) -> List[dict]:
        """Check for connections to suspicious ports."""
        threats = []

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, psutil.Error):
            return threats

        for conn in connections:
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue

            remote_port = conn.raddr.port
            if remote_port in self.suspicious_ports:
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    name = proc.name() if proc else "unknown"
                except (psutil.NoSuchProcess, psutil.Error):
                    name = "unknown"

                threats.append({
                    "type": "suspicious_connection",
                    "severity": "high",
                    "pid": conn.pid,
                    "name": name,
                    "details": f"Connection to suspicious port {remote_port} from {name}",
                    "threat_score": 0.8,
                    "timestamp": current_time
                })

        return threats

    def _check_process_network_activity(self, current_time: float) -> List[dict]:
        """Check for unusual network activity from processes."""
        threats = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                # Skip system processes
                if pid < 100:
                    continue

                connections = proc.connections()
                if len(connections) > self.max_connections_per_process:
                    threats.append({
                        "type": "unusual_network_activity",
                        "severity": "medium",
                        "pid": pid,
                        "name": name,
                        "details": f"Process has {len(connections)} network connections",
                        "threat_score": 0.6,
                        "timestamp": current_time
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                continue

        return threats

    def get_stats(self) -> dict:
        """Get current exfiltration monitoring statistics."""
        return {
            "processes_tracked": len(self.io_counters),
            "suspicious_events": len(self.suspicious_events),
        }
