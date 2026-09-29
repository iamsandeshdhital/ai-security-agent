"""
Process Monitor Module
Detects suspicious processes, unauthorized access, and malicious activity.
"""

import time
import threading
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

import psutil


@dataclass
class ProcessEvent:
    """Represents a process-related security event."""
    timestamp: float
    pid: int
    name: str
    event_type: str  # "created", "suspicious", "high_resource", "terminated"
    details: str
    threat_score: float = 0.0


@dataclass
class ProcessProfile:
    """Tracks a process's behavior over time."""
    pid: int
    name: str
    cpu_samples: List[float] = field(default_factory=list)
    memory_samples: List[float] = field(default_factory=list)
    connections_count: int = 0
    created_at: float = field(default_factory=time.time)
    threat_score: float = 0.0


class ProcessMonitor:
    """Monitors system processes for suspicious activity."""

    def __init__(self, config: dict):
        self.config = config
        self.suspicious_patterns = config.get("suspicious_patterns", [])
        self.max_cpu = config.get("max_cpu_percent", 90)
        self.max_memory = config.get("max_memory_percent", 85)
        self.auto_kill = config.get("auto_kill", False)

        # Tracking
        self.known_pids: Set[int] = set()
        self.process_profiles: Dict[int, ProcessProfile] = {}
        self.suspicious_processes: List[ProcessEvent] = []
        self._lock = threading.Lock()
        self._running = False

        # Baseline of known good processes
        self.baseline_processes: Set[str] = set()

    def start(self):
        """Start process monitoring."""
        self._running = True
        # Build baseline of currently running processes
        self._build_baseline()
        print(f"[ProcessMonitor] Started. Baseline: {len(self.baseline_processes)} known processes")

    def stop(self):
        """Stop process monitoring."""
        self._running = False
        print("[ProcessMonitor] Stopped monitoring")

    def _build_baseline(self):
        """Build baseline of known/trusted processes."""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.baseline_processes.add(proc.info['name'].lower())
                self.known_pids.add(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def check_processes(self) -> List[dict]:
        """
        Check all running processes for suspicious activity.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_pids: Set[int] = set()

        try:
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'connections', 'create_time', 'exe', 'cmdline']))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return threats

        with self._lock:
            for proc in processes:
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or "unknown"
                    current_pids.add(pid)

                    # Skip system processes (PID < 100 on Windows)
                    if pid < 100:
                        continue

                    # Check 1: New process not in baseline
                    if pid not in self.known_pids:
                        threat = self._check_new_process(proc, name, pid)
                        if threat:
                            threats.append(threat)

                    # Check 2: Suspicious name patterns
                    threat = self._check_suspicious_name(name, pid)
                    if threat:
                        threats.append(threat)

                    # Check 3: High resource usage
                    threat = self._check_resource_usage(proc, name, pid)
                    if threat:
                        threats.append(threat)

                    # Update profile
                    self._update_profile(pid, name, proc)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Check for terminated processes (potential cleanup by malware)
            terminated = self.known_pids - current_pids
            for pid in terminated:
                if pid in self.process_profiles:
                    del self.process_profiles[pid]

            self.known_pids = current_pids

        return threats

    def _check_new_process(self, proc, name: str, pid: int) -> Optional[dict]:
        """Check if a new process is suspicious."""
        name_lower = name.lower()

        # Check against suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.lower() in name_lower:
                event = ProcessEvent(
                    timestamp=time.time(),
                    pid=pid,
                    name=name,
                    event_type="suspicious",
                    details=f"New process matches suspicious pattern: '{pattern}'",
                    threat_score=0.8
                )
                self.suspicious_processes.append(event)
                return {
                    "type": "suspicious_process",
                    "severity": "high",
                    "pid": pid,
                    "name": name,
                    "details": f"Matches pattern: '{pattern}'",
                    "threat_score": 0.8,
                    "timestamp": time.time()
                }

        # Check if running from temp directory
        try:
            exe = proc.info.get('exe', '')
            if exe and ('temp' in exe.lower() or 'tmp' in exe.lower()):
                return {
                    "type": "suspicious_location",
                    "severity": "medium",
                    "pid": pid,
                    "name": name,
                    "details": f"Running from temp directory: {exe}",
                    "threat_score": 0.6,
                    "timestamp": time.time()
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return None

    def _check_suspicious_name(self, name: str, pid: int) -> Optional[dict]:
        """Check if process name matches known malicious patterns."""
        name_lower = name.lower()

        # Known malicious process names (common botnet/malware names)
        known_malicious = {
            "nc.exe", "netcat.exe", "cryptominer.exe", "xmrig.exe",
            "bot.exe", "ddos.exe", "flooder.exe", "keylogger.exe"
        }

        if name_lower in known_malicious:
            return {
                "type": "known_malware",
                "severity": "critical",
                "pid": pid,
                "name": name,
                "details": f"Known malicious process detected: {name}",
                "threat_score": 1.0,
                "timestamp": time.time()
            }

        return None

    def _check_resource_usage(self, proc, name: str, pid: int) -> Optional[dict]:
        """Check for abnormal resource consumption."""
        try:
            cpu = proc.info.get('cpu_percent', 0) or 0
            mem = proc.info.get('memory_percent', 0) or 0

            if cpu > self.max_cpu:
                return {
                    "type": "high_cpu",
                    "severity": "medium",
                    "pid": pid,
                    "name": name,
                    "details": f"High CPU usage: {cpu:.1f}%",
                    "threat_score": 0.5,
                    "timestamp": time.time()
                }

            if mem > self.max_memory:
                return {
                    "type": "high_memory",
                    "severity": "medium",
                    "pid": pid,
                    "name": name,
                    "details": f"High memory usage: {mem:.1f}%",
                    "threat_score": 0.5,
                    "timestamp": time.time()
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return None

    def _update_profile(self, pid: int, name: str, proc):
        """Update process behavior profile."""
        if pid not in self.process_profiles:
            self.process_profiles[pid] = ProcessProfile(pid=pid, name=name)

        profile = self.process_profiles[pid]
        try:
            cpu = proc.info.get('cpu_percent', 0) or 0
            mem = proc.info.get('memory_percent', 0) or 0
            profile.cpu_samples.append(cpu)
            profile.memory_samples.append(mem)

            # Keep only last 100 samples
            profile.cpu_samples = profile.cpu_samples[-100:]
            profile.memory_samples = profile.memory_samples[-100:]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def kill_process(self, pid: int) -> bool:
        """Terminate a suspicious process."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            print(f"[ProcessMonitor] Terminated process {pid} ({proc.name()})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[ProcessMonitor] Failed to kill process {pid}: {e}")
            return False

    def get_stats(self) -> dict:
        """Get current monitoring statistics."""
        return {
            "known_pids": len(self.known_pids),
            "baseline_processes": len(self.baseline_processes),
            "suspicious_detected": len(self.suspicious_processes),
            "profiles_tracked": len(self.process_profiles),
        }
