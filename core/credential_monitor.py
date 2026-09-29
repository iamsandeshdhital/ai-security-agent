"""
Credential Monitor Module
Detects credential dumping, brute force attacks, password theft, and unauthorized access.
"""

import time
import subprocess
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

import psutil


@dataclass
class CredentialEvent:
    """Represents a credential security event."""
    timestamp: float
    event_type: str  # "failed_login", "credential_dump", "brute_force", "privilege_escalation"
    details: str
    threat_score: float = 0.0


@dataclass
class LoginAttempt:
    """Tracks a login attempt."""
    timestamp: float
    username: str
    source_ip: str
    success: bool


class CredentialMonitor:
    """Monitors for credential theft, brute force, and unauthorized access."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 30)

        # Brute force thresholds
        self.max_failed_attempts = config.get("max_failed_attempts", 5)
        self.brute_force_window = config.get("brute_force_window_seconds", 300)

        # Tracking
        self.failed_attempts: deque = deque(maxlen=1000)
        self.known_users: Set[str] = set()
        self.suspicious_events: List[CredentialEvent] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Start credential monitoring."""
        self._running = True
        self._build_baseline()
        print(f"[CredentialMonitor] Started. Monitoring for brute force & credential theft")

    def stop(self):
        """Stop credential monitoring."""
        self._running = False
        print("[CredentialMonitor] Stopped")

    def _build_baseline(self):
        """Build baseline of known users."""
        try:
            result = subprocess.run(
                'net user',
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('---') and not line.startswith('User accounts'):
                    self.known_users.add(line.split()[0])
        except Exception:
            pass

    def check_credentials(self) -> List[dict]:
        """
        Check for credential attacks.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        # Check 1: Failed login attempts (brute force)
        threats.extend(self._check_failed_logins(current_time))

        # Check 2: Credential dumping attempts
        threats.extend(self._check_credential_dumping(current_time))

        # Check 3: Privilege escalation
        threats.extend(self._check_privilege_escalation(current_time))

        return threats

    def _check_failed_logins(self, current_time: float) -> List[dict]:
        """Check for brute force login attempts."""
        threats = []

        try:
            # Get recent failed login events from Windows Event Log
            result = subprocess.run(
                'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:20 /f:text /rd:true',
                shell=True, capture_output=True, text=True, timeout=15
            )

            for line in result.stdout.split('\n'):
                if 'Account Name:' in line:
                    username = line.split(':', 1)[1].strip() if ':' in line else ""
                    if username and username not in ('-', ''):
                        self.failed_attempts.append(LoginAttempt(
                            timestamp=current_time,
                            username=username,
                            source_ip="local",
                            success=False
                        ))

            # Check for brute force pattern
            with self._lock:
                # Count recent failures per user
                user_failures: Dict[str, int] = defaultdict(int)
                for attempt in self.failed_attempts:
                    if current_time - attempt.timestamp < self.brute_force_window:
                        user_failures[attempt.username] += 1

                for username, count in user_failures.items():
                    if count >= self.max_failed_attempts:
                        event = CredentialEvent(
                            timestamp=current_time,
                            event_type="brute_force",
                            details=f"Brute force detected: {count} failed logins for {username}",
                            threat_score=0.85
                        )
                        self.suspicious_events.append(event)
                        threats.append({
                            "type": "brute_force",
                            "severity": "high",
                            "username": username,
                            "details": f"{count} failed login attempts in {self.brute_force_window}s",
                            "threat_score": 0.85,
                            "timestamp": current_time
                        })

        except Exception:
            pass

        return threats

    def _check_credential_dumping(self, current_time: float) -> List[dict]:
        """Check for credential dumping attempts."""
        threats = []

        # Check for LSASS access (common credential dumping technique)
        try:
            result = subprocess.run(
                'tasklist /fi "imagename eq lsass.exe" /v',
                shell=True, capture_output=True, text=True, timeout=10
            )

            # Check for suspicious processes that might be dumping credentials
            suspicious_tools = {
                'mimikatz.exe', 'gsecdump.exe', 'pwdump.exe', 'fgdump.exe',
                'wce.exe', 'lazagne.exe', 'procdump.exe', 'processhacker.exe'
            }

            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    name = proc.info['name'].lower()
                    if name in suspicious_tools:
                        threats.append({
                            "type": "credential_dump",
                            "severity": "critical",
                            "details": f"Credential dumping tool detected: {name}",
                            "threat_score": 0.95,
                            "timestamp": current_time
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception:
            pass

        return threats

    def _check_privilege_escalation(self, current_time: float) -> List[dict]:
        """Check for privilege escalation attempts."""
        threats = []

        # Check for new admin users
        try:
            result = subprocess.run(
                'net localgroup administrators',
                shell=True, capture_output=True, text=True, timeout=10
            )

            current_admins = set()
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('---') and not line.startswith('Alias name') and not line.startswith('Comment') and not line.startswith('Members') and not line.startswith('The command completed'):
                    current_admins.add(line)

            # Check for new admin users
            new_admins = current_admins - self.known_users
            for admin in new_admins:
                threats.append({
                    "type": "privilege_escalation",
                    "severity": "high",
                    "details": f"New administrator account detected: {admin}",
                    "threat_score": 0.8,
                    "timestamp": current_time
                })

            self.known_users.update(current_admins)

        except Exception:
            pass

        return threats

    def get_stats(self) -> dict:
        """Get current credential monitoring statistics."""
        return {
            "known_users": len(self.known_users),
            "failed_attempts_tracked": len(self.failed_attempts),
            "suspicious_events": len(self.suspicious_events),
        }
