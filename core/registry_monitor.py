"""
Registry Monitor Module
Detects unauthorized registry modifications, persistence mechanisms, and configuration changes.
"""

import time
import threading
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RegistryEvent:
    """Represents a registry security event."""
    timestamp: float
    event_type: str  # "modified", "created", "deleted", "suspicious"
    key_path: str
    value_name: str
    details: str
    threat_score: float = 0.0


@dataclass
class RegistryKeyProfile:
    """Tracks a registry key's state."""
    key_path: str
    value_name: str
    last_value: Optional[str]
    first_seen: float
    modified_count: int = 0
    threat_score: float = 0.0


class RegistryMonitor:
    """Monitors Windows Registry for unauthorized modifications."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 30)

        # Critical registry paths to monitor
        self.critical_paths = config.get("critical_paths", [
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot",
        ])

        # Suspicious registry values (persistence mechanisms)
        self.suspicious_patterns = config.get("suspicious_patterns", [
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "mshta",
            "wscript",
            "cscript",
            "certutil",
            "bitsadmin",
            "regsvr32",
        ])

        # Tracking
        self.key_profiles: Dict[str, RegistryKeyProfile] = {}
        self.suspicious_events: List[RegistryEvent] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Start registry monitoring."""
        self._running = True
        self._build_baseline()
        print(f"[RegistryMonitor] Started. Monitoring {len(self.critical_paths)} critical paths")

    def stop(self):
        """Stop registry monitoring."""
        self._running = False
        print("[RegistryMonitor] Stopped")

    def _build_baseline(self):
        """Build baseline of current registry state."""
        try:
            import winreg
        except ImportError:
            return

        for path in self.critical_paths:
            try:
                # Parse the path
                parts = path.split("\\")
                root_name = parts[0]
                sub_path = "\\".join(parts[1:])

                # Get root key
                root = self._get_root_key(root_name)
                if root is None:
                    continue

                # Open the key
                key = winreg.OpenKey(root, sub_path, 0, winreg.KEY_READ)
                self._scan_key(key, path)
                winreg.CloseKey(key)

            except (PermissionError, OSError):
                continue

    def _get_root_key(self, name: str):
        """Convert root key name to winreg constant."""
        import winreg
        roots = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS": winreg.HKEY_USERS,
        }
        return roots.get(name)

    def _scan_key(self, key, path: str):
        """Scan a registry key and its values."""
        import winreg

        try:
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    profile_key = f"{path}\\{value_name}"

                    self.key_profiles[profile_key] = RegistryKeyProfile(
                        key_path=path,
                        value_name=value_name,
                        last_value=str(value_data),
                        first_seen=time.time()
                    )
                    i += 1
                except OSError:
                    break
        except Exception:
            pass

    def check_registry(self) -> List[dict]:
        """
        Check registry for unauthorized modifications.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        try:
            import winreg
        except ImportError:
            return threats

        with self._lock:
            for path in self.critical_paths:
                try:
                    parts = path.split("\\")
                    root_name = parts[0]
                    sub_path = "\\".join(parts[1:])

                    root = self._get_root_key(root_name)
                    if root is None:
                        continue

                    key = winreg.OpenKey(root, sub_path, 0, winreg.KEY_READ)
                    threats.extend(self._check_key(key, path, current_time))
                    winreg.CloseKey(key)

                except (PermissionError, OSError):
                    continue

        return threats

    def _check_key(self, key, path: str, current_time: float) -> List[dict]:
        """Check a single registry key for changes."""
        import winreg

        threats = []
        current_values = {}

        try:
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    current_values[value_name] = str(value_data)
                    profile_key = f"{path}\\{value_name}"

                    # Check 1: New value created
                    if profile_key not in self.key_profiles:
                        threat = self._check_suspicious_value(
                            path, value_name, str(value_data), current_time
                        )
                        if threat:
                            threats.append(threat)

                        self.key_profiles[profile_key] = RegistryKeyProfile(
                            key_path=path,
                            value_name=value_name,
                            last_value=str(value_data),
                            first_seen=current_time
                        )

                    # Check 2: Existing value modified
                    else:
                        profile = self.key_profiles[profile_key]
                        if profile.last_value != str(value_data):
                            threat = self._check_suspicious_value(
                                path, value_name, str(value_data), current_time
                            )
                            if threat:
                                threats.append(threat)

                            profile.last_value = str(value_data)
                            profile.modified_count += 1
                            profile.threat_score = min(1.0, profile.threat_score + 0.2)

                    i += 1
                except OSError:
                    break

            # Check 3: Values deleted
            for profile_key, profile in list(self.key_profiles.items()):
                if profile.key_path == path and profile.value_name not in current_values:
                    event = RegistryEvent(
                        timestamp=current_time,
                        event_type="deleted",
                        key_path=path,
                        value_name=profile.value_name,
                        details=f"Registry value deleted: {path}\\{profile.value_name}",
                        threat_score=0.4
                    )
                    self.suspicious_events.append(event)
                    del self.key_profiles[profile_key]

        except Exception:
            pass

        return threats

    def _check_suspicious_value(self, path: str, value_name: str, value_data: str, current_time: float) -> Optional[dict]:
        """Check if a registry value is suspicious."""
        value_lower = value_data.lower()
        name_lower = value_name.lower()

        # Check for suspicious patterns in value data
        for pattern in self.suspicious_patterns:
            if pattern.lower() in value_lower:
                event = RegistryEvent(
                    timestamp=current_time,
                    event_type="suspicious",
                    key_path=path,
                    value_name=value_name,
                    details=f"Suspicious registry value: {path}\\{value_name} = {value_data[:100]}",
                    threat_score=0.7
                )
                self.suspicious_events.append(event)
                return {
                    "type": "suspicious_registry",
                    "severity": "high",
                    "key_path": path,
                    "value_name": value_name,
                    "details": f"Suspicious pattern '{pattern}' in {path}\\{value_name}",
                    "threat_score": 0.7,
                    "timestamp": current_time
                }

        # Check for persistence in Run keys
        if "run" in path.lower() and value_data:
            event = RegistryEvent(
                timestamp=current_time,
                event_type="persistence",
                key_path=path,
                value_name=value_name,
                details=f"New startup item: {path}\\{value_name} = {value_data[:100]}",
                threat_score=0.6
            )
            self.suspicious_events.append(event)
            return {
                "type": "persistence_mechanism",
                "severity": "high",
                "key_path": path,
                "value_name": value_name,
                "details": f"New startup item: {value_data[:100]}",
                "threat_score": 0.6,
                "timestamp": current_time
            }

        return None

    def get_stats(self) -> dict:
        """Get current registry monitoring statistics."""
        return {
            "critical_paths_monitored": len(self.critical_paths),
            "keys_tracked": len(self.key_profiles),
            "suspicious_events": len(self.suspicious_events),
        }
