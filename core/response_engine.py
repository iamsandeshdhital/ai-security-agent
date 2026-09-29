"""
Response Engine Module
Automatically responds to detected threats with configurable actions.
"""

import os
import time
import subprocess
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ResponseAction:
    """Represents a response action taken."""
    timestamp: float
    action_type: str
    target: str
    success: bool
    details: str


class ResponseEngine:
    """Automatically responds to security threats."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)

        # Action mappings
        self.action_map = {
            "port_scan": config.get("on_port_scan", ["log", "alert"]),
            "ddos": config.get("on_ddos", ["log", "alert", "block_ip"]),
            "global_ddos": config.get("on_ddos", ["log", "alert", "block_ip"]),
            "suspicious_process": config.get("on_suspicious_process", ["log", "alert"]),
            "known_malware": config.get("on_suspicious_process", ["log", "alert", "kill_process"]),
            "behavioral_anomaly": config.get("on_anomaly", ["log", "alert"]),
            "ransomware_pattern": config.get("on_anomaly", ["log", "alert"]),
            "mass_modification": config.get("on_anomaly", ["log", "alert"]),
            "brute_force": config.get("on_brute_force", ["log", "alert", "block_ip"]),
        }

        # Action history
        self.actions_taken: List[ResponseAction] = []
        self._lock = threading.Lock()

        # Reference to monitors (set later)
        self.network_monitor = None
        self.process_monitor = None

    def set_monitors(self, network_monitor, process_monitor):
        """Set references to monitors for taking actions."""
        self.network_monitor = network_monitor
        self.process_monitor = process_monitor

    def respond(self, threat: dict) -> List[str]:
        """
        Execute response actions for a detected threat.
        Returns list of actions taken.
        """
        if not self.enabled:
            return []

        threat_type = threat.get("type", "unknown")
        actions = self.action_map.get(threat_type, ["log", "alert"])
        taken = []

        for action in actions:
            try:
                if action == "block_ip":
                    ip = threat.get("ip", "")
                    if ip and ip != "multiple":
                        success = self._block_ip(ip)
                        taken.append(f"block_ip:{ip}")
                        self._record_action("block_ip", ip, success)

                elif action == "kill_process":
                    pid = threat.get("pid", 0)
                    if pid:
                        success = self._kill_process(pid)
                        taken.append(f"kill_process:{pid}")
                        self._record_action("kill_process", str(pid), success)

                elif action == "isolate":
                    success = self._isolate_system()
                    taken.append("isolate_system")
                    self._record_action("isolate", "system", success)

                elif action == "alert":
                    taken.append("alert_sent")

                elif action == "log":
                    taken.append("logged")

            except Exception as e:
                self._record_action(action, threat.get("ip", ""), False, str(e))

        return taken

    def _block_ip(self, ip: str) -> bool:
        """Block an IP address using Windows Firewall."""
        if self.network_monitor:
            return self.network_monitor.block_ip(ip)

        # Fallback: direct firewall command
        try:
            rule_name = f"SentinelAI_Block_{ip.replace('.', '_')}"
            cmd = (
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip}'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

    def _kill_process(self, pid: int) -> bool:
        """Kill a suspicious process."""
        if self.process_monitor:
            return self.process_monitor.kill_process(pid)

        # Fallback: direct kill
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            return True
        except Exception:
            return False

    def _isolate_system(self) -> bool:
        """
        Isolate the system from network (emergency response).
        Disables all network adapters.
        """
        try:
            # Get network adapters
            result = subprocess.run(
                'netsh interface show interface',
                shell=True, capture_output=True, text=True
            )

            # Disable all connected adapters
            for line in result.stdout.split('\n'):
                if 'Connected' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        adapter_name = ' '.join(parts[3:])
                        subprocess.run(
                            f'netsh interface set interface "{adapter_name}" disable',
                            shell=True, capture_output=True
                        )

            print("[ResponseEngine] SYSTEM ISOLATED - Network adapters disabled")
            return True
        except Exception as e:
            print(f"[ResponseEngine] Failed to isolate system: {e}")
            return False

    def _record_action(self, action_type: str, target: str, success: bool, details: str = ""):
        """Record a response action."""
        action = ResponseAction(
            timestamp=time.time(),
            action_type=action_type,
            target=target,
            success=success,
            details=details
        )
        with self._lock:
            self.actions_taken.append(action)

    def get_actions_summary(self) -> dict:
        """Get summary of all actions taken."""
        with self._lock:
            total = len(self.actions_taken)
            successful = sum(1 for a in self.actions_taken if a.success)
            by_type = {}
            for action in self.actions_taken:
                by_type[action.action_type] = by_type.get(action.action_type, 0) + 1

            return {
                "total_actions": total,
                "successful": successful,
                "failed": total - successful,
                "by_type": by_type
            }
