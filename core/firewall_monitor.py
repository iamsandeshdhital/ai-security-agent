"""
Firewall Monitor Module
Detects unauthorized firewall changes, rule modifications, and bypass attempts.
"""

import time
import subprocess
import threading
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class FirewallEvent:
    """Represents a firewall security event."""
    timestamp: float
    event_type: str  # "rule_added", "rule_removed", "rule_modified", "disabled", "suspicious"
    rule_name: str
    details: str
    threat_score: float = 0.0


@dataclass
class FirewallRule:
    """Tracks a firewall rule."""
    name: str
    direction: str
    action: str
    protocol: str
    local_port: str
    remote_port: str
    remote_ip: str
    first_seen: float
    modified_count: int = 0


class FirewallMonitor:
    """Monitors Windows Firewall for unauthorized changes."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 30)

        # Suspicious rule patterns
        self.suspicious_patterns = config.get("suspicious_patterns", [
            "allow all",
            "any",
            "0.0.0.0/0",
            "permit",
        ])

        # Tracking
        self.known_rules: Dict[str, FirewallRule] = {}
        self.suspicious_events: List[FirewallEvent] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Start firewall monitoring."""
        self._running = True
        self._build_baseline()
        print(f"[FirewallMonitor] Started. {len(self.known_rules)} rules tracked")

    def stop(self):
        """Stop firewall monitoring."""
        self._running = False
        print("[FirewallMonitor] Stopped")

    def _build_baseline(self):
        """Build baseline of current firewall rules."""
        try:
            result = subprocess.run(
                'netsh advfirewall firewall show rule name=all verbose',
                shell=True, capture_output=True, text=True, timeout=30
            )
            self._parse_rules(result.stdout)
        except Exception as e:
            print(f"[FirewallMonitor] Baseline error: {e}")

    def _parse_rules(self, output: str):
        """Parse firewall rules from netsh output."""
        current_rule = {}
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("Rule Name:"):
                if current_rule.get('name'):
                    self._add_rule(current_rule)
                current_rule = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith("Direction:"):
                current_rule['direction'] = line.split(':', 1)[1].strip()
            elif line.startswith("Action:"):
                current_rule['action'] = line.split(':', 1)[1].strip()
            elif line.startswith("Protocol:"):
                current_rule['protocol'] = line.split(':', 1)[1].strip()
            elif line.startswith("Local Port:"):
                current_rule['local_port'] = line.split(':', 1)[1].strip()
            elif line.startswith("Remote Port:"):
                current_rule['remote_port'] = line.split(':', 1)[1].strip()
            elif line.startswith("Remote IP:"):
                current_rule['remote_ip'] = line.split(':', 1)[1].strip()

        if current_rule.get('name'):
            self._add_rule(current_rule)

    def _add_rule(self, rule_data: dict):
        """Add a rule to tracking."""
        name = rule_data.get('name', '')
        if name and name not in self.known_rules:
            self.known_rules[name] = FirewallRule(
                name=name,
                direction=rule_data.get('direction', ''),
                action=rule_data.get('action', ''),
                protocol=rule_data.get('protocol', ''),
                local_port=rule_data.get('local_port', ''),
                remote_port=rule_data.get('remote_port', ''),
                remote_ip=rule_data.get('remote_ip', ''),
                first_seen=time.time()
            )

    def check_firewall(self) -> List[dict]:
        """
        Check firewall for unauthorized changes.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        # Check 1: Is firewall enabled?
        threats.extend(self._check_firewall_status())

        # Check 2: Rule changes
        threats.extend(self._check_rule_changes(current_time))

        return threats

    def _check_firewall_status(self) -> List[dict]:
        """Check if firewall is enabled."""
        threats = []
        try:
            result = subprocess.run(
                'netsh advfirewall show allprofiles state',
                shell=True, capture_output=True, text=True, timeout=10
            )

            if "OFF" in result.stdout or "off" in result.stdout:
                threats.append({
                    "type": "firewall_disabled",
                    "severity": "critical",
                    "details": "Windows Firewall is DISABLED",
                    "threat_score": 0.95,
                    "timestamp": time.time()
                })
        except Exception:
            pass

        return threats

    def _check_rule_changes(self, current_time: float) -> List[dict]:
        """Check for firewall rule changes."""
        threats = []

        try:
            result = subprocess.run(
                'netsh advfirewall firewall show rule name=all verbose',
                shell=True, capture_output=True, text=True, timeout=30
            )

            current_rules = {}
            current_rule = {}

            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith("Rule Name:"):
                    if current_rule.get('name'):
                        current_rules[current_rule['name']] = current_rule
                    current_rule = {'name': line.split(':', 1)[1].strip()}
                elif line.startswith("Direction:"):
                    current_rule['direction'] = line.split(':', 1)[1].strip()
                elif line.startswith("Action:"):
                    current_rule['action'] = line.split(':', 1)[1].strip()
                elif line.startswith("Protocol:"):
                    current_rule['protocol'] = line.split(':', 1)[1].strip()
                elif line.startswith("Local Port:"):
                    current_rule['local_port'] = line.split(':', 1)[1].strip()
                elif line.startswith("Remote IP:"):
                    current_rule['remote_ip'] = line.split(':', 1)[1].strip()

            if current_rule.get('name'):
                current_rules[current_rule['name']] = current_rule

            with self._lock:
                # Check for new rules
                for name, rule_data in current_rules.items():
                    if name not in self.known_rules:
                        threat = self._check_suspicious_rule(name, rule_data, current_time)
                        if threat:
                            threats.append(threat)

                        self.known_rules[name] = FirewallRule(
                            name=name,
                            direction=rule_data.get('direction', ''),
                            action=rule_data.get('action', ''),
                            protocol=rule_data.get('protocol', ''),
                            local_port=rule_data.get('local_port', ''),
                            remote_port=rule_data.get('remote_port', ''),
                            remote_ip=rule_data.get('remote_ip', ''),
                            first_seen=current_time
                        )

                # Check for removed rules
                for name in list(self.known_rules.keys()):
                    if name not in current_rules:
                        event = FirewallEvent(
                            timestamp=current_time,
                            event_type="rule_removed",
                            rule_name=name,
                            details=f"Firewall rule removed: {name}",
                            threat_score=0.5
                        )
                        self.suspicious_events.append(event)
                        del self.known_rules[name]

        except Exception:
            pass

        return threats

    def _check_suspicious_rule(self, name: str, rule_data: dict, current_time: float) -> Optional[dict]:
        """Check if a new firewall rule is suspicious."""
        # Check for overly permissive rules
        remote_ip = rule_data.get('remote_ip', '')
        action = rule_data.get('action', '')

        if action.lower() == 'allow' and remote_ip in ('any', '0.0.0.0/0', '*'):
            event = FirewallEvent(
                timestamp=current_time,
                event_type="suspicious",
                rule_name=name,
                details=f"Overly permissive firewall rule: {name} allows {remote_ip}",
                threat_score=0.8
            )
            self.suspicious_events.append(event)
            return {
                "type": "permissive_firewall_rule",
                "severity": "high",
                "rule_name": name,
                "details": f"New rule allows all IPs: {name}",
                "threat_score": 0.8,
                "timestamp": current_time
            }

        # Check for rules allowing suspicious ports
        local_port = rule_data.get('local_port', '')
        suspicious_ports = {'4444', '5555', '6666', '7777', '8888', '31337', '12345'}
        if local_port in suspicious_ports:
            return {
                "type": "suspicious_port_rule",
                "severity": "high",
                "rule_name": name,
                "details": f"Firewall rule opens suspicious port {local_port}",
                "threat_score": 0.85,
                "timestamp": current_time
            }

        return None

    def get_stats(self) -> dict:
        """Get current firewall monitoring statistics."""
        return {
            "rules_tracked": len(self.known_rules),
            "suspicious_events": len(self.suspicious_events),
        }
