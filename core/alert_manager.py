"""
Alert Manager Module
Handles all security alerts, notifications, and logging.
"""

import os
import json
import time
import threading
from typing import List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


@dataclass
class SecurityAlert:
    """Represents a security alert."""
    timestamp: float
    alert_type: str
    severity: str  # "low", "medium", "high", "critical"
    source: str  # Which module generated it
    message: str
    details: str
    threat_score: float
    actions_taken: List[str] = field(default_factory=list)
    acknowledged: bool = False


class AlertManager:
    """Manages security alerts, notifications, and logging."""

    def __init__(self, config: dict):
        self.config = config
        self.console_enabled = config.get("console", True)
        self.sound_enabled = config.get("sound", False)
        self.desktop_notifications = config.get("desktop_notification", True)
        self.webhook_url = config.get("webhook_url", "")

        # Alert storage
        self.alerts: List[SecurityAlert] = []
        self.alert_log_path = "alerts.json"
        self._lock = threading.Lock()

        # Rich console for beautiful output
        if HAS_RICH:
            self.console = Console()
        else:
            self.console = None

        # Severity colors
        self.severity_colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red"
        }

        # Severity icons
        self.severity_icons = {
            "low": "[+]",
            "medium": "[!]",
            "high": "[X]",
            "critical": "[!!!]"
        }

    def process_threat(self, threat: dict, source: str) -> SecurityAlert:
        """Process a detected threat and create an alert."""
        severity = threat.get("severity", "medium")
        threat_type = threat.get("type", "unknown")
        details = threat.get("details", "")
        threat_score = threat.get("threat_score", 0.5)
        timestamp = threat.get("timestamp", time.time())

        # Create alert
        alert = SecurityAlert(
            timestamp=timestamp,
            alert_type=threat_type,
            severity=severity,
            source=source,
            message=f"[{severity.upper()}] {threat_type}: {details}",
            details=details,
            threat_score=threat_score
        )

        with self._lock:
            self.alerts.append(alert)

        # Output alert
        self._display_alert(alert)
        self._log_alert(alert)
        self._send_notifications(alert)

        return alert

    def _display_alert(self, alert: SecurityAlert):
        """Display alert to console."""
        if not self.console_enabled:
            return

        time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")

        if self.console and HAS_RICH:
            color = self.severity_colors.get(alert.severity, "white")
            icon = self.severity_icons.get(alert.severity, "[?]")

            # Create panel for high/critical alerts
            if alert.severity in ("high", "critical"):
                panel = Panel(
                    f"[bold]{icon} {alert.alert_type.upper()}[/bold]\n"
                    f"Source: {alert.source}\n"
                    f"Details: {alert.details}\n"
                    f"Threat Score: {alert.threat_score:.2f}",
                    title=f"[{color}]SECURITY ALERT - {alert.severity.upper()}[/{color}]",
                    border_style=color,
                    box=box.DOUBLE
                )
                self.console.print(panel)
            else:
                self.console.print(
                    f"[{color}][{time_str}] {icon} {alert.source}: "
                    f"{alert.alert_type} - {alert.details}[/{color}]"
                )
        else:
            # Fallback to plain text
            print(f"[{time_str}] [{alert.severity.upper()}] {alert.source}: "
                  f"{alert.alert_type} - {alert.details}")

    def _log_alert(self, alert: SecurityAlert):
        """Log alert to file."""
        try:
            log_entry = {
                "timestamp": alert.timestamp,
                "datetime": datetime.fromtimestamp(alert.timestamp).isoformat(),
                "type": alert.alert_type,
                "severity": alert.severity,
                "source": alert.source,
                "message": alert.message,
                "details": alert.details,
                "threat_score": alert.threat_score,
                "actions_taken": alert.actions_taken
            }

            # Append to JSON log
            existing = []
            if os.path.exists(self.alert_log_path):
                try:
                    with open(self.alert_log_path, 'r') as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, IOError):
                    existing = []

            existing.append(log_entry)

            with open(self.alert_log_path, 'w') as f:
                json.dump(existing, f, indent=2)

        except IOError as e:
            print(f"[AlertManager] Failed to log alert: {e}")

    def _send_notifications(self, alert: SecurityAlert):
        """Send external notifications."""
        # Desktop notification
        if self.desktop_notifications and alert.severity in ("high", "critical"):
            self._desktop_notify(alert)

        # Webhook notification
        if self.webhook_url:
            self._webhook_notify(alert)

        # Sound alert
        if self.sound_enabled and alert.severity == "critical":
            self._sound_alert()

    def _desktop_notify(self, alert: SecurityAlert):
        """Send Windows desktop notification."""
        try:
            # Use PowerShell for Windows notification
            import subprocess
            title = f"Security Alert: {alert.alert_type}"
            message = alert.details[:200]  # Truncate for notification
            ps_cmd = (
                f'Add-Type -AssemblyName System.Windows.Forms; '
                f'[System.Windows.Forms.MessageBox]::Show('
                f'"{message}", "{title}", "OK", "Warning")'
            )
            # Non-blocking notification using msg command
            subprocess.run(
                f'msg * /TIME:10 "{title}: {message[:100]}"',
                shell=True, capture_output=True
            )
        except Exception:
            pass

    def _webhook_notify(self, alert: SecurityAlert):
        """Send webhook notification (Slack/Discord/etc)."""
        if not self.webhook_url:
            return
        try:
            import requests
            payload = {
                "text": f"Security Alert: {alert.alert_type}\n"
                        f"Severity: {alert.severity}\n"
                        f"Details: {alert.details}\n"
                        f"Source: {alert.source}"
            }
            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception:
            pass

    def _sound_alert(self):
        """Play alert sound."""
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except ImportError:
            print("\a")  # Terminal bell

    def add_action(self, alert: SecurityAlert, action: str):
        """Record an action taken for an alert."""
        alert.actions_taken.append(action)
        # Update log
        self._log_alert(alert)

    def get_active_threats(self) -> List[SecurityAlert]:
        """Get all unacknowledged alerts."""
        with self._lock:
            return [a for a in self.alerts if not a.acknowledged]

    def acknowledge(self, alert: SecurityAlert):
        """Acknowledge an alert."""
        alert.acknowledged = True

    def get_summary(self) -> dict:
        """Get alert summary statistics."""
        with self._lock:
            total = len(self.alerts)
            by_severity = {}
            by_type = {}
            for alert in self.alerts:
                by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
                by_type[alert.alert_type] = by_type.get(alert.alert_type, 0) + 1

            return {
                "total_alerts": total,
                "active_threats": len(self.get_active_threats()),
                "by_severity": by_severity,
                "by_type": by_type
            }

    def display_dashboard(self):
        """Display security dashboard."""
        if not (self.console and HAS_RICH):
            return

        summary = self.get_summary()

        table = Table(
            title="SentinelAI Security Dashboard",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Alerts", str(summary["total_alerts"]))
        table.add_row("Active Threats", str(summary["active_threats"]))

        for severity, count in summary["by_severity"].items():
            table.add_row(f"{severity.title()} Alerts", str(count))

        self.console.print(table)
