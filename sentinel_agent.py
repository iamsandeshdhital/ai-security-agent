"""
SentinelAI - AI-Powered Device Security Agent
=============================================
Protects your device from bot attacks, AI attacks, unauthorized access,
and other cyber threats using behavioral analysis and real-time monitoring.

Usage:
    python sentinel_agent.py              # Start with default config
    python sentinel_agent.py --config custom.yaml
    python sentinel_agent.py --dashboard  # Show dashboard only
"""

import os
import sys
import time
import signal
import argparse
import threading
from pathlib import Path

import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.network_monitor import NetworkMonitor
from core.process_monitor import ProcessMonitor
from core.filesystem_monitor import FileSystemMonitor
from core.anomaly_detector import AnomalyDetector
from core.alert_manager import AlertManager
from core.response_engine import ResponseEngine
from core.usb_monitor import USBMonitor
from core.registry_monitor import RegistryMonitor
from core.browser_monitor import BrowserMonitor
from core.firewall_monitor import FirewallMonitor
from core.dns_monitor import DNSMonitor
from core.credential_monitor import CredentialMonitor
from core.exfiltration_monitor import ExfiltrationMonitor


class SentinelAI:
    """Main security agent orchestrator."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.running = False
        self._shutdown_event = threading.Event()

        # Initialize modules
        print("=" * 60)
        print("  SentinelAI - AI Security Agent v1.0")
        print("  Protecting your device from cyber threats")
        print("=" * 60)

        self.alert_manager = AlertManager(self.config.get("alerts", {}))
        self.response_engine = ResponseEngine(self.config.get("response", {}))

        self.network_monitor = NetworkMonitor(self.config.get("network", {}))
        self.process_monitor = ProcessMonitor(self.config.get("process", {}))
        self.filesystem_monitor = FileSystemMonitor(self.config.get("filesystem", {}))
        self.anomaly_detector = AnomalyDetector(self.config.get("ai", {}))
        self.usb_monitor = USBMonitor(self.config.get("usb", {}))
        self.registry_monitor = RegistryMonitor(self.config.get("registry", {}))
        self.browser_monitor = BrowserMonitor(self.config.get("browser", {}))
        self.firewall_monitor = FirewallMonitor(self.config.get("firewall", {}))
        self.dns_monitor = DNSMonitor(self.config.get("dns", {}))
        self.credential_monitor = CredentialMonitor(self.config.get("credential", {}))
        self.exfiltration_monitor = ExfiltrationMonitor(self.config.get("exfiltration", {}))

        # Link response engine to monitors
        self.response_engine.set_monitors(
            self.network_monitor,
            self.process_monitor
        )

        # Statistics
        self.scan_count = 0
        self.threats_detected = 0
        self.start_time = None

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        if not os.path.exists(config_path):
            print(f"[SentinelAI] Config not found: {config_path}, using defaults")
            return self._default_config()

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            print(f"[SentinelAI] Loaded configuration from {config_path}")
            return config
        except Exception as e:
            print(f"[SentinelAI] Error loading config: {e}, using defaults")
            return self._default_config()

    def _default_config(self) -> dict:
        """Default configuration."""
        return {
            "agent": {"scan_interval_seconds": 5},
            "network": {"enabled": True, "max_connections_per_ip": 20},
            "process": {"enabled": True},
            "filesystem": {"enabled": True},
            "ai": {"enabled": True, "learning_period_seconds": 300},
            "response": {"enabled": True},
            "alerts": {"enabled": True, "console": True}
        }

    def start(self):
        """Start the security agent."""
        self.running = True
        self.start_time = time.time()

        # Start all monitors
        self.network_monitor.start()
        self.process_monitor.start()
        self.filesystem_monitor.start()
        self.anomaly_detector.start()
        self.usb_monitor.start()
        self.registry_monitor.start()
        self.browser_monitor.start()
        self.firewall_monitor.start()
        self.dns_monitor.start()
        self.credential_monitor.start()
        self.exfiltration_monitor.start()

        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        print("\n[SentinelAI] All modules started. Monitoring active.")
        print("[SentinelAI] Press Ctrl+C to stop.\n")

        # Main loop
        interval = self.config.get("agent", {}).get("scan_interval_seconds", 5)

        try:
            while self.running and not self._shutdown_event.is_set():
                self._scan_cycle()
                self._shutdown_event.wait(interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _scan_cycle(self):
        """Execute one full scan cycle."""
        self.scan_count += 1
        threats = []

        # 1. Network analysis
        if self.config.get("network", {}).get("enabled", True):
            network_threats = self.network_monitor.check_connections()
            threats.extend(network_threats)

        # 2. Process analysis
        if self.config.get("process", {}).get("enabled", True):
            process_threats = self.process_monitor.check_processes()
            threats.extend(process_threats)

        # 3. File system analysis
        if self.config.get("filesystem", {}).get("enabled", True):
            fs_threats = self.filesystem_monitor.check_filesystem()
            threats.extend(fs_threats)

        # 4. AI anomaly detection
        if self.config.get("ai", {}).get("enabled", True):
            anomalies = self.anomaly_detector.analyze()
            threats.extend(anomalies)

        # 5. USB device monitoring
        if self.config.get("usb", {}).get("enabled", True):
            usb_threats = self.usb_monitor.check_usb()
            threats.extend(usb_threats)

        # 6. Registry monitoring
        if self.config.get("registry", {}).get("enabled", True):
            registry_threats = self.registry_monitor.check_registry()
            threats.extend(registry_threats)

        # 7. Browser monitoring
        if self.config.get("browser", {}).get("enabled", True):
            browser_threats = self.browser_monitor.check_browsers()
            threats.extend(browser_threats)

        # 8. Firewall monitoring
        if self.config.get("firewall", {}).get("enabled", True):
            firewall_threats = self.firewall_monitor.check_firewall()
            threats.extend(firewall_threats)

        # 9. DNS monitoring
        if self.config.get("dns", {}).get("enabled", True):
            dns_threats = self.dns_monitor.check_dns()
            threats.extend(dns_threats)

        # 10. Credential monitoring
        if self.config.get("credential", {}).get("enabled", True):
            cred_threats = self.credential_monitor.check_credentials()
            threats.extend(cred_threats)

        # 11. Data exfiltration monitoring
        if self.config.get("exfiltration", {}).get("enabled", True):
            exfil_threats = self.exfiltration_monitor.check_exfiltration()
            threats.extend(exfil_threats)

        # Process all threats
        for threat in threats:
            self._handle_threat(threat)

        # Periodic status display
        if self.scan_count % 12 == 0:  # Every ~60 seconds
            self._display_status()

    def _handle_threat(self, threat: dict):
        """Handle a detected threat."""
        self.threats_detected += 1

        # Determine source module
        threat_type = threat.get("type", "")
        if threat_type in ("ddos", "port_scan", "global_ddos", "suspicious_port"):
            source = "NetworkMonitor"
        elif threat_type in ("suspicious_process", "known_malware", "high_cpu", "high_memory"):
            source = "ProcessMonitor"
        elif threat_type in ("suspicious_file", "mass_deletion", "mass_modification", "ransomware_pattern"):
            source = "FileSystemMonitor"
        elif threat_type in ("badusb_detected", "unauthorized_usb", "unauthorized_usb_storage"):
            source = "USBMonitor"
        elif threat_type in ("suspicious_registry", "persistence_mechanism"):
            source = "RegistryMonitor"
        elif threat_type in ("malicious_extension", "suspicious_extension", "homepage_hijack", "proxy_hijack"):
            source = "BrowserMonitor"
        elif threat_type in ("firewall_disabled", "permissive_firewall_rule", "suspicious_port_rule"):
            source = "FirewallMonitor"
        elif threat_type in ("dns_hijack", "dns_tunneling"):
            source = "DNSMonitor"
        elif threat_type in ("brute_force", "credential_dump", "privilege_escalation"):
            source = "CredentialMonitor"
        elif threat_type in ("large_data_transfer", "suspicious_connection", "unusual_network_activity"):
            source = "ExfiltrationMonitor"
        else:
            source = "AnomalyDetector"

        # Create alert
        alert = self.alert_manager.process_threat(threat, source)

        # Execute response actions
        actions = self.response_engine.respond(threat)
        for action in actions:
            self.alert_manager.add_action(alert, action)

    def _display_status(self):
        """Display current security status."""
        uptime = time.time() - self.start_time if self.start_time else 0

        print("\n" + "-" * 50)
        print(f"  Scan #{self.scan_count} | Uptime: {uptime:.0f}s | Threats: {self.threats_detected}")
        print("-" * 50)

        # Module stats
        net_stats = self.network_monitor.get_stats()
        proc_stats = self.process_monitor.get_stats()
        fs_stats = self.filesystem_monitor.get_stats()
        ai_stats = self.anomaly_detector.get_stats()
        usb_stats = self.usb_monitor.get_stats()
        reg_stats = self.registry_monitor.get_stats()
        brw_stats = self.browser_monitor.get_stats()
        fw_stats = self.firewall_monitor.get_stats()
        dns_stats = self.dns_monitor.get_stats()
        cred_stats = self.credential_monitor.get_stats()
        exfil_stats = self.exfiltration_monitor.get_stats()

        print(f"  Network: {net_stats['unique_ips_tracked']} IPs tracked, "
              f"{len(net_stats['suspicious_ips'])} suspicious")
        print(f"  Process: {proc_stats['known_pids']} processes, "
              f"{proc_stats['suspicious_detected']} suspicious")
        print(f"  Files:   {fs_stats['total_files_tracked']} files tracked, "
              f"{fs_stats['suspicious_events']} events")
        print(f"  AI:      {'Learning' if ai_stats['is_learning'] else 'Active'} "
              f"({ai_stats['learning_progress']:.0f}%), "
              f"{ai_stats['anomalies_detected']} anomalies")
        print(f"  USB:     {usb_stats['known_devices']} devices, "
              f"{usb_stats['suspicious_events']} events")
        print(f"  Registry:{reg_stats['keys_tracked']} keys tracked, "
              f"{reg_stats['suspicious_events']} events")
        print(f"  Browser: {brw_stats['browsers_monitored']} browsers, "
              f"{brw_stats['total_extensions']} extensions")
        print(f"  FW:      {fw_stats['rules_tracked']} rules tracked, "
              f"{fw_stats['suspicious_events']} events")
        print(f"  DNS:     {dns_stats['known_servers']} servers, "
              f"{dns_stats['suspicious_events']} events")
        print(f"  Cred:    {cred_stats['known_users']} users, "
              f"{cred_stats['suspicious_events']} events")
        print(f"  Exfil:   {exfil_stats['processes_tracked']} procs, "
              f"{exfil_stats['suspicious_events']} events")

        # Response actions
        resp_stats = self.response_engine.get_actions_summary()
        if resp_stats['total_actions'] > 0:
            print(f"  Actions: {resp_stats['total_actions']} taken "
                  f"({resp_stats['successful']} successful)")

        print("-" * 50 + "\n")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[SentinelAI] Shutdown signal received...")
        self.running = False
        self._shutdown_event.set()

    def stop(self):
        """Stop the security agent."""
        print("\n[SentinelAI] Stopping all modules...")

        self.network_monitor.stop()
        self.process_monitor.stop()
        self.filesystem_monitor.stop()
        self.anomaly_detector.stop()
        self.usb_monitor.stop()
        self.registry_monitor.stop()
        self.browser_monitor.stop()
        self.firewall_monitor.stop()
        self.dns_monitor.stop()
        self.credential_monitor.stop()
        self.exfiltration_monitor.stop()

        # Final summary
        uptime = time.time() - self.start_time if self.start_time else 0
        print("\n" + "=" * 50)
        print("  SentinelAI - Session Summary")
        print("=" * 50)
        print(f"  Uptime:          {uptime:.0f} seconds")
        print(f"  Scans completed: {self.scan_count}")
        print(f"  Threats detected:{self.threats_detected}")

        resp_stats = self.response_engine.get_actions_summary()
        print(f"  Actions taken:   {resp_stats['total_actions']}")
        print(f"  Blocked IPs:     {len(self.network_monitor.get_stats()['blocked_ips'])}")
        print("=" * 50)
        print("[SentinelAI] Stay safe!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SentinelAI - AI-Powered Device Security Agent"
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--dashboard", "-d",
        action="store_true",
        help="Show dashboard and exit"
    )

    args = parser.parse_args()

    agent = SentinelAI(config_path=args.config)

    if args.dashboard:
        agent.alert_manager.display_dashboard()
    else:
        agent.start()


if __name__ == "__main__":
    main()
