"""
DNS Monitor Module
Detects DNS hijacking, poisoning, tunneling, and suspicious DNS queries.
"""

import time
import subprocess
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class DNSEvent:
    """Represents a DNS security event."""
    timestamp: float
    event_type: str  # "hijack_detected", "suspicious_query", "tunneling", "server_changed"
    details: str
    threat_score: float = 0.0


@dataclass
class DNSProfile:
    """Tracks DNS behavior."""
    known_servers: Set[str] = field(default_factory=set)
    query_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    suspicious_queries: int = 0


class DNSMonitor:
    """Monitors DNS for hijacking, poisoning, and tunneling attacks."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 30)

        # Known good DNS servers
        self.trusted_dns: Set[str] = set(config.get("trusted_dns", [
            "8.8.8.8",       # Google
            "8.8.4.4",       # Google
            "1.1.1.1",       # Cloudflare
            "1.0.0.1",       # Cloudflare
            "9.9.9.9",       # Quad9
            "208.67.222.222", # OpenDNS
        ]))

        # Suspicious TLDs often used in attacks
        self.suspicious_tlds: Set[str] = set(config.get("suspicious_tlds", [
            ".tk", ".ml", ".ga", ".cf", ".gq",  # Free domains
            ".xyz", ".top", ".club", ".work",
        ]))

        # Tracking
        self.profile = DNSProfile()
        self.suspicious_events: List[DNSEvent] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Start DNS monitoring."""
        self._running = True
        self._build_baseline()
        print(f"[DNSMonitor] Started. Trusted DNS: {len(self.trusted_dns)}")

    def stop(self):
        """Stop DNS monitoring."""
        self._running = False
        print("[DNSMonitor] Stopped")

    def _build_baseline(self):
        """Build baseline of current DNS settings."""
        try:
            result = subprocess.run(
                'netsh interface ip show dns',
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        dns = parts[1].strip()
                        if dns and dns[0].isdigit():
                            self.profile.known_servers.add(dns)
        except Exception:
            pass

    def check_dns(self) -> List[dict]:
        """
        Check DNS for hijacking and suspicious activity.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        # Check 1: DNS server changes
        threats.extend(self._check_dns_servers(current_time))

        # Check 2: DNS resolution anomalies
        threats.extend(self._check_dns_resolution(current_time))

        return threats

    def _check_dns_servers(self, current_time: float) -> List[dict]:
        """Check for unauthorized DNS server changes."""
        threats = []

        try:
            result = subprocess.run(
                'netsh interface ip show dns',
                shell=True, capture_output=True, text=True, timeout=10
            )

            current_servers = set()
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        dns = parts[1].strip()
                        if dns and dns[0].isdigit():
                            current_servers.add(dns)

            with self._lock:
                # Check for new DNS servers
                for server in current_servers:
                    if server not in self.profile.known_servers:
                        # Check if it's a known trusted DNS
                        if server not in self.trusted_dns:
                            event = DNSEvent(
                                timestamp=current_time,
                                event_type="server_changed",
                                details=f"New DNS server detected: {server}",
                                threat_score=0.7
                            )
                            self.suspicious_events.append(event)
                            threats.append({
                                "type": "dns_hijack",
                                "severity": "high",
                                "details": f"DNS server changed to untrusted: {server}",
                                "threat_score": 0.7,
                                "timestamp": current_time
                            })

                        self.profile.known_servers.add(server)

        except Exception:
            pass

        return threats

    def _check_dns_resolution(self, current_time: float) -> List[dict]:
        """Check for suspicious DNS resolution patterns."""
        threats = []

        # Check for DNS tunneling indicators
        # Long subdomains, high entropy queries
        try:
            # Get DNS cache
            result = subprocess.run(
                'ipconfig /displaydns',
                shell=True, capture_output=True, text=True, timeout=10
            )

            current_time = time.time()
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'Record Name' in line:
                    domain = line.split(':', 1)[1].strip() if ':' in line else ""

                    # Check for DNS tunneling indicators
                    if self._is_suspicious_domain(domain):
                        event = DNSEvent(
                            timestamp=current_time,
                            event_type="suspicious_query",
                            details=f"Suspicious DNS query: {domain}",
                            threat_score=0.6
                        )
                        self.suspicious_events.append(event)
                        threats.append({
                            "type": "dns_tunneling",
                            "severity": "medium",
                            "details": f"Possible DNS tunneling: {domain[:50]}",
                            "threat_score": 0.6,
                            "timestamp": current_time
                        })

        except Exception:
            pass

        return threats

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if a domain looks suspicious."""
        if not domain:
            return False

        # Check for suspicious TLDs
        domain_lower = domain.lower()
        for tld in self.suspicious_tlds:
            if domain_lower.endswith(tld):
                return True

        # Check for DNS tunneling indicators (long subdomains)
        parts = domain.split('.')
        if len(parts) > 4:
            # Check for high entropy subdomains (base64-like)
            for part in parts[:-2]:  # Exclude TLD and domain
                if len(part) > 20:
                    # High entropy check
                    unique_chars = len(set(part))
                    if unique_chars > 15:
                        return True

        return False

    def get_stats(self) -> dict:
        """Get current DNS monitoring statistics."""
        return {
            "known_servers": len(self.profile.known_servers),
            "trusted_dns_count": len(self.trusted_dns),
            "suspicious_events": len(self.suspicious_events),
        }
