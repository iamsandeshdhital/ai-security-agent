"""
Browser Attack Detection Module
Detects browser-based attacks, malicious extensions, hijacking, and credential theft.
"""

import os
import time
import json
import threading
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BrowserEvent:
    """Represents a browser security event."""
    timestamp: float
    event_type: str  # "extension_added", "homepage_changed", "proxy_changed", "suspicious"
    browser: str
    details: str
    threat_score: float = 0.0


@dataclass
class BrowserProfile:
    """Tracks a browser's security state."""
    name: str
    extensions: Dict[str, dict] = field(default_factory=dict)
    homepage: str = ""
    proxy_settings: str = ""
    first_seen: float = field(default_factory=time.time)
    threat_score: float = 0.0


class BrowserMonitor:
    """Monitors browsers for attacks, hijacking, and malicious extensions."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 60)

        # Known malicious extension IDs
        self.malicious_extensions: Set[str] = set(config.get("malicious_extensions", []))

        # Suspicious extension patterns
        self.suspicious_patterns = config.get("suspicious_patterns", [
            "adblock",
            "vpn",
            "proxy",
            "download manager",
            "video downloader",
            "coupon",
            "shopping",
            "search",
        ])

        # Tracking
        self.browser_profiles: Dict[str, BrowserProfile] = {}
        self.suspicious_events: List[BrowserEvent] = []
        self._lock = threading.Lock()
        self._running = False

        # Browser paths
        self.browser_paths = {
            "chrome": {
                "extensions": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"),
                "prefs": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Preferences"),
                "secure_prefs": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Secure Preferences"),
            },
            "edge": {
                "extensions": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions"),
                "prefs": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Preferences"),
                "secure_prefs": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Secure Preferences"),
            },
            "firefox": {
                "extensions": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
                "prefs": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
            },
            "brave": {
                "extensions": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions"),
                "prefs": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Preferences"),
            },
        }

    def start(self):
        """Start browser monitoring."""
        self._running = True
        self._build_baseline()
        print(f"[BrowserMonitor] Started. Monitoring {len(self.browser_profiles)} browsers")

    def stop(self):
        """Stop browser monitoring."""
        self._running = False
        print("[BrowserMonitor] Stopped")

    def _build_baseline(self):
        """Build baseline of browser states."""
        for browser_name, paths in self.browser_paths.items():
            if os.path.exists(paths.get("extensions", "")):
                profile = BrowserProfile(name=browser_name)
                self._scan_extensions(browser_name, paths, profile)
                self._scan_preferences(browser_name, paths, profile)
                self.browser_profiles[browser_name] = profile

    def _scan_extensions(self, browser_name: str, paths: dict, profile: BrowserProfile):
        """Scan browser extensions."""
        ext_path = paths.get("extensions", "")
        if not os.path.exists(ext_path):
            return

        try:
            for ext_id in os.listdir(ext_path):
                ext_dir = os.path.join(ext_path, ext_id)
                if not os.path.isdir(ext_dir):
                    continue

                # Get extension name from manifest
                manifest_path = self._find_manifest(ext_dir)
                ext_name = ext_id
                if manifest_path:
                    try:
                        with open(manifest_path, 'r', encoding='utf-8') as f:
                            manifest = json.load(f)
                            ext_name = manifest.get('name', ext_id)
                    except (json.JSONDecodeError, IOError):
                        pass

                profile.extensions[ext_id] = {
                    "name": ext_name,
                    "path": ext_dir,
                    "first_seen": time.time()
                }
        except (PermissionError, OSError):
            pass

    def _find_manifest(self, ext_dir: str) -> Optional[str]:
        """Find the manifest.json file in an extension directory."""
        try:
            for root, dirs, files in os.walk(ext_dir):
                if 'manifest.json' in files:
                    return os.path.join(root, 'manifest.json')
                # Limit depth
                if root.replace(ext_dir, '').count(os.sep) > 2:
                    break
        except (PermissionError, OSError):
            pass
        return None

    def _scan_preferences(self, browser_name: str, paths: dict, profile: BrowserProfile):
        """Scan browser preferences for homepage and proxy settings."""
        prefs_path = paths.get("prefs", "") or paths.get("secure_prefs", "")
        if not os.path.exists(prefs_path):
            return

        try:
            with open(prefs_path, 'r', encoding='utf-8') as f:
                prefs = json.load(f)

            # Get homepage
            profile.homepage = prefs.get('homepage', '') or prefs.get('session', {}).get('startup_urls', [''])[0]

            # Get proxy settings
            proxy = prefs.get('proxy', {})
            profile.proxy_settings = str(proxy.get('mode', '')) if proxy else ""

        except (json.JSONDecodeError, IOError, KeyError):
            pass

    def check_browsers(self) -> List[dict]:
        """
        Check browsers for attacks and suspicious changes.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        with self._lock:
            for browser_name, paths in self.browser_paths.items():
                if browser_name not in self.browser_profiles:
                    continue

                profile = self.browser_profiles[browser_name]

                # Check 1: New extensions
                threats.extend(self._check_extensions(browser_name, paths, profile, current_time))

                # Check 2: Homepage hijacking
                threats.extend(self._check_homepage(browser_name, paths, profile, current_time))

                # Check 3: Proxy changes
                threats.extend(self._check_proxy(browser_name, paths, profile, current_time))

        return threats

    def _check_extensions(self, browser_name: str, paths: dict, profile: BrowserProfile, current_time: float) -> List[dict]:
        """Check for new or suspicious extensions."""
        threats = []
        ext_path = paths.get("extensions", "")
        if not os.path.exists(ext_path):
            return threats

        try:
            current_ext_ids = set(os.listdir(ext_path))
        except (PermissionError, OSError):
            return threats

        # Check for new extensions
        for ext_id in current_ext_ids:
            if ext_id not in profile.extensions:
                ext_dir = os.path.join(ext_path, ext_id)
                if not os.path.isdir(ext_dir):
                    continue

                # Get extension name
                manifest_path = self._find_manifest(ext_dir)
                ext_name = ext_id
                if manifest_path:
                    try:
                        with open(manifest_path, 'r', encoding='utf-8') as f:
                            manifest = json.load(f)
                            ext_name = manifest.get('name', ext_id)
                    except (json.JSONDecodeError, IOError):
                        pass

                # Check if known malicious
                if ext_id in self.malicious_extensions:
                    threat = {
                        "type": "malicious_extension",
                        "severity": "critical",
                        "browser": browser_name,
                        "details": f"Known malicious extension: {ext_name} ({ext_id})",
                        "threat_score": 0.95,
                        "timestamp": current_time
                    }
                    threats.append(threat)
                    profile.threat_score = min(1.0, profile.threat_score + 0.5)

                # Check suspicious patterns
                else:
                    name_lower = ext_name.lower()
                    for pattern in self.suspicious_patterns:
                        if pattern.lower() in name_lower:
                            threat = {
                                "type": "suspicious_extension",
                                "severity": "medium",
                                "browser": browser_name,
                                "details": f"Suspicious extension '{ext_name}' matches pattern '{pattern}'",
                                "threat_score": 0.5,
                                "timestamp": current_time
                            }
                            threats.append(threat)
                            break

                # Add to profile
                profile.extensions[ext_id] = {
                    "name": ext_name,
                    "path": ext_dir,
                    "first_seen": current_time
                }

                event = BrowserEvent(
                    timestamp=current_time,
                    event_type="extension_added",
                    browser=browser_name,
                    details=f"New extension installed: {ext_name}",
                    threat_score=0.3
                )
                self.suspicious_events.append(event)

        return threats

    def _check_homepage(self, browser_name: str, paths: dict, profile: BrowserProfile, current_time: float) -> List[dict]:
        """Check for homepage hijacking."""
        threats = []
        prefs_path = paths.get("prefs", "") or paths.get("secure_prefs", "")
        if not os.path.exists(prefs_path):
            return threats

        try:
            with open(prefs_path, 'r', encoding='utf-8') as f:
                prefs = json.load(f)

            current_homepage = prefs.get('homepage', '') or prefs.get('session', {}).get('startup_urls', [''])[0]

            if current_homepage and current_homepage != profile.homepage:
                # Check if homepage is suspicious
                suspicious_domains = ['search', 'conduit', 'ask', 'yahoo', 'hijack', 'virus', 'malware']
                is_suspicious = any(domain in current_homepage.lower() for domain in suspicious_domains)

                if is_suspicious:
                    threat = {
                        "type": "homepage_hijack",
                        "severity": "high",
                        "browser": browser_name,
                        "details": f"Homepage hijacked to: {current_homepage}",
                        "threat_score": 0.8,
                        "timestamp": current_time
                    }
                    threats.append(threat)
                    profile.threat_score = min(1.0, profile.threat_score + 0.4)

                profile.homepage = current_homepage

        except (json.JSONDecodeError, IOError, KeyError):
            pass

        return threats

    def _check_proxy(self, browser_name: str, paths: dict, profile: BrowserProfile, current_time: float) -> List[dict]:
        """Check for proxy setting changes."""
        threats = []
        prefs_path = paths.get("prefs", "") or paths.get("secure_prefs", "")
        if not os.path.exists(prefs_path):
            return threats

        try:
            with open(prefs_path, 'r', encoding='utf-8') as f:
                prefs = json.load(f)

            proxy = prefs.get('proxy', {})
            current_proxy = str(proxy.get('mode', '')) if proxy else ""

            if current_proxy and current_proxy != profile.proxy_settings:
                if current_proxy in ('fixed_servers', 'pac_script'):
                    threat = {
                        "type": "proxy_hijack",
                        "severity": "high",
                        "browser": browser_name,
                        "details": f"Proxy settings changed to: {current_proxy}",
                        "threat_score": 0.7,
                        "timestamp": current_time
                    }
                    threats.append(threat)
                    profile.threat_score = min(1.0, profile.threat_score + 0.3)

                profile.proxy_settings = current_proxy

        except (json.JSONDecodeError, IOError, KeyError):
            pass

        return threats

    def get_stats(self) -> dict:
        """Get current browser monitoring statistics."""
        return {
            "browsers_monitored": len(self.browser_profiles),
            "total_extensions": sum(len(p.extensions) for p in self.browser_profiles.values()),
            "suspicious_events": len(self.suspicious_events),
        }
