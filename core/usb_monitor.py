"""
USB Device Monitor Module
Detects unauthorized USB device connections, BadUSB attacks, and data exfiltration.
"""

import time
import threading
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

import psutil


@dataclass
class USBEvent:
    """Represents a USB-related security event."""
    timestamp: float
    event_type: str  # "connected", "disconnected", "suspicious", "mass_storage"
    device_id: str
    device_name: str
    details: str
    threat_score: float = 0.0


@dataclass
class USBDeviceProfile:
    """Tracks a USB device's behavior."""
    device_id: str
    device_name: str
    first_seen: float
    last_seen: float
    is_mass_storage: bool = False
    data_transferred: int = 0
    threat_score: float = 0.0


class USBMonitor:
    """Monitors USB device connections for suspicious activity."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.authorized_devices: Set[str] = set(config.get("authorized_devices", []))
        self.block_unauthorized = config.get("block_unauthorized", False)
        self.mass_storage_only = config.get("mass_storage_only", False)

        # Tracking
        self.known_devices: Dict[str, USBDeviceProfile] = {}
        self.suspicious_events: List[USBEvent] = []
        self._lock = threading.Lock()
        self._running = False

        # Known BadUSB device signatures (VID:PID pairs)
        self.badusb_signatures = {
            "16d0:087d",  # Rubber Ducky
            "046d:c52b",  # Logitech (often spoofed)
            "1b1c:1b00",  # Corsair (often spoofed)
            "0483:5740",  # STM32 (common BadUSB)
            "1c4f:0002",  # SiGma Micro (often spoofed)
        }

    def start(self):
        """Start USB monitoring."""
        self._running = True
        self._scan_usb_devices()
        print(f"[USBMonitor] Started. {len(self.known_devices)} devices known")

    def stop(self):
        """Stop USB monitoring."""
        self._running = False
        print("[USBMonitor] Stopped")

    def _scan_usb_devices(self):
        """Scan currently connected USB devices."""
        try:
            # Get disk drives (USB mass storage)
            disk_partitions = psutil.disk_partitions()
            current_drives = set()
            for partition in disk_partitions:
                if 'removable' in partition.opts.lower():
                    current_drives.add(partition.device)

            # Get all USB devices via WMI
            import subprocess
            result = subprocess.run(
                'wmic path Win32_PnPEntity where "PNPDeviceID like \'USB%\'" get DeviceID,Name /format:csv',
                shell=True, capture_output=True, text=True, timeout=10
            )

            current_devices = {}
            for line in result.stdout.strip().split('\n'):
                if 'USB' in line and ',' in line:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        device_id = parts[1].strip()
                        device_name = parts[2].strip()
                        current_devices[device_id] = device_name

            return current_devices, current_drives

        except Exception as e:
            return {}, set()

    def check_usb(self) -> List[dict]:
        """
        Check USB devices for suspicious activity.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        try:
            current_devices, current_drives = self._scan_usb_devices()
        except Exception:
            return threats

        with self._lock:
            # Check 1: New USB device connected
            for device_id, device_name in current_devices.items():
                if device_id not in self.known_devices:
                    threat = self._handle_new_device(device_id, device_name, current_time)
                    if threat:
                        threats.append(threat)

            # Check 2: USB device disconnected
            disconnected = set(self.known_devices.keys()) - set(current_devices.keys())
            for device_id in disconnected:
                profile = self.known_devices[device_id]
                event = USBEvent(
                    timestamp=current_time,
                    event_type="disconnected",
                    device_id=device_id,
                    device_name=profile.device_name,
                    details=f"USB device disconnected: {profile.device_name}",
                    threat_score=0.0
                )
                self.suspicious_events.append(event)
                del self.known_devices[device_id]

            # Check 3: Mass storage device connected
            if current_drives:
                for drive in current_drives:
                    # Check if this is a new mass storage device
                    for device_id, profile in self.known_devices.items():
                        if profile.is_mass_storage and device_id not in self.authorized_devices:
                            threat = {
                                "type": "unauthorized_usb_storage",
                                "severity": "medium",
                                "device_id": device_id,
                                "device_name": profile.device_name,
                                "details": f"Unauthorized USB storage device: {profile.device_name}",
                                "threat_score": 0.6,
                                "timestamp": current_time
                            }
                            threats.append(threat)

        return threats

    def _handle_new_device(self, device_id: str, device_name: str, current_time: float) -> Optional[dict]:
        """Handle a newly connected USB device."""
        # Check for BadUSB signatures
        device_id_upper = device_id.upper()
        for sig in self.badusb_signatures:
            if sig.upper() in device_id_upper:
                event = USBEvent(
                    timestamp=current_time,
                    event_type="suspicious",
                    device_id=device_id,
                    device_name=device_name,
                    details=f"Possible BadUSB device detected: {device_name} ({device_id})",
                    threat_score=0.9
                )
                self.suspicious_events.append(event)
                self.known_devices[device_id] = USBDeviceProfile(
                    device_id=device_id,
                    device_name=device_name,
                    first_seen=current_time,
                    last_seen=current_time,
                    threat_score=0.9
                )
                return {
                    "type": "badusb_detected",
                    "severity": "critical",
                    "device_id": device_id,
                    "device_name": device_name,
                    "details": f"BadUSB signature match: {device_name}",
                    "threat_score": 0.9,
                    "timestamp": current_time
                }

        # Check if device is unauthorized
        if self.block_unauthorized and device_id not in self.authorized_devices:
            event = USBEvent(
                timestamp=current_time,
                event_type="unauthorized",
                device_id=device_id,
                device_name=device_name,
                details=f"Unauthorized USB device connected: {device_name}",
                threat_score=0.5
            )
            self.suspicious_events.append(event)
            self.known_devices[device_id] = USBDeviceProfile(
                device_id=device_id,
                device_name=device_name,
                first_seen=current_time,
                last_seen=current_time,
                threat_score=0.5
            )
            return {
                "type": "unauthorized_usb",
                "severity": "medium",
                "device_id": device_id,
                "device_name": device_name,
                "details": f"Unauthorized USB device: {device_name}",
                "threat_score": 0.5,
                "timestamp": current_time
            }

        # Normal device - add to known
        self.known_devices[device_id] = USBDeviceProfile(
            device_id=device_id,
            device_name=device_name,
            first_seen=current_time,
            last_seen=current_time
        )
        return None

    def authorize_device(self, device_id: str):
        """Add a device to the authorized list."""
        self.authorized_devices.add(device_id)

    def get_stats(self) -> dict:
        """Get current USB monitoring statistics."""
        return {
            "known_devices": len(self.known_devices),
            "authorized_devices": len(self.authorized_devices),
            "suspicious_events": len(self.suspicious_events),
        }
