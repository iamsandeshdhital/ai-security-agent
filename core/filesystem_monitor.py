"""
File System Monitor Module
Detects unauthorized file changes, ransomware activity, and data exfiltration.
"""

import os
import time
import hashlib
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileEvent:
    """Represents a file system security event."""
    timestamp: float
    filepath: str
    event_type: str  # "created", "modified", "deleted", "suspicious"
    details: str
    threat_score: float = 0.0


@dataclass
class DirectoryProfile:
    """Tracks file system activity for a directory."""
    path: str
    file_hashes: Dict[str, str] = field(default_factory=dict)
    known_files: Set[str] = field(default_factory=set)
    events: deque = field(default_factory=lambda: deque(maxlen=500))
    creation_times: deque = field(default_factory=lambda: deque(maxlen=1000))


class FileSystemMonitor:
    """Monitors file system for unauthorized changes and ransomware patterns."""

    def __init__(self, config: dict):
        self.config = config
        self.watch_dirs = config.get("watch_directories", [])
        self.suspicious_exts = config.get("suspicious_exts", [])
        self.max_new_files = config.get("max_new_files_per_minute", 10)

        # Tracking
        self.dir_profiles: Dict[str, DirectoryProfile] = {}
        self.suspicious_events: List[FileEvent] = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Start file system monitoring."""
        self._running = True
        for dir_path in self.watch_dirs:
            if os.path.exists(dir_path):
                self._scan_directory(dir_path)
        print(f"[FileSystemMonitor] Started. Watching {len(self.dir_profiles)} directories")

    def stop(self):
        """Stop file system monitoring."""
        self._running = False
        print("[FileSystemMonitor] Stopped monitoring")

    def _scan_directory(self, dir_path: str):
        """Initial scan of a directory to build baseline."""
        profile = DirectoryProfile(path=dir_path)

        try:
            for root, dirs, files in os.walk(dir_path):
                # Limit depth to avoid huge scans
                depth = root.replace(dir_path, '').count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue

                for f in files:
                    filepath = os.path.join(root, f)
                    profile.known_files.add(filepath)

                    # Hash small files for integrity checking
                    try:
                        if os.path.getsize(filepath) < 10_000_000:  # < 10MB
                            profile.file_hashes[filepath] = self._hash_file(filepath)
                    except (OSError, IOError):
                        pass

        except (PermissionError, OSError):
            pass

        self.dir_profiles[dir_path] = profile

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, IOError):
            return ""

    def check_filesystem(self) -> List[dict]:
        """
        Check file system for suspicious changes.
        Returns list of detected threats.
        """
        if not self._running:
            return []

        threats = []
        current_time = time.time()

        with self._lock:
            for dir_path, profile in self.dir_profiles.items():
                if not os.path.exists(dir_path):
                    continue

                try:
                    current_files = set()
                    for root, dirs, files in os.walk(dir_path):
                        depth = root.replace(dir_path, '').count(os.sep)
                        if depth > 3:
                            dirs.clear()
                            continue

                        for f in files:
                            filepath = os.path.join(root, f)
                            current_files.add(filepath)

                    # Check 1: New files created
                    new_files = current_files - profile.known_files
                    for filepath in new_files:
                        threat = self._check_new_file(filepath, current_time)
                        if threat:
                            threats.append(threat)

                        # Track creation time for rate limiting
                        profile.creation_times.append(current_time)

                    # Check 2: Files deleted
                    deleted_files = profile.known_files - current_files
                    if len(deleted_files) > 5:
                        threats.append({
                            "type": "mass_deletion",
                            "severity": "high",
                            "details": f"{len(deleted_files)} files deleted from {dir_path}",
                            "threat_score": 0.7,
                            "timestamp": current_time
                        })

                    # Check 3: File modifications (potential ransomware)
                    modified_count = 0
                    for filepath, old_hash in profile.file_hashes.items():
                        if filepath in current_files:
                            new_hash = self._hash_file(filepath)
                            if new_hash and new_hash != old_hash:
                                modified_count += 1
                                profile.file_hashes[filepath] = new_hash

                    if modified_count > 10:
                        threats.append({
                            "type": "mass_modification",
                            "severity": "critical",
                            "details": f"{modified_count} files modified in {dir_path} - possible ransomware!",
                            "threat_score": 0.95,
                            "timestamp": current_time
                        })

                    # Check 4: Too many new files (ransomware encryption)
                    recent_creations = [
                        t for t in profile.creation_times
                        if current_time - t < 60
                    ]
                    if len(recent_creations) > self.max_new_files:
                        threats.append({
                            "type": "ransomware_pattern",
                            "severity": "critical",
                            "details": f"{len(recent_creations)} new files in 60s - ransomware pattern!",
                            "threat_score": 0.95,
                            "timestamp": current_time
                        })

                    # Update known files
                    profile.known_files = current_files

                except (PermissionError, OSError):
                    continue

        return threats

    def _check_new_file(self, filepath: str, current_time: float) -> Optional[dict]:
        """Check if a newly created file is suspicious."""
        ext = os.path.splitext(filepath)[1].lower()

        # Check for suspicious extensions
        if ext in self.suspicious_exts:
            # Check if in a suspicious location
            path_lower = filepath.lower()
            suspicious_paths = ['temp', 'tmp', 'downloads', 'desktop']
            if any(sp in path_lower for sp in suspicious_paths):
                event = FileEvent(
                    timestamp=current_time,
                    filepath=filepath,
                    event_type="suspicious",
                    details=f"Suspicious file created: {filepath}",
                    threat_score=0.6
                )
                self.suspicious_events.append(event)
                return {
                    "type": "suspicious_file",
                    "severity": "medium",
                    "filepath": filepath,
                    "details": f"Suspicious file type {ext} in {filepath}",
                    "threat_score": 0.6,
                    "timestamp": current_time
                }

        return None

    def get_stats(self) -> dict:
        """Get current monitoring statistics."""
        return {
            "directories_watched": len(self.dir_profiles),
            "total_files_tracked": sum(len(p.known_files) for p in self.dir_profiles.values()),
            "suspicious_events": len(self.suspicious_events),
        }
