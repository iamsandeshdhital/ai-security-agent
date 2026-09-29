"""
AI Anomaly Detection Engine
Uses behavioral analysis and statistical methods to detect unknown threats.
"""

import time
import math
import threading
from collections import deque
from typing import Dict, List, Optional, Deque
from dataclasses import dataclass, field

import psutil


@dataclass
class FeatureVector:
    """Represents a snapshot of system behavior features."""
    timestamp: float
    network_connection_rate: float
    process_creation_rate: float
    cpu_usage_variance: float
    memory_usage_variance: float
    disk_io_rate: float
    failed_logins: int


@dataclass
class FeatureStats:
    """Running statistics for a single feature."""
    values: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    mean: float = 0.0
    std_dev: float = 0.0
    min_val: float = float('inf')
    max_val: float = float('-inf')

    def update(self, value: float):
        """Update running statistics with a new value."""
        self.values.append(value)
        n = len(self.values)
        if n > 0:
            self.mean = sum(self.values) / n
            if n > 1:
                variance = sum((x - self.mean) ** 2 for x in self.values) / n
                self.std_dev = math.sqrt(variance)
            self.min_val = min(self.min_val, value)
            self.max_val = max(self.max_val, value)

    def z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        if self.std_dev == 0:
            return 0.0
        return abs(value - self.mean) / self.std_dev


class AnomalyDetector:
    """
    AI-powered anomaly detection using statistical behavioral analysis.
    Learns normal behavior patterns and flags deviations.
    """

    def __init__(self, config: dict):
        self.config = config
        self.learning_period = config.get("learning_period_seconds", 300)
        self.anomaly_threshold = config.get("anomaly_threshold", 0.75)
        self.features_list = config.get("features", [])

        # Feature statistics
        self.feature_stats: Dict[str, FeatureStats] = {
            feat: FeatureStats() for feat in self.features_list
        }

        # Historical data
        self.history: Deque[FeatureVector] = deque(maxlen=10000)
        self.start_time = time.time()
        self.is_learning = True

        # Anomaly tracking
        self.anomalies_detected: List[dict] = []
        self._lock = threading.Lock()
        self._running = False

        # Previous values for rate calculations
        self._prev_network_conns = 0
        self._prev_process_count = 0
        self._prev_disk_io = 0
        self._prev_time = time.time()

    def start(self):
        """Start anomaly detection."""
        self._running = True
        print(f"[AnomalyDetector] Started. Learning period: {self.learning_period}s")

    def stop(self):
        """Stop anomaly detection."""
        self._running = False
        print("[AnomalyDetector] Stopped")

    def analyze(self) -> List[dict]:
        """
        Analyze current system state for anomalies.
        Returns list of detected anomalies.
        """
        if not self._running:
            return []

        current_time = time.time()
        elapsed = current_time - self.start_time

        # Check if still in learning phase
        if elapsed > self.learning_period:
            self.is_learning = False

        # Gather current features
        features = self._extract_features(current_time)

        with self._lock:
            self.history.append(features)

            # Update feature statistics
            for feat_name, value in features.__dict__.items():
                if feat_name != 'timestamp' and feat_name in self.feature_stats:
                    self.feature_stats[feat_name].update(value)

            # Skip detection during learning phase
            if self.is_learning:
                return []

            # Run anomaly detection
            anomalies = self._detect_anomalies(features)

        return anomalies

    def _extract_features(self, current_time: float) -> FeatureVector:
        """Extract current system behavior features."""
        time_delta = current_time - self._prev_time
        if time_delta < 0.1:
            time_delta = 0.1

        # Network connection rate
        try:
            connections = psutil.net_connections()
            current_conns = len(connections)
        except (psutil.AccessDenied, psutil.Error):
            current_conns = self._prev_network_conns

        network_rate = (current_conns - self._prev_network_conns) / time_delta
        self._prev_network_conns = current_conns

        # Process creation rate
        current_procs = len(list(psutil.process_iter()))
        process_rate = (current_procs - self._prev_process_count) / time_delta
        self._prev_process_count = current_procs

        # CPU usage variance
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_samples = [cpu_percent]
        for _ in range(5):
            cpu_samples.append(psutil.cpu_percent(interval=0.05))
        cpu_variance = self._calculate_variance(cpu_samples)

        # Memory usage
        mem = psutil.virtual_memory()
        mem_variance = mem.percent

        # Disk I/O rate
        try:
            disk_io = psutil.disk_io_counters()
            current_disk = disk_io.read_bytes + disk_io.write_bytes
            disk_rate = (current_disk - self._prev_disk_io) / time_delta
            self._prev_disk_io = current_disk
        except (psutil.Error, AttributeError):
            disk_rate = 0

        # Failed login attempts (Windows event log - simplified)
        failed_logins = self._check_failed_logins()

        self._prev_time = current_time

        return FeatureVector(
            timestamp=current_time,
            network_connection_rate=network_rate,
            process_creation_rate=process_rate,
            cpu_usage_variance=cpu_variance,
            memory_usage_variance=mem_variance,
            disk_io_rate=disk_rate,
            failed_logins=failed_logins
        )

    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    def _check_failed_logins(self) -> int:
        """Check for failed login attempts (simplified)."""
        # In a real implementation, this would read Windows Event Log
        # For now, return 0 as placeholder
        return 0

    def _detect_anomalies(self, features: FeatureVector) -> List[dict]:
        """Detect anomalies using z-score analysis."""
        anomalies = []
        total_score = 0.0
        feature_count = 0

        for feat_name, stats in self.feature_stats.items():
            value = getattr(features, feat_name, None)
            if value is None:
                continue

            z = stats.z_score(value)
            total_score += min(z / 3.0, 1.0)  # Normalize to 0-1
            feature_count += 1

            # Individual feature anomaly
            if z > 3.0:  # 3 sigma rule
                anomalies.append({
                    "type": "feature_anomaly",
                    "severity": "medium",
                    "feature": feat_name,
                    "details": f"Abnormal {feat_name}: z-score={z:.2f}, value={value:.2f}, mean={stats.mean:.2f}",
                    "threat_score": min(z / 5.0, 1.0),
                    "timestamp": features.timestamp
                })

        # Overall anomaly score
        if feature_count > 0:
            avg_score = total_score / feature_count
            if avg_score > self.anomaly_threshold:
                anomaly = {
                    "type": "behavioral_anomaly",
                    "severity": "high",
                    "details": f"Overall behavioral anomaly detected (score: {avg_score:.2f})",
                    "threat_score": avg_score,
                    "timestamp": features.timestamp,
                    "features": {
                        "network_rate": features.network_connection_rate,
                        "process_rate": features.process_creation_rate,
                    }
                }
                anomalies.append(anomaly)
                self.anomalies_detected.append(anomaly)

        return anomalies

    def get_stats(self) -> dict:
        """Get current anomaly detection statistics."""
        return {
            "is_learning": self.is_learning,
            "learning_progress": min(100, (time.time() - self.start_time) / self.learning_period * 100),
            "features_tracked": len(self.feature_stats),
            "anomalies_detected": len(self.anomalies_detected),
            "history_size": len(self.history),
        }
