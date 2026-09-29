# SentinelAI - AI-Powered Device Security Agent

A comprehensive AI-driven security agent that protects your device from **all types of threats and attacks** including bot attacks, AI attacks, zero-day exploits, data theft, and unauthorized access.

## Protection Modules (11 Total)

| # | Module | Attack Vectors Covered |
|---|--------|----------------------|
| 1 | **Network Monitor** | DDoS, port scans, bot connections, suspicious ports |
| 2 | **Process Monitor** | Malware, suspicious processes, resource abuse |
| 3 | **File System Monitor** | Ransomware, unauthorized file changes |
| 4 | **AI Anomaly Detector** | Unknown/AI-powered attacks via behavioral analysis |
| 5 | **USB Monitor** | BadUSB devices, unauthorized USB storage, data exfiltration |
| 6 | **Registry Monitor** | Persistence mechanisms, unauthorized registry edits |
| 7 | **Browser Monitor** | Malicious extensions, homepage hijacking, proxy changes |
| 8 | **Firewall Monitor** | Firewall bypass, unauthorized rule changes |
| 9 | **DNS Monitor** | DNS hijacking, poisoning, tunneling |
| 10 | **Credential Monitor** | Brute force, credential dumping, privilege escalation |
| 11 | **Exfiltration Monitor** | Data theft, large transfers, C2 connections |

## Complete Threat Coverage

| Threat Type | Detection Method | Auto-Response |
|-------------|-----------------|---------------|
| **Bot/DDoS Attack** | Connection rate analysis | Blocks IP via Windows Firewall |
| **Port Scan** | Tracks unique ports per IP | Blocks IP + alerts |
| **Malware/RAT** | Process name + behavior analysis | Kills process + alerts |
| **Ransomware** | File modification rate monitoring | Critical alert |
| **AI/Unknown Attacks** | Statistical anomaly detection (z-score) | Alert + optional isolation |
| **BadUSB Attack** | USB device signature matching | Critical alert |
| **USB Data Theft** | Unauthorized mass storage detection | Alert + optional block |
| **Registry Persistence** | Run key + service monitoring | Alert + details |
| **Browser Hijack** | Homepage/proxy change detection | Alert + details |
| **Malicious Extension** | Extension ID + name pattern matching | Critical alert |
| **Firewall Bypass** | Rule change + status monitoring | Critical alert |
| **DNS Hijacking** | Server change + tunneling detection | Alert + details |
| **Brute Force** | Failed login tracking | Blocks source IP |
| **Credential Dumping** | LSASS access + tool detection | Critical alert |
| **Privilege Escalation** | New admin account detection | Alert + details |
| **Data Exfiltration** | Large transfer + C2 connection detection | Alert + details |
| **Zero-Day Exploit** | Behavioral anomaly detection | Alert + optional isolation |

## Quick Start

### 1. Install Python
Download from [python.org](https://www.python.org/downloads/) and check "Add Python to PATH".

### 2. Install Dependencies
```bash
pip install psutil pyyaml rich
```

### 3. Run as Administrator
```bash
python sentinel_agent.py
```

## How It Works

1. **Learning Phase** (first 5 minutes): The AI learns your device's normal behavior patterns
2. **Detection Phase**: Continuously monitors 11 different attack vectors
3. **Response**: Automatically blocks threats based on your configuration

## Configuration

Edit `config.yaml` to customize:
- Enable/disable any of the 11 modules
- Adjust detection thresholds
- Configure auto-response actions
- Set up webhook notifications
- Define authorized USB devices
- Set trusted DNS servers

## Requirements

- Windows 10/11
- Python 3.9+
- Administrator privileges (recommended for full protection)

## Disclaimer

This is a defensive security tool designed to protect your own device. Always keep your OS and antivirus software up to date as well.
