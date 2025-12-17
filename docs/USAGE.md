# NetObserver Usage Guide

## Overview

NetObserver is a defensive network monitoring tool designed for incident response and threat detection. This guide covers installation, configuration, and operational use.

## Legal Requirements

**⚠️ CRITICAL: Authorization Required**

- You MUST have explicit written permission to monitor any network
- Use ONLY on networks you own or are authorized to monitor
- Unauthorized network monitoring is illegal in most jurisdictions
- This tool is for DEFENSIVE purposes only (incident response, forensics, threat hunting)
- NOT for offensive operations, exploitation, or evasion

## System Requirements

### Minimum Requirements
- Python 3.8 or higher
- 4GB RAM
- Linux, macOS, or Windows

### Recommended
- Python 3.10+
- 8GB RAM
- Linux (for best capture support)
- Root/administrator privileges OR CAP_NET_RAW capability

## Installation

### Basic Installation
```bash
# Navigate to project directory
cd NetObserver

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

Linux Permissions
For live packet capture on Linux, you need either:
Option 1: Run with sudo (not recommended for development)
bashsudo python run.py
Option 2: Grant CAP_NET_RAW capability (recommended)
bash# Grant capability to Python interpreter
sudo setcap cap_net_raw+ep $(which python3)

# Now run without sudo
python run.py
Option 3: Add user to pcap group (Debian/Ubuntu)
bashsudo groupadd pcap
sudo usermod -a -G pcap $USER
sudo chgrp pcap /usr/bin/tcpdump
sudo chmod 750 /usr/bin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
Optional Dependencies
For advanced PCAP analysis:
bashpip install pyshark scapy
Running NetObserver
Basic Startup
bashpython run.py
Developer Mode
bash# Run with verbose logging
python run.py --verbose

# Run with specific interface
python run.py --interface eth0
```

## Interface Overview

### Main Dashboard Layout
```
┌──────────────┬─────────┬──────────────┐
│              │ Status  │              │
│ Connections  ├─────────┤  Protocols   │
│   Panel      │ Threat  │    Panel     │
│              │  Level  │              │
├──────────────┼─────────┼──────────────┤
│              │ Actions │              │
│  Event Logs  │ Panel   │    Alerts    │
│              │         │              │
└──────────────┴─────────┴──────────────┘
Panel Descriptions
Active Connections Panel

Shows real-time network connections
Columns: Protocol, Source IP, Source Port, Dest IP, Dest Port, Time
Limited to 100 most recent connections

Protocol Statistics Panel

Displays protocol distribution
Shows count and percentage for each protocol
Automatically updates with new traffic

Event Logs Panel

Scrolling log of all events and alerts
Color-coded by severity (green=info, yellow=warning, red=error)
Maximum 1000 lines retained

Security Alerts Panel

Scrollable list of security alerts
Color-coded severity indicators
Click info button (ℹ) for alert details

System Status Panel

Shows current capture state
Displays status messages

Actions Panel

▶ Start: Begin network capture
■ Stop: End capture
✖ Clear: Clear all panels

Central Ring Indicator

Shows current threat level (0-100%)
Color changes based on severity:

Green (0-30%): Safe
Yellow (30-60%): Elevated
Orange (60-85%): High
Red (85-100%): Critical



Basic Operations
Starting Capture

Click ▶ Start button or use menu: Capture → Start Capture
NetObserver will automatically select the best capture method:

Linux: /proc/net monitoring (no root required)
With pyshark: Live packet capture
Fallback: Simulated mode for testing



Stopping Capture

Click ■ Stop button or use menu: Capture → Stop Capture
Data remains visible in panels

Viewing Alert Details

Locate alert in Alerts panel
Click the ℹ button on the right
Read detailed explanation and metadata

Exporting Data
Export PCAP:

Menu: File → Export PCAP...
Choose save location
PCAP file contains captured packets

Clearing Display

Click ✖ Clear button to clear all panels
Data in database remains (not deleted)

Configuration
Opening Settings
Menu: Settings → Preferences...
Capture Settings

Interface: Network interface to capture from (default: "any")
Buffer Size: Packet buffer size in bytes
Promiscuous Mode: Capture all packets on network segment

Analytics Settings

Enable Heuristics: Toggle anomaly detection
Alert Threshold: Minimum occurrences to trigger alert

API Keys
⚠️ Security Warning: API keys stored in plaintext at ~/.NetObserver/keys.json with file permissions 0600.
Supported Services:

VirusTotal: For hash/domain reputation lookups

Adding API Key:

Open Settings → Preferences
Navigate to "API Keys" tab
Enter API key
Click "Save Settings"

Understanding Alerts
Alert Types
Port Scan Detection

Triggers when single source contacts 20+ unique ports
Severity: High
Indicates reconnaissance activity

DNS Anomalies

Repeated DNS failures (NXDOMAIN)
DGA-like domain patterns (high entropy, unusual length)
Severity: Medium to High

Outbound Traffic Spikes

Single host makes 100+ connections in 5 minutes
Severity: Medium
May indicate data exfiltration or malware

Failed Authentication

Multiple auth attempts to SSH/RDP
Severity: High
Indicates potential brute force attack

Suspicious Port Connections

Connections to known malware ports (4444, 6667, 31337, etc.)
Severity: Critical

Alert Severity Levels

Low: Informational, routine anomaly
Medium: Suspicious activity, warrants investigation
High: Likely security incident, immediate attention
Critical: Active threat detected, urgent response required

Troubleshooting
"Permission denied" errors
Problem: Cannot capture packets
Solution:

Run with sudo, or
Grant CAP_NET_RAW capability (see Installation section)

No traffic appearing
Problem: Capture started but no events shown
Solution:

Verify correct interface selected
Check if interface has traffic: ip link show
Try "any" interface to capture from all
Verify firewall not blocking

High memory usage
Problem: Application using excessive RAM
Solution:

Clear panels periodically (✖ Clear button)
Reduce capture duration
Lower buffer size in settings

Pyshark not working
Problem: "pyshark not available" warning
Solution:
bash# Install pyshark
pip install pyshark

# Ensure tshark is installed
# Ubuntu/Debian:
sudo apt install tshark

# Fedora/RHEL:
sudo yum install wireshark-cli

# macOS:
brew install wireshark
Database errors
Problem: "Database locked" or write errors
Solution:

Close any other NetObserver instances
Delete ~/.NetObserver/netgui.db (will lose history)
Check disk space

Data Storage
Configuration Directory
All data stored in: ~/.NetObserver/
Contents:

config.json - Application settings
keys.json - API keys (file mode 0600)
netgui.db - SQLite database with events/alerts
logs/ - Application log files

Database Schema
Events Table:

Stores all captured network events
Includes: timestamp, protocol, IPs, ports, metadata

Alerts Table:

Stores generated security alerts
Includes: term, count, severity, explanation, metadata

Logs
Log files located in: ~/.NetObserver/logs/

Format: NetObserver_YYYYMMDD_HHMMSS.log
Contains detailed application activity
Useful for debugging and audit trails

Best Practices
Incident Response Workflow

Preparation

Configure settings before incident
Test capture on authorized network
Familiarize yourself with interface


Detection

Start capture at first sign of incident
Monitor alerts panel for anomalies
Watch threat level indicator


Analysis

Review connection patterns in Connections panel
Check protocol distribution for anomalies
Examine alert details for IOCs


Documentation

Export PCAP for forensic analysis
Save logs for reporting
Screenshot relevant alerts


Response

Use findings to inform containment strategy
Correlate with other security tools
Document timeline of events



Performance Tips

Clear panels regularly during long captures
Use specific interface instead of "any" when possible
Adjust alert threshold to reduce false positives
Disable heuristics if only collecting data

Security Considerations

Never run on untrusted networks without authorization
Protect API keys and configuration files
Use secure channels to transfer PCAP exports
Sanitize data before sharing externally
Follow chain-of-custody for forensic captures

Custom Heuristics
To add custom detection rules:

Edit analytics/heuristics.py
Add new method to Heuristics class
Call from analyze_event() method
Restart application

Database Queries
Direct database access:
bashsqlite3 ~/.NetObserver/netgui.db

# Example queries:
SELECT * FROM alerts WHERE severity='critical';
SELECT protocol, COUNT(*) FROM events GROUP BY protocol;
SELECT * FROM events WHERE src_ip='192.168.1.100';
```

## Support and Feedback

### Reporting Issues

When reporting issues, include:
- NetObserver version
- Operating system and version
- Python version
- Steps to reproduce
- Relevant log entries from `~/.NetObserver/logs/`

### Feature Requests

Feature requests should include:
- Use case description
- Expected behavior
- Defensive security justification

## Appendix

### Keyboard Shortcuts

Currently, NetObserver uses menu accelerators:
- Alt+F: File menu
- Alt+C: Capture menu
- Alt+S: Settings menu
- Alt+H: Help menu

### Known Limitations

- No packet reassembly for fragmented traffic
- Limited IPv6 support in simulated mode
- No real-time PCAP writing (export only)
- Parser stubs need full protocol implementation
- Single-threaded capture may drop packets under high load

### Future Enhancements

Planned features:
- IPv6 full support
- Protocol parser completion
- Real-time PCAP recording
- Advanced filtering and search
- Alert correlation engine
- Integration with SIEM systems
- Custom alert rules via GUI
```

# Next Steps Checklist

## Testing NetObserver in Developer Mode

### 1. Environment Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Basic Functionality Test
```bash
# Run the application
python run.py

# Expected behavior:
# - Window opens with black background and white borders
# - All 6 panels visible
# - Central ring indicator shows 0%
# - "Ready" status in helper panel
```

### 3. Capture Testing
- Click "▶ Start" button
- Observe simulated events appearing in:
  - Connections panel (every ~2 seconds)
  - Protocol statistics updating
  - Event logs scrolling
- Watch threat level ring indicator change color as alerts trigger

### 4. Alert System Testing
- Wait for alerts to appear in Alerts panel
- Click ℹ button on alerts to view details
- Verify severity color coding (green/yellow/orange/red)
- Check that threat level ring updates

### 5. Settings Testing
- Open Settings → Preferences
- Navigate through all tabs
- Change values and save
- Verify `~/.NetObserver/configs/config.json` is created

### 6. Export Testing
- With capture running, try File → Export PCAP
- Verify PCAP file is created (though currently stub)

### 7. Log Verification
```bash
# Check logs directory
ls ~/.NetObserver/logs/

# View most recent log
tail -f ~/.NetObserver/logs/netgui_*.log
```

### 8. Database Verification
```bash
# Check database was created
ls ~/.NetObserver/netgui.db

# Query database
sqlite3 ~/.NetObserver/configs/netgui.db "SELECT COUNT(*) FROM events;"
sqlite3 ~/.NetObserver/configs/netgui.db "SELECT COUNT(*) FROM alerts;"
```

### 9. Known Working Modes
- **Simulated Mode**: Works immediately, no dependencies
- **Host Backend**: Works on Linux with `/proc/net` access
- **PCAP Backend**: Requires pyshark installation

### 10. Next Development Steps
1. Complete protocol parser implementations with real packet parsing
2. Implement full PCAP backend with pyshark/scapy
3. Add real-time PCAP writing capability
4. Implement advanced filtering and search
5. Add keyboard shortcuts
6. Create automated tests
7. Add IPv6 full support
8. Implement alert correlation engine

---
# Whitelist Quick Reference Card

## Add to Whitelist
1. Click ⊕ button on alert
2. Choose type
3. Enter reason
4. Click "Add to Whitelist"

## View Whitelist
Settings → Preferences → Whitelist tab

## Toggle Filtered Alerts
Click "🛡️ X Filtered" in alerts panel

## Copy IP
Click 📋 button next to IP in alert

## Export/Import
Settings → Whitelist → Export/Import buttons

## Review Whitelist
Settings → Whitelist → "Mark as Reviewed" button

## Whitelist Types
- **Source IP**: From this IP
- **Destination IP**: To this IP
- **IP Pair**: Specific connection
- **CIDR**: IP range (192.168.1.0/24)
- **Port**: Specific IP:Port
- **Rule**: Disable rule for IP
- **Time**: During time window
- **Protocol**: Specific protocol from IP

## Global Toggle
Settings → Whitelist → "Enable Whitelist" toggle

## Statistics
Settings → Whitelist → Statistics tab

## Audit Log
Settings → Whitelist → Audit Log tab

## Default Settings
- Max alerts: 1000
- Review interval: 180 days (6 months)
- Show filtered: Yes
- Log filtered: Yes

## File Locations
- Config: `~/.NetObserver/configs/whitelist.json`
- Backups: `~/.NetObserver/configs/whitelist_backups/`
- Audit: `~/.NetObserver/configs/whitelist_audit.log`

## Keyboard Shortcuts
None currently - use mouse/UI

## Pro Tips
✓ Always provide clear reasons
✓ Review regularly
✓ Start specific, expand carefully
✓ Monitor filter rate (<75%)
✗ Don't over-whitelist
✗ Don't ignore hit counts
✗ Don't forget reviews

# NetObserver Whitelist System - User Guide

## Overview

The whitelist system allows you to filter out known-safe alerts, reducing false positives and alert fatigue. This guide explains how to use all whitelist features.

## Quick Start

1. **Add Alert to Whitelist**
   - In the Security Alerts panel, click the ⊕ button next to any alert
   - Choose what to whitelist (Source IP, Destination IP, etc.)
   - Provide a reason (required)
   - Click "Add to Whitelist"

2. **Manage Whitelist**
   - Go to Settings → Preferences → Whitelist tab
   - View, edit, or remove entries
   - Export/Import whitelist for backup

3. **View Filtered Alerts**
   - Filtered alerts appear grayed out with 🛡️ WHITELISTED badge
   - Click "🛡️ X Filtered" at top of alerts panel to show/hide them

## Whitelist Types

### 1. Source IP Whitelist
**Use for:** Trusted internal devices that generate legitimate traffic
**Example:** `192.168.1.1` - ISP router login page

### 2. Destination IP Whitelist
**Use for:** Legitimate external services
**Example:** `8.8.8.8` - Google DNS server

### 3. IP Pair Whitelist
**Use for:** Specific connections you know are safe
**Example:** `192.168.1.50 → 10.0.0.5` - Backup server to NAS

### 4. CIDR/Subnet Whitelist
**Use for:** Entire network ranges
**Example:** `192.168.1.0/24` - All internal network

### 5. Port-Based Whitelist
**Use for:** Specific services on specific hosts
**Example:** `10.0.0.5:22` - SSH to my server

### 6. Rule-Specific Whitelist
**Use for:** Disable specific detection rules for certain IPs
**Example:** Disable "Outbound Spike" for web server `192.168.1.100`

### 7. Time-Based Whitelist
**Use for:** Scheduled tasks that trigger alerts
**Example:** Backup server `192.168.1.75` active 2-4 AM

### 8. Protocol-Based Whitelist
**Use for:** Legitimate use of unusual protocols
**Example:** DNS from local DNS server `192.168.1.1`

## Features

### Copy IP Addresses
- Click 📋 button next to any IP in an alert to copy it
- Useful for adding to firewall rules or further investigation

### Alert IDs
- Each alert has a unique ID: `AL-20250115-0042`
- Use IDs to reference alerts in notes or reports
- Searchable in event logs

### Filtered Alert Count
- See `🛡️ X Filtered` at top of Security Alerts panel
- Click to toggle visibility of filtered alerts
- Helps track how many alerts are being suppressed

### Whitelist Statistics
- Settings → Whitelist → Statistics tab
- View total filtered vs alerted
- See filter rate percentage
- Identify most-used whitelist rules

### Audit Log
- Settings → Whitelist → Audit Log tab
- See all whitelist changes
- Track who added/removed entries
- Timestamps for all modifications

### Review Reminders
- Periodic reminder to review whitelist (default: 6 months)
- Configurable interval in settings
- Prevents stale whitelist entries

### Import/Export
- Export whitelist to JSON for backup
- Import on other machines
- Share whitelist with team members

## Best Practices

### ✅ Good Whitelist Usage

1. **Always provide clear reasons**
   - Good: "ISP router - login page checks"
   - Bad: "Router"

2. **Review whitelist regularly**
   - Remove outdated entries
   - Update reasons if network changes
   - Check hit counts to find unused entries

3. **Start specific, expand carefully**
   - Whitelist individual IPs first
   - Only use subnets when you're certain

4. **Monitor filtered count**
   - If >75% of alerts are filtered, adjust detection thresholds instead
   - Balance between reducing noise and maintaining visibility

### ❌ Avoid These Mistakes

1. **Over-whitelisting**
   - Don't whitelist everything just to silence alerts
   - You might miss real threats

2. **Vague reasons**
   - "Ignore this" is not helpful
   - Future you won't remember why

3. **Forgetting reviews**
   - Whitelisted device could be compromised later
   - Network changes make old whitelists invalid

4. **Ignoring hit counts**
   - Zero hits = unused rule, consider removing
   - High hits on specific IP = might need investigation

## Troubleshooting

### Alert still appearing after whitelisting
- Check if entry is enabled (green ✓)
- Verify IP addresses match exactly
- For CIDR, ensure IP is in range
- Check global whitelist toggle is ON

### Too many filtered alerts
- Review whitelist statistics
- Consider adjusting detection thresholds instead
- Some rules might be too broad

### Can't find whitelist file
- Location: `~/.NetObserver/configs/whitelist.json` (Linux)
- Location: `path_to_NetObserver\NetObserver\configs\whitelist.json` (Windows)
- Check file permissions (should be 0600)

### Review reminder not working
- Check review interval in settings
- Ensure app is running when due
- Check logs for errors

## Configuration Files

### whitelist.json
Main whitelist storage

### whitelist_audit.log
All changes logged here

### whitelist_backups/
Last 7 backups kept automatically

## Advanced Usage

### Filter Groups
- Group related whitelist entries
- Enable/disable entire groups at once
- Examples: "Printers & IoT", "Monitoring Systems"

### Learning Mode
- First 24 hours: track frequent alerts
- Suggests IPs for whitelisting
- Accept/reject suggestions in Settings

### Temporary Disable
- Toggle global whitelist OFF for testing
- See all alerts without modifying whitelist
- Useful for troubleshooting

## Security Considerations

⚠️ **Whitelisting reduces visibility**
- You won't see alerts from whitelisted sources
- Compromised whitelisted device = blind spot
- Regular reviews are critical

✅ **Safe whitelisting practices**
- Only whitelist after investigation
- Document why each entry exists
- Review when network topology changes
- Keep backups of whitelist
- Share whitelist changes with team

## Support

For issues or questions:
1. Check logs: `~/.NetObserver/configs/logs/`
2. Review audit log for recent changes
3. Try exporting/reimporting whitelist
4. Check documentation at docs/USAGE.md

**Project Status**: Core framework complete and functional. All UI components working. Capture backends provide working stubs. Ready for testing and incremental feature development.

**Security Stance**: Strictly defensive. No offensive capabilities included. All parsers read-only and metadata-only.