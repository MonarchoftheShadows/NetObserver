"""
Whitelist management system for filtering security alerts.
Supports multiple filter types and provides centralized whitelist matching.
"""

import json
import time
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from core.logger import get_logger

logger = get_logger(__name__)


class WhitelistManager:
    """
    Manages whitelist entries and determines if alerts should be filtered.
    """
    
    def __init__(self, config_dir: Path):
        """
        Initialize whitelist manager.
        
        Args:
            config_dir: Configuration directory path
        """
        self.config_dir = config_dir
        self.whitelist_file = config_dir / "whitelist.json"
        self.backup_dir = config_dir / "whitelist_backups"
        self.audit_log_file = config_dir / "whitelist_audit.log"
        
        # Ensure backup directory exists
        self.backup_dir.mkdir(exist_ok=True)
        
        # Load whitelist
        self.whitelist = self._load_whitelist()
        
        # Performance optimization: pre-compile sets and dictionaries
        self._rebuild_lookup_structures()
        
        logger.info("Whitelist manager initialized")
    
    def _load_whitelist(self) -> Dict[str, Any]:
        """Load whitelist from file or create default."""
        default_whitelist = {
            "version": "1.0",
            "last_review": datetime.now().isoformat(),
            "next_review": (datetime.now() + timedelta(days=180)).isoformat(),
            "review_interval_days": 180,
            "whitelist_enabled": True,
            "show_filtered_alerts": True,
            "log_filtered_alerts": True,
            
            "source_ip": [],
            "destination_ip": [],
            "ip_pair": [],
            "cidr_subnet": [],
            "port_based": [],
            "rule_specific": [],
            "time_based": [],
            "protocol_based": [],
            "filter_groups": [],
            
            "learning_mode": {
                "enabled": False,
                "started": None,
                "duration_hours": 24,
                "suggestions": []
            },
            
            "statistics": {
                "total_filtered": 0,
                "total_alerted": 0,
                "last_reset": datetime.now().isoformat()
            }
        }
        
        if not self.whitelist_file.exists():
            self._save_whitelist(default_whitelist)
            return default_whitelist
        
        try:
            with open(self.whitelist_file, 'r') as f:
                whitelist = json.load(f)
                logger.info("Whitelist loaded successfully")
                return whitelist
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
            return default_whitelist
    
    def _save_whitelist(self, whitelist: Dict[str, Any] = None) -> None:
        """Save whitelist to file with backup."""
        if whitelist is None:
            whitelist = self.whitelist
        
        try:
            # Create backup before saving
            self._create_backup()
            
            # Save whitelist
            with open(self.whitelist_file, 'w') as f:
                json.dump(whitelist, f, indent=2)
            
            logger.info("Whitelist saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")
    
    def _create_backup(self) -> None:
        """Create backup of current whitelist."""
        try:
            if self.whitelist_file.exists():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_file = self.backup_dir / f"whitelist_backup_{timestamp}.json"
                
                with open(self.whitelist_file, 'r') as f:
                    data = f.read()
                
                with open(backup_file, 'w') as f:
                    f.write(data)
                
                # Keep only last 7 backups
                self._cleanup_old_backups()
                
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
    
    def _cleanup_old_backups(self) -> None:
        """Keep only the last 7 backups."""
        try:
            backups = sorted(self.backup_dir.glob("whitelist_backup_*.json"))
            while len(backups) > 7:
                oldest = backups.pop(0)
                oldest.unlink()
                logger.debug(f"Deleted old backup: {oldest}")
        except Exception as e:
            logger.error(f"Failed to cleanup backups: {e}")
    
    def _rebuild_lookup_structures(self) -> None:
        """Rebuild optimized lookup structures for fast matching."""
        # Source IP set (O(1) lookup)
        self.source_ip_set = set(
            entry['ip'] for entry in self.whitelist['source_ip'] 
            if entry.get('enabled', True)
        )
        
        # Destination IP set
        self.destination_ip_set = set(
            entry['ip'] for entry in self.whitelist['destination_ip']
            if entry.get('enabled', True)
        )
        
        # IP pair set
        self.ip_pair_set = set(
            (entry['source_ip'], entry['destination_ip'])
            for entry in self.whitelist['ip_pair']
            if entry.get('enabled', True)
        )
        
        # Port-based dictionary
        self.port_whitelist = {}
        for entry in self.whitelist['port_based']:
            if entry.get('enabled', True):
                key = (entry['ip'], entry['port'], entry['direction'])
                self.port_whitelist[key] = entry
        
        # Rule-specific dictionary
        self.rule_whitelist = defaultdict(set)
        for entry in self.whitelist['rule_specific']:
            if entry.get('enabled', True):
                self.rule_whitelist[entry['rule_name']].add(entry['source_ip'])
        
        # CIDR networks
        self.cidr_networks = []
        for entry in self.whitelist['cidr_subnet']:
            if entry.get('enabled', True):
                try:
                    network = ipaddress.ip_network(entry['subnet'])
                    self.cidr_networks.append((network, entry['direction'], entry))
                except Exception as e:
                    logger.error(f"Invalid CIDR: {entry['subnet']}: {e}")
        
        logger.debug("Lookup structures rebuilt")
    
    def should_filter_alert(self, event: Dict[str, Any], alert_type: str) -> Tuple[bool, Optional[str]]:
        """
        Determine if an alert should be filtered based on whitelist.
        
        Args:
            event: Network event that triggered the alert
            alert_type: Type of alert (e.g., 'port_scan', 'outbound_spike')
        
        Returns:
            Tuple of (should_filter: bool, reason: str or None)
        """
        # Check if whitelist is globally disabled
        if not self.whitelist.get('whitelist_enabled', True):
            return False, None
        
        # Extract event details
        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')
        dst_port = event.get('dst_port', 0)
        protocol = event.get('protocol', '')
        timestamp = event.get('timestamp', time.time())
        current_hour = time.localtime(timestamp).tm_hour
        
        # Check learning mode
        if self.whitelist['learning_mode'].get('enabled', False):
            self._track_for_learning(event, alert_type)
        
        # 1. Source IP whitelist (fastest check)
        if src_ip in self.source_ip_set:
            entry = self._find_entry('source_ip', 'ip', src_ip)
            if entry:
                self._record_hit(entry)
                return True, f"Source IP whitelisted: {entry.get('reason', 'No reason')}"
        
        # 2. Destination IP whitelist
        if dst_ip in self.destination_ip_set:
            entry = self._find_entry('destination_ip', 'ip', dst_ip)
            if entry:
                self._record_hit(entry)
                return True, f"Destination IP whitelisted: {entry.get('reason', 'No reason')}"
        
        # 3. IP pair whitelist
        if (src_ip, dst_ip) in self.ip_pair_set:
            entry = self._find_ip_pair_entry(src_ip, dst_ip)
            if entry:
                self._record_hit(entry)
                return True, f"IP pair whitelisted: {entry.get('reason', 'No reason')}"
        
        # 4. CIDR/Subnet whitelist
        cidr_match = self._check_cidr_whitelist(src_ip, dst_ip)
        if cidr_match:
            entry, reason = cidr_match
            self._record_hit(entry)
            return True, reason
        
        # 5. Rule-specific whitelist
        if alert_type in self.rule_whitelist:
            if src_ip in self.rule_whitelist[alert_type]:
                entry = self._find_rule_specific_entry(alert_type, src_ip)
                if entry:
                    self._record_hit(entry)
                    return True, f"Rule exception: {entry.get('reason', 'No reason')}"
        
        # 6. Port-based whitelist
        if dst_port:
            port_match = self._check_port_whitelist(dst_ip, dst_port)
            if port_match:
                entry, reason = port_match
                self._record_hit(entry)
                return True, reason
        
        # 7. Time-based whitelist
        time_match = self._check_time_whitelist(src_ip, current_hour)
        if time_match:
            entry, reason = time_match
            self._record_hit(entry)
            return True, reason
        
        # 8. Protocol-based whitelist
        if protocol:
            protocol_match = self._check_protocol_whitelist(protocol, src_ip)
            if protocol_match:
                entry, reason = protocol_match
                self._record_hit(entry)
                return True, reason
        
        # Not whitelisted
        return False, None
    
    def _find_entry(self, category: str, field: str, value: str) -> Optional[Dict[str, Any]]:
        """Find entry in whitelist category by field value."""
        for entry in self.whitelist[category]:
            if entry.get('enabled', True) and entry.get(field) == value:
                return entry
        return None
    
    def _find_ip_pair_entry(self, src_ip: str, dst_ip: str) -> Optional[Dict[str, Any]]:
        """Find IP pair entry."""
        for entry in self.whitelist['ip_pair']:
            if (entry.get('enabled', True) and 
                entry.get('source_ip') == src_ip and 
                entry.get('destination_ip') == dst_ip):
                return entry
        return None
    
    def _find_rule_specific_entry(self, rule_name: str, src_ip: str) -> Optional[Dict[str, Any]]:
        """Find rule-specific entry."""
        for entry in self.whitelist['rule_specific']:
            if (entry.get('enabled', True) and 
                entry.get('rule_name') == rule_name and 
                entry.get('source_ip') == src_ip):
                return entry
        return None
    
    def _check_cidr_whitelist(self, src_ip: str, dst_ip: str) -> Optional[Tuple[Dict[str, Any], str]]:
        """Check if IP matches any CIDR whitelist."""
        try:
            for network, direction, entry in self.cidr_networks:
                check_ip = src_ip if direction == 'source' else dst_ip
                if ipaddress.ip_address(check_ip) in network:
                    reason = f"Subnet {entry['subnet']} whitelisted: {entry.get('reason', 'No reason')}"
                    return entry, reason
        except Exception as e:
            logger.debug(f"CIDR check error: {e}")
        
        return None
    
    def _check_port_whitelist(self, dst_ip: str, dst_port: int) -> Optional[Tuple[Dict[str, Any], str]]:
        """Check port-based whitelist."""
        key = (dst_ip, dst_port, 'destination')
        if key in self.port_whitelist:
            entry = self.port_whitelist[key]
            reason = f"Port {dst_port} on {dst_ip} whitelisted: {entry.get('reason', 'No reason')}"
            return entry, reason
        return None
    
    def _check_time_whitelist(self, src_ip: str, current_hour: int) -> Optional[Tuple[Dict[str, Any], str]]:
        """Check time-based whitelist."""
        for entry in self.whitelist['time_based']:
            if not entry.get('enabled', True):
                continue
            
            if entry.get('source_ip') != src_ip:
                continue
            
            start_hour = entry.get('start_hour', 0)
            end_hour = entry.get('end_hour', 0)
            
            # Handle wrap-around (e.g., 22:00 to 6:00)
            if start_hour <= end_hour:
                in_range = start_hour <= current_hour <= end_hour
            else:
                in_range = current_hour >= start_hour or current_hour <= end_hour
            
            if in_range:
                reason = f"Time-based filter ({start_hour}:00-{end_hour}:00): {entry.get('reason', 'No reason')}"
                return entry, reason
        
        return None
    
    def _check_protocol_whitelist(self, protocol: str, src_ip: str) -> Optional[Tuple[Dict[str, Any], str]]:
        """Check protocol-based whitelist."""
        for entry in self.whitelist['protocol_based']:
            if (entry.get('enabled', True) and 
                entry.get('protocol') == protocol and 
                entry.get('source_ip') == src_ip):
                reason = f"Protocol {protocol} from {src_ip} whitelisted: {entry.get('reason', 'No reason')}"
                return entry, reason
        return None
    
    def _record_hit(self, entry: Dict[str, Any]) -> None:
        """Record that a whitelist entry was hit."""
        if 'hit_count' not in entry:
            entry['hit_count'] = 0
        entry['hit_count'] += 1
        entry['last_hit'] = datetime.now().isoformat()
        
        # Update statistics
        self.whitelist['statistics']['total_filtered'] += 1
        
        # Save periodically (every 10 hits to avoid excessive I/O)
        if self.whitelist['statistics']['total_filtered'] % 10 == 0:
            self._save_whitelist()
    
    def _track_for_learning(self, event: Dict[str, Any], alert_type: str) -> None:
        """Track event for learning mode suggestions."""
        # Check if learning mode is still active
        learning = self.whitelist['learning_mode']
        if not learning.get('enabled'):
            return
        
        started = learning.get('started')
        if started:
            started_time = datetime.fromisoformat(started)
            duration = timedelta(hours=learning.get('duration_hours', 24))
            
            if datetime.now() > started_time + duration:
                # Learning mode expired
                learning['enabled'] = False
                self._save_whitelist()
                return
        
        # Track suggestion
        src_ip = event.get('src_ip', '')
        if not src_ip:
            return
        
        # Find or create suggestion
        suggestions = learning['suggestions']
        suggestion = None
        for s in suggestions:
            if s.get('type') == 'source_ip' and s.get('value') == src_ip:
                suggestion = s
                break
        
        if suggestion:
            suggestion['alert_count'] += 1
        else:
            suggestions.append({
                'type': 'source_ip',
                'value': src_ip,
                'alert_count': 1,
                'alert_types': [alert_type],
                'suggested_reason': f"Frequent {alert_type} alerts"
            })
    
    def add_whitelist_entry(self, category: str, entry_data: Dict[str, Any], user: str = "user") -> str:
        """
        Add new whitelist entry.
        
        Args:
            category: Whitelist category (e.g., 'source_ip')
            entry_data: Entry data dictionary
            user: User who added the entry
        
        Returns:
            Entry ID
        """
        # Generate unique ID
        entry_id = f"wl_{int(time.time())}_{len(self.whitelist[category])}"
        
        # Add metadata
        entry = {
            'id': entry_id,
            **entry_data,
            'added_date': datetime.now().isoformat(),
            'added_by': user,
            'enabled': entry_data.get('enabled', True),
            'hit_count': 0
        }
        
        # Add to whitelist
        self.whitelist[category].append(entry)
        
        # Rebuild lookup structures
        self._rebuild_lookup_structures()
        
        # Save
        self._save_whitelist()
        
        # Audit log
        self._audit_log('ADD', category, entry_id, entry_data, user)
        
        logger.info(f"Added whitelist entry: {category}/{entry_id}")
        
        return entry_id
    
    def remove_whitelist_entry(self, category: str, entry_id: str, user: str = "user") -> bool:
        """
        Remove whitelist entry.
        
        Args:
            category: Whitelist category
            entry_id: Entry ID to remove
            user: User who removed the entry
        
        Returns:
            True if removed, False if not found
        """
        entries = self.whitelist[category]
        for i, entry in enumerate(entries):
            if entry.get('id') == entry_id:
                removed_entry = entries.pop(i)
                
                # Rebuild lookup structures
                self._rebuild_lookup_structures()
                
                # Save
                self._save_whitelist()
                
                # Audit log
                self._audit_log('REMOVE', category, entry_id, removed_entry, user)
                
                logger.info(f"Removed whitelist entry: {category}/{entry_id}")
                return True
        
        return False
    
    def update_whitelist_entry(self, category: str, entry_id: str, updates: Dict[str, Any], user: str = "user") -> bool:
        """
        Update whitelist entry.
        
        Args:
            category: Whitelist category
            entry_id: Entry ID to update
            updates: Dictionary of fields to update
            user: User who updated the entry
        
        Returns:
            True if updated, False if not found
        """
        for entry in self.whitelist[category]:
            if entry.get('id') == entry_id:
                old_entry = entry.copy()
                entry.update(updates)
                entry['modified_date'] = datetime.now().isoformat()
                entry['modified_by'] = user
                
                # Rebuild lookup structures
                self._rebuild_lookup_structures()
                
                # Save
                self._save_whitelist()
                
                # Audit log
                self._audit_log('UPDATE', category, entry_id, {'old': old_entry, 'new': entry}, user)
                
                logger.info(f"Updated whitelist entry: {category}/{entry_id}")
                return True
        
        return False
    
    def _audit_log(self, action: str, category: str, entry_id: str, data: Dict[str, Any], user: str) -> None:
        """Write to audit log."""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'category': category,
                'entry_id': entry_id,
                'user': user,
                'data': data
            }
            
            with open(self.audit_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def export_whitelist(self, filepath: str) -> bool:
        """Export whitelist to JSON file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.whitelist, f, indent=2)
            logger.info(f"Whitelist exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export whitelist: {e}")
            return False
    
    def import_whitelist(self, filepath: str, merge: bool = False) -> bool:
        """
        Import whitelist from JSON file.
        
        Args:
            filepath: Path to JSON file
            merge: If True, merge with existing. If False, replace.
        
        Returns:
            True if successful
        """
        try:
            with open(filepath, 'r') as f:
                imported = json.load(f)
            
            if merge:
                # Merge entries from each category
                for category in ['source_ip', 'destination_ip', 'ip_pair', 'cidr_subnet',
                                'port_based', 'rule_specific', 'time_based', 'protocol_based']:
                    if category in imported:
                        self.whitelist[category].extend(imported[category])
            else:
                # Replace entire whitelist
                self.whitelist = imported
            
            # Rebuild and save
            self._rebuild_lookup_structures()
            self._save_whitelist()
            
            logger.info(f"Whitelist imported from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import whitelist: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get whitelist statistics."""
        stats = self.whitelist['statistics'].copy()
        
        # Count active entries by category
        stats['active_entries'] = {}
        for category in ['source_ip', 'destination_ip', 'ip_pair', 'cidr_subnet',
                        'port_based', 'rule_specific', 'time_based', 'protocol_based']:
            active = sum(1 for entry in self.whitelist[category] if entry.get('enabled', True))
            stats['active_entries'][category] = active
        
        stats['total_active'] = sum(stats['active_entries'].values())
        
        # Calculate filter rate
        total = stats['total_filtered'] + stats['total_alerted']
        if total > 0:
            stats['filter_rate'] = (stats['total_filtered'] / total) * 100
        else:
            stats['filter_rate'] = 0
        
        return stats
    
    def check_review_due(self) -> bool:
        """Check if whitelist review is due."""
        next_review = self.whitelist.get('next_review')
        if not next_review:
            return False
        
        try:
            next_review_date = datetime.fromisoformat(next_review)
            return datetime.now() >= next_review_date
        except:
            return False
    
    def mark_reviewed(self) -> None:
        """Mark whitelist as reviewed and set next review date."""
        interval_days = self.whitelist.get('review_interval_days', 180)
        
        self.whitelist['last_review'] = datetime.now().isoformat()
        self.whitelist['next_review'] = (datetime.now() + timedelta(days=interval_days)).isoformat()
        
        self._save_whitelist()
        logger.info("Whitelist marked as reviewed")