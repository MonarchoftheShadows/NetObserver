"""
Heuristic-based threat detection with configurable thresholds.
Implements simple anomaly detection rules for defensive monitoring.
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import time

from core.logger import get_logger
from core.app_config import AppConfig

logger = get_logger(__name__)


class Alert:
    """Represents a security alert."""
    
    def __init__(self, term: str, count: int, severity: str, explanation: str, 
                 metadata: Dict[str, Any] = None, threat_weight: int = 10):
        """
        Initialize alert.
        
        Args:
            term: Alert identifier/term
            count: Occurrence count
            severity: 'low', 'medium', 'high', or 'critical'
            explanation: Human-readable explanation
            metadata: Additional context
            threat_weight: Weight for threat calculation (1-100)
        """
        self.term = term
        self.count = count
        self.severity = severity
        self.explanation = explanation
        self.metadata = metadata or {}
        self.timestamp = time.time()
        self.threat_weight = threat_weight
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'term': self.term,
            'count': self.count,
            'severity': self.severity,
            'explanation': self.explanation,
            'metadata': self.metadata,
            'timestamp': self.timestamp,
            'threat_weight': self.threat_weight
        }


class Heuristics:
    """
    Heuristic-based threat detection engine with configurable rules.
    """
    
    def __init__(self, config: AppConfig):
        """
        Initialize heuristics engine.
        
        Args:
            config: Application configuration
        """
        self.config = config
        
        # Track connection patterns
        self.port_scan_tracker = defaultdict(set)
        self.dns_failure_tracker = defaultdict(int)
        self.outbound_spike_tracker = defaultdict(list)
        self.failed_auth_tracker = defaultdict(int)
        self.large_transfer_tracker = defaultdict(int)
        self.unusual_protocol_tracker = defaultdict(int)
        self.repeated_connection_tracker = defaultdict(int)
        self.time_anomaly_tracker = defaultdict(list)
        
        logger.info("Heuristics engine initialized with configurable thresholds")
    
    def analyze_event(self, event: Dict[str, Any]) -> Optional[Alert]:
        """
        Analyze event and generate alert if anomaly detected.
        
        Args:
            event: Parsed network event
        
        Returns:
            Alert object if anomaly detected, None otherwise
        """
        try:
            # Check each heuristic if enabled
            if self.config.get('heuristics.port_scan.enabled', True):
                alert = self._check_port_scan(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.dns_failures.enabled', True):
                alert = self._check_dns_failures(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.dga_detection.enabled', True):
                alert = self._check_dga_detection(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.outbound_spike.enabled', True):
                alert = self._check_outbound_spike(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.failed_auth.enabled', True):
                alert = self._check_failed_auth(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.suspicious_ports.enabled', True):
                alert = self._check_suspicious_ports(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.large_transfers.enabled', True):
                alert = self._check_large_transfers(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.unusual_protocols.enabled', False):
                alert = self._check_unusual_protocols(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.repeated_connections.enabled', True):
                alert = self._check_repeated_connections(event)
                if alert:
                    return alert
            
            if self.config.get('heuristics.time_anomalies.enabled', False):
                alert = self._check_time_anomalies(event)
                if alert:
                    return alert
            
            return None
            
        except Exception as e:
            logger.error(f"Error in heuristic analysis: {e}")
            return None
    
    def _check_port_scan(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect potential port scanning activity."""
        src_ip = event.get('src_ip')
        dst_port = event.get('dst_port')
        
        if not src_ip or not dst_port:
            return None
        
        self.port_scan_tracker[src_ip].add(dst_port)
        unique_ports = len(self.port_scan_tracker[src_ip])
        
        threshold = self.config.get('heuristics.port_scan.threshold', 20)
        
        if unique_ports > threshold:
            return Alert(
                term=f"Port Scan from {src_ip}",
                count=unique_ports,
                severity='high',
                explanation=f"Host {src_ip} contacted {unique_ports} unique ports (threshold: {threshold})",
                metadata={'src_ip': src_ip, 'port_count': unique_ports},
                threat_weight=40
            )
        
        return None
    
    def _check_dns_failures(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect DNS anomalies."""
        if event.get('parsed_protocol') != 'DNS':
            return None
        
        domain = event.get('dns_query', '')
        response_code = event.get('dns_response_code', 0)
        
        if response_code == 3:  # NXDOMAIN
            self.dns_failure_tracker[domain] += 1
            
            threshold = self.config.get('heuristics.dns_failures.threshold', 5)
            
            if self.dns_failure_tracker[domain] > threshold:
                return Alert(
                    term=f"Repeated DNS Failure: {domain}",
                    count=self.dns_failure_tracker[domain],
                    severity='medium',
                    explanation=f"Domain {domain} failed DNS resolution {self.dns_failure_tracker[domain]} times (threshold: {threshold})",
                    metadata={'domain': domain},
                    threat_weight=25
                )
        
        return None
    
    def _check_dga_detection(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect DGA-like domains."""
        if event.get('parsed_protocol') != 'DNS':
            return None
        
        domain = event.get('dns_query', '')
        
        if self._is_dga_like(domain):
            return Alert(
                term=f"Suspicious Domain: {domain}",
                count=1,
                severity='high',
                explanation=f"Domain {domain} exhibits DGA-like characteristics",
                metadata={'domain': domain},
                threat_weight=50
            )
        
        return None
    
    def _check_outbound_spike(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect unusual outbound traffic spikes."""
        src_ip = event.get('src_ip', '')
        timestamp = event.get('timestamp', time.time())
        
        if not src_ip.startswith('192.168.') and not src_ip.startswith('10.'):
            return None
        
        self.outbound_spike_tracker[src_ip].append(timestamp)
        
        time_window = self.config.get('heuristics.outbound_spike.time_window', 300)
        cutoff = timestamp - time_window
        self.outbound_spike_tracker[src_ip] = [
            ts for ts in self.outbound_spike_tracker[src_ip] if ts > cutoff
        ]
        
        connection_count = len(self.outbound_spike_tracker[src_ip])
        threshold = self.config.get('heuristics.outbound_spike.threshold', 100)
        
        if connection_count > threshold:
            return Alert(
                term=f"Outbound Spike from {src_ip}",
                count=connection_count,
                severity='medium',
                explanation=f"Host {src_ip} made {connection_count} outbound connections in {time_window}s (threshold: {threshold})",
                metadata={'src_ip': src_ip, 'connection_count': connection_count},
                threat_weight=30
            )
        
        return None
    
    def _check_failed_auth(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect repeated authentication failures."""
        protocol = event.get('parsed_protocol', '')
        dst_ip = event.get('dst_ip')
        dst_port = event.get('dst_port')
        
        if protocol in ['SSH'] or dst_port in [22, 3389]:
            self.failed_auth_tracker[dst_ip] += 1
            
            threshold = self.config.get('heuristics.failed_auth.threshold', 10)
            
            if self.failed_auth_tracker[dst_ip] > threshold:
                return Alert(
                    term=f"Potential Brute Force: {dst_ip}",
                    count=self.failed_auth_tracker[dst_ip],
                    severity='high',
                    explanation=f"Multiple authentication attempts to {dst_ip} detected (threshold: {threshold})",
                    metadata={'dst_ip': dst_ip, 'protocol': protocol},
                    threat_weight=45
                )
        
        return None
    
    def _check_suspicious_ports(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Check for connections to suspicious ports."""
        dst_port = event.get('dst_port', 0)
        dst_ip = event.get('dst_ip', '')
        
        suspicious_ports = {
            4444: 'Metasploit default',
            6667: 'IRC (often used by botnets)',
            31337: 'Back Orifice',
            12345: 'NetBus',
            1337: 'Common backdoor port'
        }
        
        if dst_port in suspicious_ports:
            return Alert(
                term=f"Suspicious Port: {dst_port}",
                count=1,
                severity='critical',
                explanation=f"Connection to suspicious port {dst_port} ({suspicious_ports[dst_port]}) at {dst_ip}",
                metadata={'dst_ip': dst_ip, 'dst_port': dst_port},
                threat_weight=80
            )
        
        return None
    
    def _check_large_transfers(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect large data transfers (potential exfiltration)."""
        src_ip = event.get('src_ip', '')
        length = event.get('length', 0)
        
        if not src_ip.startswith('192.168.') and not src_ip.startswith('10.'):
            return None
        
        self.large_transfer_tracker[src_ip] += length
        
        threshold = self.config.get('heuristics.large_transfers.threshold', 104857600)  # 100MB default
        
        if self.large_transfer_tracker[src_ip] > threshold:
            mb_transferred = self.large_transfer_tracker[src_ip] / (1024 * 1024)
            threshold_mb = threshold / (1024 * 1024)
            return Alert(
                term=f"Large Data Transfer: {src_ip}",
                count=int(mb_transferred),
                severity='medium',
                explanation=f"Host {src_ip} has transferred {mb_transferred:.2f} MB of data (threshold: {threshold_mb:.0f} MB)",
                metadata={'src_ip': src_ip, 'bytes': self.large_transfer_tracker[src_ip]},
                threat_weight=35
            )
        
        return None
    
    def _check_unusual_protocols(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect unusual or uncommon protocols."""
        protocol = event.get('protocol', '')
        
        self.unusual_protocol_tracker[protocol] += 1
        
        unusual_protocols = ['TELNET', 'FTP', 'TFTP', 'SNMP']
        
        if protocol in unusual_protocols and self.unusual_protocol_tracker[protocol] == 1:
            return Alert(
                term=f"Unusual Protocol: {protocol}",
                count=1,
                severity='low',
                explanation=f"Detected use of uncommon protocol: {protocol}",
                metadata={'protocol': protocol},
                threat_weight=15
            )
        
        return None
    
    def _check_repeated_connections(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect repeated connections to same destination."""
        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')
        dst_port = event.get('dst_port', 0)
        
        connection_key = f"{src_ip}->{dst_ip}:{dst_port}"
        self.repeated_connection_tracker[connection_key] += 1
        
        threshold = self.config.get('heuristics.repeated_connections.threshold', 50)
        
        if self.repeated_connection_tracker[connection_key] > threshold:
            return Alert(
                term=f"Repeated Connection: {connection_key}",
                count=self.repeated_connection_tracker[connection_key],
                severity='low',
                explanation=f"Host repeatedly connecting to {dst_ip}:{dst_port} ({self.repeated_connection_tracker[connection_key]} times, threshold: {threshold})",
                metadata={'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port},
                threat_weight=20
            )
        
        return None
    
    def _check_time_anomalies(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Detect connections during unusual hours."""
        timestamp = event.get('timestamp', time.time())
        hour = time.localtime(timestamp).tm_hour
        
        start_hour = self.config.get('heuristics.time_anomalies.start_hour', 2)
        end_hour = self.config.get('heuristics.time_anomalies.end_hour', 5)
        
        # Check if current hour is in the off-hours range
        if start_hour <= end_hour:
            in_off_hours = start_hour <= hour <= end_hour
        else:  # Handle wrap-around (e.g., 22:00 to 6:00)
            in_off_hours = hour >= start_hour or hour <= end_hour
        
        if in_off_hours:
            self.time_anomaly_tracker[hour].append(timestamp)
            
            recent_count = len([t for t in self.time_anomaly_tracker[hour] 
                               if timestamp - t < 3600])  # Last hour
            
            threshold = self.config.get('heuristics.time_anomalies.threshold', 20)
            
            if recent_count > threshold:
                return Alert(
                    term=f"Off-Hours Activity: {hour}:00",
                    count=recent_count,
                    severity='medium',
                    explanation=f"Unusual network activity detected at {hour}:00 ({recent_count} connections, threshold: {threshold})",
                    metadata={'hour': hour, 'count': recent_count},
                    threat_weight=28
                )
        
        return None
    
    def _is_dga_like(self, domain: str) -> bool:
        """Check if domain exhibits DGA-like characteristics."""
        if not domain or domain == 'unknown.domain':
            return False
        
        if len(domain) > 30:
            return True
        
        consonants = sum(1 for c in domain.lower() if c in 'bcdfghjklmnpqrstvwxyz')
        if len(domain) > 10 and consonants / len(domain) > 0.7:
            return True
        
        for i in range(len(domain) - 3):
            substring = domain[i:i+4]
            if all(c in 'bcdfghjklmnpqrstvwxyz' for c in substring.lower()):
                return True
        
        return False