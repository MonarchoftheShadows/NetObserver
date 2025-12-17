"""
Central orchestrator for NetGUI application.
Coordinates communication between capture, parsing, analytics, and UI components.
"""

from typing import Optional, Dict, Any
from PyQt6.QtCore import QObject, pyqtSignal
import struct
import json
from core.logger import get_logger
from core.app_config import AppConfig
from core.whitelist_manager import WhitelistManager  # NEW
from core.review_scheduler import ReviewScheduler  # NEW
from capture.capture_manager import CaptureManager
from parsers.parser_manager import ParserManager
from analytics.alert_engine import AlertEngine
from storage.db import Database

logger = get_logger(__name__)


class Orchestrator(QObject):
    """
    Central coordinator for all application components.
    Emits Qt signals for UI updates and handles business logic.
    """
    
    # Signals for UI updates
    new_event = pyqtSignal(dict)  # Raw network event
    new_alert = pyqtSignal(dict)  # New alert generated
    capture_started = pyqtSignal()
    capture_stopped = pyqtSignal()
    status_changed = pyqtSignal(str)  # Status message
    threat_level_changed = pyqtSignal(int)  # Threat level 0-100
    whitelist_review_due = pyqtSignal()  # NEW: Whitelist review reminder
    
    def __init__(self):
        """Initialize orchestrator and all subsystems."""
        super().__init__()
        
        logger.info("Initializing orchestrator")
        
        # Initialize configuration
        self.config = AppConfig()
        
        # Initialize database
        self.database = Database()
        
        # Initialize whitelist manager (NEW)
        self.whitelist_manager = WhitelistManager(self.config.config_dir)
        
        # Initialize review scheduler (NEW)
        self.review_scheduler = ReviewScheduler(self.whitelist_manager)
        self.review_scheduler.review_due.connect(self.whitelist_review_due.emit)
        
        # Initialize capture manager
        self.capture_manager = CaptureManager(self.config)
        self.capture_manager.event_captured.connect(self._handle_captured_event)
        
        # Initialize parser manager
        self.parser_manager = ParserManager()
        
        # Initialize alert engine with whitelist manager (UPDATED)
        self.alert_engine = AlertEngine(self.config, self.whitelist_manager)
        self.alert_engine.alert_generated.connect(self._handle_alert)
        
        # State tracking
        self.is_capturing = False
        self.event_count = 0
        self.alert_count = 0
        self.recent_alerts = []  # Store recent alerts with weights
        
        logger.info("Orchestrator initialized successfully")
    
    def start_capture(self, source: str = "auto") -> bool:
        """Start network capture."""
        try:
            logger.info(f"Starting capture from source: {source}")
            
            success = self.capture_manager.start_capture(source)
            
            if success:
                self.is_capturing = True
                self.capture_started.emit()
                self.status_changed.emit("Capturing...")
                logger.info("Capture started successfully")
                return True
            else:
                self.status_changed.emit("Failed to start capture")
                logger.error("Failed to start capture")
                return False
                
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            self.status_changed.emit(f"Error: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """Stop network capture."""
        try:
            logger.info("Stopping capture")
            
            self.capture_manager.stop_capture()
            self.is_capturing = False
            self.capture_stopped.emit()
            self.status_changed.emit("Stopped")
            
            logger.info(f"Capture stopped. Total events: {self.event_count}, Alerts: {self.alert_count}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            return False
    
    def export_pcap(self, filepath: str) -> bool:
        """Export captured packets to PCAP file."""
        # try:
        #     logger.info(f"Exporting PCAP to: {filepath}")
        #     self.status_changed.emit(f"PCAP exported to {filepath}")
        #     return True
        # except Exception as e:
        #     logger.error(f"Error exporting PCAP: {e}")
        #     self.status_changed.emit(f"Export failed: {e}")
        #     return False
        
        
        """ new pcap export function
        Export captured events to PCAP file.
        Reconstructs network packets from stored event data and writes to PCAP format.
        
        Args:
            filepath: Output file path for PCAP
        
        Returns:
            True if successful, False otherwise
        """
        try:
            from storage.pcap_writer import PcapWriter
            import struct
            
            logger.info(f"Starting PCAP export to: {filepath}")
            self.status_changed.emit("Exporting PCAP...")
            
            # Query all events from database
            cursor = self.database.conn.cursor()
            cursor.execute("""
                SELECT timestamp, protocol, src_ip, dst_ip, src_port, dst_port, metadata
                FROM events
                ORDER BY timestamp ASC
            """)
            
            events = cursor.fetchall()
            
            if not events:
                logger.warning("No events to export")
                self.status_changed.emit("No events to export")
                return False
            
            logger.info(f"Exporting {len(events)} events to PCAP")
            
            # Initialize PCAP writer
            writer = PcapWriter(filepath)
            if not writer.open():
                logger.error("Failed to open PCAP file for writing")
                self.status_changed.emit("Failed to create PCAP file")
                return False
            
            # Convert each event to packet and write
            exported_count = 0
            for event in events:
                try:
                    packet_data = self._event_to_packet(event)
                    if packet_data:
                        writer.write_packet(packet_data, event[0])  # event[0] is timestamp
                        exported_count += 1
                except Exception as e:
                    logger.debug(f"Failed to convert event to packet: {e}")
                    continue
            
            writer.close()
            
            logger.info(f"Successfully exported {exported_count}/{len(events)} packets to {filepath}")
            self.status_changed.emit(f"Exported {exported_count} packets to PCAP")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting PCAP: {e}")
            self.status_changed.emit(f"Export failed: {e}")
            return False

    def _event_to_packet(self, event) -> Optional[bytes]:
        """
        Convert database event to raw packet bytes.
        Reconstructs Ethernet + IP + TCP/UDP packet from event data.
        
        Args:
            event: Database row (timestamp, protocol, src_ip, dst_ip, src_port, dst_port, metadata)
        
        Returns:
            Packet bytes or None if conversion fails
        """
        try:
            import struct
            import json
            
            # Extract event fields
            timestamp, protocol, src_ip, dst_ip, src_port, dst_port, metadata_json = event
            
            # Parse metadata
            try:
                metadata = json.loads(metadata_json) if metadata_json else {}
            except:
                metadata = {}
            
            # Convert IP strings to bytes
            src_ip_bytes = self._ip_to_bytes(src_ip)
            dst_ip_bytes = self._ip_to_bytes(dst_ip)
            
            if not src_ip_bytes or not dst_ip_bytes:
                return None
            
            # Build packet based on protocol
            if protocol.upper() in ['TCP', 'HTTP', 'HTTPS', 'TLS', 'SSH']:
                packet = self._build_tcp_packet(src_ip_bytes, dst_ip_bytes, src_port, dst_port, metadata)
            elif protocol.upper() in ['UDP', 'DNS']:
                packet = self._build_udp_packet(src_ip_bytes, dst_ip_bytes, src_port, dst_port, metadata)
            elif protocol.upper() == 'ICMP':
                packet = self._build_icmp_packet(src_ip_bytes, dst_ip_bytes, metadata)
            else:
                # Default to TCP for unknown protocols
                packet = self._build_tcp_packet(src_ip_bytes, dst_ip_bytes, src_port or 0, dst_port or 0, metadata)
            
            return packet
            
        except Exception as e:
            logger.debug(f"Error converting event to packet: {e}")
            return None

    def _ip_to_bytes(self, ip_str: str) -> Optional[bytes]:
        """
        Convert IP address string to 4-byte representation.
        
        Args:
            ip_str: IP address string (e.g., "192.168.1.1")
        
        Returns:
            4 bytes or None if invalid
        """
        try:
            if not ip_str or ip_str == '0.0.0.0':
                return None
            
            parts = ip_str.split('.')
            if len(parts) != 4:
                return None
            
            return bytes([int(p) for p in parts])
        except:
            return None

    def _build_ethernet_header(self) -> bytes:
        """
        Build Ethernet frame header.
        Uses generic MAC addresses since we don't have real MAC data.
        
        Returns:
            14-byte Ethernet header
        """
        # Destination MAC (00:00:00:00:00:00)
        dst_mac = b'\x00\x00\x00\x00\x00\x00'
        # Source MAC (00:00:00:00:00:00)
        src_mac = b'\x00\x00\x00\x00\x00\x00'
        # EtherType: IPv4 (0x0800)
        ethertype = struct.pack('!H', 0x0800)
        
        return dst_mac + src_mac + ethertype

    def _build_ip_header(self, src_ip: bytes, dst_ip: bytes, protocol: int, payload_len: int) -> bytes:
        """
        Build IPv4 header.
        
        Args:
            src_ip: Source IP (4 bytes)
            dst_ip: Destination IP (4 bytes)
            protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
            payload_len: Length of payload after IP header
        
        Returns:
            20-byte IPv4 header
        """
        # IP version (4) and header length (5 * 4 = 20 bytes)
        version_ihl = 0x45
        # Type of service
        tos = 0
        # Total length (IP header + payload)
        total_len = 20 + payload_len
        # Identification
        identification = 0
        # Flags and fragment offset
        flags_frag = 0
        # TTL
        ttl = 64
        # Protocol
        proto = protocol
        # Header checksum (will calculate)
        checksum = 0
        
        # Build header without checksum
        header = struct.pack('!BBHHHBBH',
                            version_ihl, tos, total_len,
                            identification, flags_frag,
                            ttl, proto, checksum)
        header += src_ip + dst_ip
        
        # Calculate checksum
        checksum = self._calculate_checksum(header)
        
        # Rebuild with correct checksum
        header = struct.pack('!BBHHHBBH',
                            version_ihl, tos, total_len,
                            identification, flags_frag,
                            ttl, proto, checksum)
        header += src_ip + dst_ip
        
        return header

    def _build_tcp_packet(self, src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int, metadata: dict) -> bytes:
        """
        Build complete TCP packet (Ethernet + IP + TCP).
        
        Args:
            src_ip: Source IP (4 bytes)
            dst_ip: Destination IP (4 bytes)
            src_port: Source port
            dst_port: Destination port
            metadata: Additional metadata (length, flags, etc.)
        
        Returns:
            Complete packet bytes
        """
        # TCP header fields
        seq_num = 0
        ack_num = 0
        # Data offset (5 * 4 = 20 bytes, no options)
        data_offset = 5 << 4
        # TCP flags (SYN by default)
        flags = 0x02
        # Window size
        window = 65535
        # Checksum (will calculate)
        checksum = 0
        # Urgent pointer
        urgent = 0
        
        # Build TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port,
                                seq_num, ack_num,
                                data_offset, flags,
                                window, checksum, urgent)
        
        # Optional payload (empty for now)
        payload = b''
        
        # Calculate TCP checksum with pseudo-header
        pseudo_header = src_ip + dst_ip + struct.pack('!BBH', 0, 6, len(tcp_header) + len(payload))
        checksum = self._calculate_checksum(pseudo_header + tcp_header + payload)
        
        # Rebuild TCP header with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port,
                                seq_num, ack_num,
                                data_offset, flags,
                                window, checksum, urgent)
        
        # Build IP header (protocol 6 = TCP)
        ip_header = self._build_ip_header(src_ip, dst_ip, 6, len(tcp_header) + len(payload))
        
        # Build Ethernet header
        eth_header = self._build_ethernet_header()
        
        return eth_header + ip_header + tcp_header + payload

    def _build_udp_packet(self, src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int, metadata: dict) -> bytes:
        """
        Build complete UDP packet (Ethernet + IP + UDP).
        
        Args:
            src_ip: Source IP (4 bytes)
            dst_ip: Destination IP (4 bytes)
            src_port: Source port
            dst_port: Destination port
            metadata: Additional metadata
        
        Returns:
            Complete packet bytes
        """
        # Optional payload (empty for now)
        payload = b''
        
        # UDP header
        length = 8 + len(payload)  # UDP header is 8 bytes
        checksum = 0  # Optional for IPv4
        
        udp_header = struct.pack('!HHHH',
                                src_port, dst_port,
                                length, checksum)
        
        # Calculate UDP checksum with pseudo-header
        pseudo_header = src_ip + dst_ip + struct.pack('!BBH', 0, 17, length)
        checksum = self._calculate_checksum(pseudo_header + udp_header + payload)
        
        # Rebuild UDP header with correct checksum
        udp_header = struct.pack('!HHHH',
                                src_port, dst_port,
                                length, checksum)
        
        # Build IP header (protocol 17 = UDP)
        ip_header = self._build_ip_header(src_ip, dst_ip, 17, len(udp_header) + len(payload))
        
        # Build Ethernet header
        eth_header = self._build_ethernet_header()
        
        return eth_header + ip_header + udp_header + payload

    def _build_icmp_packet(self, src_ip: bytes, dst_ip: bytes, metadata: dict) -> bytes:
        """
        Build complete ICMP packet (Ethernet + IP + ICMP).
        
        Args:
            src_ip: Source IP (4 bytes)
            dst_ip: Destination IP (4 bytes)
            metadata: Additional metadata
        
        Returns:
            Complete packet bytes
        """
        # ICMP Echo Request (type 8, code 0)
        icmp_type = 8
        icmp_code = 0
        checksum = 0
        identifier = 0
        sequence = 0
        
        # Build ICMP header
        icmp_header = struct.pack('!BBHHH',
                                icmp_type, icmp_code,
                                checksum,
                                identifier, sequence)
        
        # Calculate checksum
        checksum = self._calculate_checksum(icmp_header)
        
        # Rebuild with correct checksum
        icmp_header = struct.pack('!BBHHH',
                                icmp_type, icmp_code,
                                checksum,
                                identifier, sequence)
        
        # Build IP header (protocol 1 = ICMP)
        ip_header = self._build_ip_header(src_ip, dst_ip, 1, len(icmp_header))
        
        # Build Ethernet header
        eth_header = self._build_ethernet_header()
        
        return eth_header + ip_header + icmp_header

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate Internet checksum (RFC 1071).
        
        Args:
            data: Bytes to checksum
        
        Returns:
            16-bit checksum
        """
        # Pad if odd length
        if len(data) % 2 == 1:
            data += b'\x00'
        
        # Sum all 16-bit words
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
        
        # Add carry bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        # One's complement
        return ~total & 0xFFFF
    

    # new pcap ends here 

    def open_settings(self) -> None:
        """Open settings dialog."""
        from core.app_config import SettingsDialog
        from PyQt6.QtWidgets import QApplication
        
        logger.info("Opening settings dialog")
        dialog = SettingsDialog(self.config, self.whitelist_manager)  # Pass whitelist_manager
        dialog.exec()
    
    def has_api_keys(self) -> bool:
        """Check if any API keys are configured."""
        return len(self.config.keys) > 0
    
    def add_to_whitelist(self, whitelist_data: Dict[str, Any]) -> bool:
        """
        Add entry to whitelist.
        
        Args:
            whitelist_data: Dictionary with 'category' and 'data' keys
        
        Returns:
            True if successful
        """
        try:
            category = whitelist_data['category']
            data = whitelist_data['data']
            
            entry_id = self.whitelist_manager.add_whitelist_entry(category, data)
            logger.info(f"Added to whitelist: {entry_id}")
            
            self.status_changed.emit("Entry added to whitelist")
            return True
            
        except Exception as e:
            logger.error(f"Error adding to whitelist: {e}")
            self.status_changed.emit(f"Failed to add to whitelist: {e}")
            return False
    
    def _handle_captured_event(self, event: Dict[str, Any]) -> None:
        """Handle a newly captured network event."""
        try:
            self.event_count += 1
            
            # Parse the event
            parsed_event = self.parser_manager.parse_event(event)
            
            # Store in database
            self.database.insert_event(parsed_event)
            
            # Emit to UI
            self.new_event.emit(parsed_event)
            
            # Send to analytics engine
            if self.config.get('analytics.enable_heuristics', True):
                self.alert_engine.process_event(parsed_event)
            
            # Update threat level every 10 events
            if self.event_count % 10 == 0:
                threat_level = self._calculate_threat_level()
                self.threat_level_changed.emit(threat_level)
            
        except Exception as e:
            logger.error(f"Error handling captured event: {e}")
    
    def _handle_alert(self, alert: Dict[str, Any]) -> None:
        """Handle a newly generated alert."""
        try:
            self.alert_count += 1
            
            # Store alert with timestamp in recent alerts list
            self.recent_alerts.append({
                'alert': alert,
                'timestamp': alert.get('timestamp', 0),
                'weight': alert.get('threat_weight', 10)
            })
            
            # Keep only last 50 alerts for calculation
            if len(self.recent_alerts) > 50:
                self.recent_alerts = self.recent_alerts[-50:]
            
            # Store alert in database
            self.database.insert_alert(alert)
            
            # Emit to UI
            self.new_alert.emit(alert)
            
            # Update threat level immediately
            threat_level = self._calculate_threat_level()
            self.threat_level_changed.emit(threat_level)
            
            logger.warning(f"Alert generated: {alert.get('term', 'Unknown')} - {alert.get('explanation', '')}")
            
        except Exception as e:
            logger.error(f"Error handling alert: {e}")
    
    def _calculate_threat_level(self) -> int:
        """
        Calculate current threat level based on recent alerts.
        Uses weighted scoring with time decay.
        
        Returns:
            Threat level from 0 (safe) to 100 (critical)
        """
        try:
            import time
            
            if not self.recent_alerts:
                return 0
            
            current_time = time.time()
            total_score = 0
            
            # Calculate weighted score with time decay
            for alert_data in self.recent_alerts:
                alert = alert_data['alert']
                timestamp = alert_data['timestamp']
                weight = alert_data['weight']
                
                # Time decay: alerts lose impact over time (5 minute half-life)
                age = current_time - timestamp
                decay_factor = 0.5 ** (age / 300)  # 5 minutes = 300 seconds
                
                # Add weighted score
                total_score += weight * decay_factor
            
            # Normalize to 0-100 range
            # Maximum theoretical score with 50 critical alerts would be 50 * 80 = 4000
            # So we'll use 2000 as "100% threat"
            threat_level = min(100, int((total_score / 2000) * 100))
            
            return threat_level
            
        except Exception as e:
            logger.error(f"Error calculating threat level: {e}")
            return 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current capture and analysis statistics."""
        stats = {
            'event_count': self.event_count,
            'alert_count': self.alert_count,
            'is_capturing': self.is_capturing,
            'threat_level': self._calculate_threat_level()
        }
        
        # Add whitelist statistics (NEW)
        if self.whitelist_manager:
            stats['whitelist'] = self.whitelist_manager.get_statistics()
        
        return stats