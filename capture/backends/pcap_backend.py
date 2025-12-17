"""
PCAP capture backend.
Reads from network interfaces or PCAP files using pyshark/scapy.
"""

from typing import Optional, Dict, Any
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal, QThread, QTimer
import time

from core.logger import get_logger
from core.app_config import AppConfig

logger = get_logger(__name__)


class PcapBackend(QObject):
    """
    PCAP-based capture backend.
    Can read from live interfaces or replay PCAP files.
    """
    
    event_ready = pyqtSignal(dict)
    
    def __init__(self, source: str, config: AppConfig):
        """
        Initialize PCAP backend.
        
        Args:
            source: PCAP file path or interface name
            config: Application configuration
        """
        super().__init__()
        self.source = source
        self.config = config
        self.is_running = False
        self.thread = None
        
        logger.info(f"PCAP backend initialized with source: {source}")
    
    def start(self) -> bool:
        """
        Start packet capture.
        
        Returns:
            True if started successfully
        """
        try:
            # Check if pyshark is available
            try:
                import pyshark
                self._use_pyshark = True
                logger.info("Using pyshark for packet capture")
            except ImportError:
                logger.warning("pyshark not available, using simulated mode")
                self._use_pyshark = False
            
            self.is_running = True
            
            if self._use_pyshark:
                self._start_pyshark_capture()
            else:
                self._start_simulated_capture()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start PCAP backend: {e}")
            return False
    
    def stop(self) -> None:
        """Stop packet capture."""
        self.is_running = False
        if self.thread:
            self.thread.quit()
            self.thread.wait()
        logger.info("PCAP backend stopped")
    
    def _start_pyshark_capture(self) -> None:
        """Start capture using pyshark."""
        import pyshark
        
        def capture_worker():
            try:
                if Path(self.source).exists():
                    # Read from PCAP file
                    cap = pyshark.FileCapture(self.source)
                else:
                    # Live capture from interface
                    cap = pyshark.LiveCapture(interface=self.source)
                
                for packet in cap:
                    if not self.is_running:
                        break
                    
                    event = self._parse_pyshark_packet(packet)
                    if event:
                        self.event_ready.emit(event)
                
            except Exception as e:
                logger.error(f"Error in pyshark capture: {e}")
        
        # Run in separate thread
        self.thread = QThread()
        self.thread.run = capture_worker
        self.thread.start()
    
    def _start_simulated_capture(self) -> None:
        """Start simulated capture for demo/testing."""
        logger.info("Starting simulated capture mode")
        
        # Use timer to emit simulated events
        self.timer = QTimer()
        self.timer.timeout.connect(self._emit_simulated_event)
        self.timer.start(2000)  # Every 2 seconds
    
    def _emit_simulated_event(self) -> None:
        """Emit a simulated network event."""
        import random
        
        protocols = ['TCP', 'UDP', 'DNS', 'HTTP', 'TLS']
        sources = ['192.168.1.10', '192.168.1.20', '10.0.0.5']
        destinations = ['8.8.8.8', '1.1.1.1', '93.184.216.34']
        
        event = {
            'timestamp': time.time(),
            'protocol': random.choice(protocols),
            'src_ip': random.choice(sources),
            'dst_ip': random.choice(destinations),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 22, 445]),
            'length': random.randint(64, 1500)
        }
        
        self.event_ready.emit(event)
    
    def _parse_pyshark_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Parse pyshark packet into event dictionary.
        
        Args:
            packet: Pyshark packet object
        
        Returns:
            Event dictionary or None
        """
        try:
            event = {
                'timestamp': float(packet.sniff_timestamp),
                'length': int(packet.length)
            }
            
            # IP layer
            if hasattr(packet, 'ip'):
                event['src_ip'] = packet.ip.src
                event['dst_ip'] = packet.ip.dst
                event['protocol'] = packet.highest_layer
            
            # TCP/UDP
            if hasattr(packet, 'tcp'):
                event['src_port'] = int(packet.tcp.srcport)
                event['dst_port'] = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                event['src_port'] = int(packet.udp.srcport)
                event['dst_port'] = int(packet.udp.dstport)
            
            return event
            
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None