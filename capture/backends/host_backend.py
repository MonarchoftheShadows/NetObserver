"""
Host-based capture backend.
Monitors network connections via /proc/net (Linux) without requiring root.
"""

from typing import Dict, Any, Set
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
import time

from core.logger import get_logger
from core.app_config import AppConfig

logger = get_logger(__name__)


class HostBackend(QObject):
    """
    Host-based network monitoring backend.
    Reads /proc/net/tcp and /proc/net/udp for connection tracking.
    """
    
    event_ready = pyqtSignal(dict)
    
    def __init__(self, config: AppConfig):
        """
        Initialize host backend.
        
        Args:
            config: Application configuration
        """
        super().__init__()
        self.config = config
        self.is_running = False
        self.known_connections: Set[str] = set()
        self.timer = None
        
        logger.info("Host backend initialized")
    
    def start(self) -> bool:
        """
        Start monitoring host connections.
        
        Returns:
            True if started successfully
        """
        try:
            # Check if /proc/net exists (Linux only)
            if not Path('/proc/net/tcp').exists():
                logger.warning("/proc/net not available, using simulated mode")
                self._use_proc = False
            else:
                self._use_proc = True
                logger.info("Using /proc/net for connection monitoring")
            
            self.is_running = True
            
            # Start periodic polling
            self.timer = QTimer()
            self.timer.timeout.connect(self._poll_connections)
            self.timer.start(1000)  # Poll every second
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start host backend: {e}")
            return False
    
    def stop(self) -> None:
        """Stop monitoring."""
        self.is_running = False
        if self.timer:
            self.timer.stop()
        logger.info("Host backend stopped")
    
    def _poll_connections(self) -> None:
        """Poll for new network connections."""
        if self._use_proc:
            self._read_proc_connections()
        else:
            self._emit_simulated_connection()
    
    def _read_proc_connections(self) -> None:
        """Read connections from /proc/net."""
        try:
            # Read TCP connections
            self._parse_proc_file('/proc/net/tcp', 'TCP')
            self._parse_proc_file('/proc/net/tcp6', 'TCP')
            
            # Read UDP connections
            self._parse_proc_file('/proc/net/udp', 'UDP')
            self._parse_proc_file('/proc/net/udp6', 'UDP')
            
        except Exception as e:
            logger.debug(f"Error reading /proc/net: {e}")
    
    def _parse_proc_file(self, filepath: str, protocol: str) -> None:
        """
        Parse /proc/net file and emit new connections.
        
        Args:
            filepath: Path to /proc/net file
            protocol: Protocol name (TCP/UDP)
        """
        try:
            if not Path(filepath).exists():
                return
            
            with open(filepath, 'r') as f:
                lines = f.readlines()[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                # Parse local and remote addresses
                local_addr = parts[1]
                remote_addr = parts[2]
                
                # Create connection identifier
                conn_id = f"{protocol}:{local_addr}:{remote_addr}"
                
                # Check if new connection
                if conn_id not in self.known_connections:
                    self.known_connections.add(conn_id)
                    
                    # Parse addresses
                    local_ip, local_port = self._parse_hex_address(local_addr)
                    remote_ip, remote_port = self._parse_hex_address(remote_addr)
                    
                    # Emit event
                    event = {
                        'timestamp': time.time(),
                        'protocol': protocol,
                        'src_ip': local_ip,
                        'src_port': local_port,
                        'dst_ip': remote_ip,
                        'dst_port': remote_port,
                        'source': 'host_monitor'
                    }
                    
                    self.event_ready.emit(event)
                    
        except Exception as e:
            logger.debug(f"Error parsing {filepath}: {e}")
    
    def _parse_hex_address(self, hex_addr: str) -> tuple:
        """
        Parse hex address from /proc/net format.
        
        Args:
            hex_addr: Hex address string (e.g., "0100007F:1F90")
        
        Returns:
            Tuple of (ip_string, port_int)
        """
        try:
            addr_parts = hex_addr.split(':')
            hex_ip = addr_parts[0]
            hex_port = addr_parts[1]
            
            # Convert hex IP to dotted decimal
            ip_parts = [str(int(hex_ip[i:i+2], 16)) for i in range(6, -1, -2)]
            ip_str = '.'.join(ip_parts)
            
            # Convert hex port to int
            port = int(hex_port, 16)
            
            return ip_str, port
            
        except Exception as e:
            logger.debug(f"Error parsing hex address {hex_addr}: {e}")
            return "0.0.0.0", 0
    
    def _emit_simulated_connection(self) -> None:
        """Emit simulated connection for testing."""
        import random
        
        protocols = ['TCP', 'UDP']
        sources = ['192.168.1.100', '10.0.0.50']
        destinations = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '199.232.210.10']
        
        event = {
            'timestamp': time.time(),
            'protocol': random.choice(protocols),
            'src_ip': random.choice(sources),
            'dst_ip': random.choice(destinations),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 22, 445, 3389]),
            'source': 'simulated'
        }
        
        self.event_ready.emit(event)