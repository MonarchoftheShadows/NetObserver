"""
PCAP file writer for exporting captured packets.
"""

from pathlib import Path
from typing import List, Dict, Any
import struct
import time

from core.logger import get_logger

logger = get_logger(__name__)


class PcapWriter:
    """
    Writes network captures to PCAP format.
    """
    
    # PCAP global header constants
    PCAP_MAGIC = 0xa1b2c3d4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE = 0
    SIGFIGS = 0
    SNAPLEN = 65535
    NETWORK = 1  # Ethernet
    
    def __init__(self, filepath: str):
        """
        Initialize PCAP writer.
        
        Args:
            filepath: Output file path
        """
        self.filepath = Path(filepath)
        self.file = None
        
        logger.info(f"PCAP writer initialized for {filepath}")
    
    def open(self) -> bool:
        """
        Open PCAP file for writing.
        
        Returns:
            True if successful
        """
        try:
            self.file = open(self.filepath, 'wb')
            self._write_global_header()
            logger.info(f"PCAP file opened: {self.filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to open PCAP file: {e}")
            return False
    
    def _write_global_header(self) -> None:
        """Write PCAP global header."""
        header = struct.pack('IHHiIII',
                           self.PCAP_MAGIC,
                           self.VERSION_MAJOR,
                           self.VERSION_MINOR,
                           self.THISZONE,
                           self.SIGFIGS,
                           self.SNAPLEN,
                           self.NETWORK)
        self.file.write(header)
    
    def write_packet(self, packet_data: bytes, timestamp: float = None) -> None:
        """
        Write packet to PCAP file.
        
        Args:
            packet_data: Raw packet bytes
            timestamp: Packet timestamp (uses current time if None)
        """
        try:
            if not self.file:
                return
            
            if timestamp is None:
                timestamp = time.time()
            
            # Split timestamp into seconds and microseconds
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1000000)
            
            # Packet header
            incl_len = len(packet_data)
            orig_len = incl_len
            
            header = struct.pack('IIII', ts_sec, ts_usec, incl_len, orig_len)
            self.file.write(header)
            self.file.write(packet_data)
            
        except Exception as e:
            logger.error(f"Failed to write packet: {e}")
    
    def close(self) -> None:
        """Close PCAP file."""
        if self.file:
            self.file.close()
            logger.info(f"PCAP file closed: {self.filepath}")