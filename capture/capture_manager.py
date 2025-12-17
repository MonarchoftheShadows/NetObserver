"""
Capture manager coordinates network packet capture.
Supports multiple backends (PCAP, host-based monitoring).
"""

from typing import Optional, Dict, Any
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal, QTimer

from core.logger import get_logger
from core.app_config import AppConfig

logger = get_logger(__name__)


class CaptureManager(QObject):
    """
    Manages network capture from various sources.
    Coordinates backend selection and event emission.
    """
    
    event_captured = pyqtSignal(dict)  # Emitted for each captured event
    
    def __init__(self, config: AppConfig):
        """
        Initialize capture manager.
        
        Args:
            config: Application configuration
        """
        super().__init__()
        self.config = config
        self.backend = None
        self.is_active = False
        
        logger.info("Capture manager initialized")
    
    def start_capture(self, source: str = "auto") -> bool:
        """
        Start capturing from specified source.
        
        Args:
            source: Capture source ("auto", interface name, or pcap file path)
        
        Returns:
            True if capture started successfully
        """
        try:
            # Determine backend based on source
            if source.endswith('.pcap') or source.endswith('.pcapng'):
                from capture.backends.pcap_backend import PcapBackend
                self.backend = PcapBackend(source, self.config)
                logger.info(f"Using PCAP backend for file: {source}")
            else:
                # Try host backend first (doesn't require root)
                from capture.backends.host_backend import HostBackend
                self.backend = HostBackend(self.config)
                logger.info("Using host backend for live capture")
            
            # Connect backend signal
            self.backend.event_ready.connect(self._on_event_ready)
            
            # Start backend
            if self.backend.start():
                self.is_active = True
                logger.info("Capture backend started successfully")
                return True
            else:
                logger.error("Backend failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            return False
    
    def stop_capture(self) -> None:
        """Stop active capture."""
        if self.backend:
            try:
                self.backend.stop()
                self.is_active = False
                logger.info("Capture stopped")
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")
    
    def _on_event_ready(self, event: Dict[str, Any]) -> None:
        """
        Handle event from backend.
        
        Args:
            event: Raw event dictionary
        """
        try:
            # Add metadata
            import time
            event['captured_at'] = time.time()
            
            # Emit to orchestrator
            self.event_captured.emit(event)
            
        except Exception as e:
            logger.error(f"Error processing captured event: {e}")