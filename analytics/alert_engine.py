"""
Alert engine processes events and generates alerts.
Coordinates with heuristics and manages alert lifecycle.
"""

from typing import Dict, Any
from PyQt6.QtCore import QObject, pyqtSignal

from core.logger import get_logger
from core.app_config import AppConfig
from analytics.heuristics import Heuristics, Alert

logger = get_logger(__name__)


class AlertEngine(QObject):
    """
    Alert generation and management engine.
    """
    
    alert_generated = pyqtSignal(dict)  # Emitted when new alert is generated
    
    def __init__(self, config: AppConfig, whitelist_manager=None):
        """
        Initialize alert engine.
        
        Args:
            config: Application configuration
            whitelist_manager: WhitelistManager instance (optional)
        """
        super().__init__()
        self.config = config
        self.whitelist_manager = whitelist_manager
        self.heuristics = Heuristics(config)
        self.alert_count = 0
        
        logger.info("Alert engine initialized")
    
    def process_event(self, event: Dict[str, Any]) -> None:
        """
        Process network event and generate alerts if necessary.
        
        Args:
            event: Parsed network event
        """
        try:
            # Run heuristic analysis
            alert = self.heuristics.analyze_event(event)
            
            if alert:
                self._emit_alert(alert, event)
        
        except Exception as e:
            logger.error(f"Error processing event in alert engine: {e}")
    
    def _emit_alert(self, alert: Alert, event: Dict[str, Any]) -> None:
        """
        Emit alert to orchestrator, checking whitelist first.
        
        Args:
            alert: Alert object
            event: Original event that triggered alert
        """
        try:
            self.alert_count += 1
            alert_dict = alert.to_dict()
            
            # Generate alert ID
            from datetime import datetime
            alert_id = f"AL-{datetime.now().strftime('%Y%m%d')}-{self.alert_count:04d}"
            alert_dict['alert_id'] = alert_id
            alert_dict['id'] = self.alert_count
            
            # Check whitelist
            if self.whitelist_manager:
                # Determine alert type from term
                alert_type = self._extract_alert_type(alert.term)
                
                should_filter, reason = self.whitelist_manager.should_filter_alert(event, alert_type)
                
                if should_filter:
                    # Mark as filtered but still emit if configured
                    alert_dict['filtered'] = True
                    alert_dict['filter_reason'] = reason
                    
                    if self.whitelist_manager.whitelist.get('show_filtered_alerts', True):
                        logger.info(f"Alert filtered: {alert.term} - {reason}")
                        self.alert_generated.emit(alert_dict)
                    else:
                        logger.debug(f"Alert silently filtered: {alert.term}")
                    
                    # Update statistics
                    if self.whitelist_manager.whitelist.get('log_filtered_alerts', True):
                        logger.info(f"Filtered alert logged: {alert_id} - {alert.term}")
                    
                    return
            
            # Not filtered - emit normally
            alert_dict['filtered'] = False
            logger.warning(f"Alert generated: {alert_id} - {alert.term} - Severity: {alert.severity}")
            self.alert_generated.emit(alert_dict)
            
        except Exception as e:
            logger.error(f"Error emitting alert: {e}")
    
    def _extract_alert_type(self, term: str) -> str:
        """Extract alert type from term."""
        # Map terms to alert types
        term_lower = term.lower()
        
        if 'port scan' in term_lower:
            return 'port_scan'
        elif 'dns failure' in term_lower:
            return 'dns_failures'
        elif 'suspicious domain' in term_lower:
            return 'dga_detection'
        elif 'outbound spike' in term_lower:
            return 'outbound_spike'
        elif 'brute force' in term_lower:
            return 'failed_auth'
        elif 'suspicious port' in term_lower:
            return 'suspicious_ports'
        elif 'large data transfer' in term_lower:
            return 'large_transfers'
        elif 'unusual protocol' in term_lower:
            return 'unusual_protocols'
        elif 'repeated connection' in term_lower:
            return 'repeated_connections'
        elif 'off-hours' in term_lower:
            return 'time_anomalies'
        else:
            return 'unknown'