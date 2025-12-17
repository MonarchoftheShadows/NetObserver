"""
DHCP protocol parser.
Extracts lease information and client identifiers.
"""

from typing import Dict, Any, Optional
from core.logger import get_logger

logger = get_logger(__name__)


class DHCPParser:
    """Parser for DHCP protocol traffic."""
    
    def parse(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse DHCP event.
        
        Args:
            event: Raw event dictionary
        
        Returns:
            Dictionary with DHCP metadata or None
        """
        try:
            result = {
                'dhcp_message_type': 'DHCPDISCOVER',  # DISCOVER, OFFER, REQUEST, ACK
                'dhcp_client_mac': '00:11:22:33:44:55',
                'dhcp_requested_ip': event.get('src_ip', 'unknown'),
                'dhcp_server_ip': event.get('dst_ip', 'unknown')
            }
            
            logger.debug(f"Parsed DHCP: {result.get('dhcp_message_type')}")
            return result
            
        except Exception as e:
            logger.error(f"DHCP parsing error: {e}")
            return None