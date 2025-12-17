"""
Parser manager coordinates protocol-specific parsers.
Routes events to appropriate parsers and aggregates results.
"""

from typing import Dict, Any, Optional
from core.logger import get_logger

# Import protocol parsers
from parsers.dns_parser import DNSParser
from parsers.http_parser import HTTPParser
from parsers.tls_parser import TLSParser
from parsers.ssh_parser import SSHParser
from parsers.dhcp_parser import DHCPParser
from parsers.smb_parser import SMBParser

logger = get_logger(__name__)


class ParserManager:
    """
    Manages protocol-specific parsers and routes events.
    """
    
    def __init__(self):
        """Initialize parser manager and all parsers."""
        self.parsers = {
            'DNS': DNSParser(),
            'HTTP': HTTPParser(),
            'TLS': TLSParser(),
            'SSH': SSHParser(),
            'DHCP': DHCPParser(),
            'SMB': SMBParser()
        }
        
        logger.info(f"Parser manager initialized with {len(self.parsers)} parsers")
    
    def parse_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse network event using appropriate parser.
        
        Args:
            event: Raw event dictionary
        
        Returns:
            Parsed event with additional metadata
        """
        try:
            # Copy event to avoid modifying original
            parsed = event.copy()
            
            # Determine protocol
            protocol = event.get('protocol', '').upper()
            dst_port = event.get('dst_port', 0)
            
            # Map ports to protocols if not explicitly set
            if not protocol or protocol in ['TCP', 'UDP']:
                protocol = self._infer_protocol(dst_port)
            
            # Route to appropriate parser
            if protocol in self.parsers:
                parser_result = self.parsers[protocol].parse(event)
                if parser_result:
                    parsed.update(parser_result)
                    parsed['parsed_protocol'] = protocol
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing event: {e}")
            return event
    
    def _infer_protocol(self, port: int) -> str:
        """
        Infer application protocol from port number.
        
        Args:
            port: Destination port number
        
        Returns:
            Protocol name or 'UNKNOWN'
        """
        port_map = {
            53: 'DNS',
            80: 'HTTP',
            443: 'TLS',
            22: 'SSH',
            67: 'DHCP',
            68: 'DHCP',
            445: 'SMB',
            139: 'SMB',
            3389: 'RDP',
            21: 'FTP',
            25: 'SMTP'
        }
        
        return port_map.get(port, 'UNKNOWN')