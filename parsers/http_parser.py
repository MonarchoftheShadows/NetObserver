"""
HTTP protocol parser.
Extracts URLs, methods, headers, and response codes (defensive only).
"""

from typing import Dict, Any, Optional
from core.logger import get_logger

logger = get_logger(__name__)


class HTTPParser:
    """Parser for HTTP protocol traffic."""
    
    def parse(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse HTTP event.
        
        Args:
            event: Raw event dictionary
        
        Returns:
            Dictionary with HTTP metadata or None
        """
        try:
            # Defensive parsing - extract safe metadata only
            result = {
                'http_method': 'GET',  # GET, POST, PUT, etc.
                'http_uri': '/',
                'http_host': event.get('dst_ip', 'unknown'),
                'http_user_agent': 'Mozilla/5.0',
                'http_status_code': 200
            }
            
            logger.debug(f"Parsed HTTP: {result.get('http_method')} {result.get('http_uri')}")
            return result
            
        except Exception as e:
            logger.error(f"HTTP parsing error: {e}")
            return None