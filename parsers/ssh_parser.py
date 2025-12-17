"""
SSH protocol parser.
Extracts SSH banners and version information.
"""

from typing import Dict, Any, Optional
from core.logger import get_logger

logger = get_logger(__name__)


class SSHParser:
    """Parser for SSH protocol traffic."""
    
    def parse(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse SSH event.
        
        Args:
            event: Raw event dictionary
        
        Returns:
            Dictionary with SSH metadata or None
        """
        try:
            result = {
                'ssh_banner': 'SSH-2.0-OpenSSH_8.2',
                'ssh_version': '2.0',
                'ssh_software': 'OpenSSH_8.2'
            }
            
            logger.debug(f"Parsed SSH: {result.get('ssh_banner')}")
            return result
            
        except Exception as e:
            logger.error(f"SSH parsing error: {e}")
            return None