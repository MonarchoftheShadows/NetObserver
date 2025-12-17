"""
Helper panel displays system status, API status, and OS information.
"""

from PyQt6.QtWidgets import QLabel, QVBoxLayout
from PyQt6.QtCore import Qt
import platform
import sys

from ui.panels.base_panel import BasePanel
from core.logger import get_logger

logger = get_logger(__name__)


class HelperPanel(BasePanel):
    """Panel displaying helper information and status."""
    
    def __init__(self, parent=None):
        """Initialize helper panel."""
        super().__init__("System Status", parent)
        
        # Status label
        self.status_label = QLabel("Ready to capture")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("""
            color: #00ffff;
            font-size: 18px;
            font-weight: bold;
            padding: 10px;
        """)
        
        # API status label
        self.api_label = QLabel("No API")
        self.api_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.api_label.setStyleSheet("""
            color: #aaa;
            font-size: 14px;
            font-weight: bold;
            padding: 10px;
        """)
        
        # OS information label
        self.os_label = QLabel(self._get_os_info())
        self.os_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.os_label.setStyleSheet("""
            color: #888;
            font-size: 14px;
            font-weight: bold;
            padding: 10px;
        """)
        self.os_label.setWordWrap(True)
        
        self.main_layout.addWidget(self.status_label)
        self.main_layout.addWidget(self.api_label)
        self.main_layout.addWidget(self.os_label)
        self.main_layout.addStretch()
        
        logger.debug("Helper panel initialized")
    
    def _get_os_info(self) -> str:
        """
        Detect and format operating system information.
        
        Returns:
            Formatted OS string
        """
        try:
            system = platform.system()
            
            if system == "Windows":
                # Detect Windows version
                release = platform.release()
                version = platform.version()
                
                # Check if Windows Server
                if "Server" in version or "Server" in platform.platform():
                    return f"Running on Windows Server {release}"
                else:
                    # Get Windows version name
                    win_version = self._get_windows_version(release, version)
                    return f"Running on {win_version}"
                    
            elif system == "Linux":
                # Try to detect Linux distribution
                distro_name = self._get_linux_distro()
                return f"Running on Linux ({distro_name})"
                
            elif system == "Darwin":
                # macOS
                mac_version = platform.mac_ver()[0]
                return f"Running on macOS {mac_version}"
                
            else:
                return f"Running on {system}"
                
        except Exception as e:
            logger.error(f"Error detecting OS: {e}")
            return "Running on Unknown OS"
    
    def _get_windows_version(self, release: str, version: str) -> str:
        """
        Get Windows version name from release and version info.
        
        Args:
            release: Windows release number
            version: Windows version string
        
        Returns:
            Friendly Windows version name
        """
        try:
            # Parse build number from version string
            if "." in version:
                build = int(version.split(".")[2]) if len(version.split(".")) > 2 else 0
            else:
                build = 0
            
            # Windows 11 detection (build 22000+)
            if build >= 22000:
                return "Windows 11"
            
            # Windows 10 versions
            if release == "10":
                if build >= 19041:
                    return "Windows 10 (2004+)"
                else:
                    return "Windows 10"
            
            # Older Windows versions
            version_map = {
                "8.1": "Windows 8.1",
                "8": "Windows 8",
                "7": "Windows 7",
                "Vista": "Windows Vista",
                "XP": "Windows XP"
            }
            
            return version_map.get(release, f"Windows {release}")
            
        except Exception as e:
            logger.debug(f"Error parsing Windows version: {e}")
            return f"Windows {release}"
    
    def _get_linux_distro(self) -> str:
        """
        Detect Linux distribution.
        
        Returns:
            Distribution name (e.g., "Ubuntu", "Debian", "Arch")
        """
        try:
            # Try using platform.freedesktop_os_release() (Python 3.10+)
            if hasattr(platform, 'freedesktop_os_release'):
                os_release = platform.freedesktop_os_release()
                distro_name = os_release.get('NAME', 'Unknown')
                
                # Simplify common names
                if 'Ubuntu' in distro_name:
                    return 'Ubuntu'
                elif 'Debian' in distro_name:
                    return 'Debian'
                elif 'Mint' in distro_name:
                    return 'Linux Mint'
                elif 'Arch' in distro_name:
                    return 'Arch'
                elif 'Fedora' in distro_name:
                    return 'Fedora'
                elif 'CentOS' in distro_name:
                    return 'CentOS'
                elif 'Red Hat' in distro_name or 'RHEL' in distro_name:
                    return 'RHEL'
                elif 'openSUSE' in distro_name:
                    return 'openSUSE'
                elif 'Manjaro' in distro_name:
                    return 'Manjaro'
                elif 'Kali' in distro_name:
                    return 'Kali'
                else:
                    return distro_name
            
            # Fallback: Try reading /etc/os-release directly
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release_content = f.read()
                    
                    if 'Ubuntu' in os_release_content:
                        return 'Ubuntu'
                    elif 'Debian' in os_release_content:
                        return 'Debian'
                    elif 'Mint' in os_release_content:
                        return 'Linux Mint'
                    elif 'Arch' in os_release_content:
                        return 'Arch'
                    elif 'Fedora' in os_release_content:
                        return 'Fedora'
                    elif 'CentOS' in os_release_content:
                        return 'CentOS'
                    elif 'Red Hat' in os_release_content or 'RHEL' in os_release_content:
                        return 'RHEL'
                    elif 'openSUSE' in os_release_content:
                        return 'openSUSE'
                    elif 'Manjaro' in os_release_content:
                        return 'Manjaro'
                    elif 'Kali' in os_release_content:
                        return 'Kali'
            except:
                pass
            
            # Try lsb_release as another fallback
            try:
                import subprocess
                result = subprocess.run(['lsb_release', '-d'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=2)
                if result.returncode == 0:
                    output = result.stdout.lower()
                    if 'ubuntu' in output:
                        return 'Ubuntu'
                    elif 'debian' in output:
                        return 'Debian'
                    elif 'mint' in output:
                        return 'Linux Mint'
                    elif 'arch' in output:
                        return 'Arch'
                    elif 'fedora' in output:
                        return 'Fedora'
                    elif 'centos' in output:
                        return 'CentOS'
                    elif 'red hat' in output or 'rhel' in output:
                        return 'RHEL'
            except:
                pass
            
            # Final fallback
            return 'Generic'
            
        except Exception as e:
            logger.debug(f"Error detecting Linux distro: {e}")
            return 'Generic'
    
    def set_status(self, status: str) -> None:
        """
        Set status text.
        
        Args:
            status: Status message
        """
        self.status_label.setText(status)
        
        # Change color based on status
        if "error" in status.lower() or "fail" in status.lower():
            color = "#ff0000"
        elif "capturing" in status.lower() or "started" in status.lower():
            color = "#00ff00"
        elif "stopped" in status.lower():
            color = "#ff0000"
        else:
            color = "#00ffff"  # Cyan for ready/idle
        
        self.status_label.setStyleSheet(f"""
            color: {color};
            font-size: 18px;
            font-weight: bold;
            padding: 10px;
        """)
    
    def set_api_status(self, has_api: bool) -> None:
        """
        Set API status.
        
        Args:
            has_api: True if API key is configured
        """
        if has_api:
            self.api_label.setText("API Active")
            self.api_label.setStyleSheet("""
                color: #00ff00;
                font-size: 14px;
                font-weight: bold;
                padding: 5px;
            """)
        else:
            self.api_label.setText("No API implemented")
            self.api_label.setStyleSheet("""
                color: #ff6666;
                font-size: 14px;
                font-weight: bold;
                padding: 5px;
            """)

    def set_whitelist_info(self, active_rules: int):
        """
        Set whitelist information.
        
        Args:
            active_rules: Number of active whitelist rules
        """
        # Add whitelist label if it doesn't exist
        if not hasattr(self, 'whitelist_label'):
            self.whitelist_label = QLabel()
            self.whitelist_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.whitelist_label.setStyleSheet("""
                color: #888;
                font-size: 14px;
                padding: 5px;
            """)
            self.whitelist_label.setCursor(Qt.CursorShape.PointingHandCursor)
            self.whitelist_label.setWordWrap(True)
            
            # Insert after API label
            self.main_layout.insertWidget(3, self.whitelist_label)
        
        if active_rules > 0:
            self.whitelist_label.setText(f"Whitelist: {active_rules} active rules")
        else:
            self.whitelist_label.setText("Whitelist: No rules")