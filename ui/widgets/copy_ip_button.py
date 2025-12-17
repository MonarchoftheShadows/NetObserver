"""
Copy IP button widget for alerts.
"""

from PyQt6.QtWidgets import QPushButton, QApplication
from PyQt6.QtCore import Qt

from core.logger import get_logger

logger = get_logger(__name__)


class CopyIPButton(QPushButton):
    """Button to copy IP address to clipboard."""
    
    def __init__(self, ip_address: str, parent=None):
        """
        Initialize copy IP button.
        
        Args:
            ip_address: IP address to copy
            parent: Parent widget
        """
        super().__init__(parent)
        self.ip_address = ip_address
        
        self.setText("📋")
        self.setFixedSize(30, 30)
        self.setToolTip(f"Copy {ip_address} to clipboard")
        
        self.setStyleSheet("""
            QPushButton {
                background-color: #2a2a2a;
                color: #aaa;
                border: 1px solid #444;
                border-radius: 3px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #00aa00;
                color: white;
                border: 1px solid #00ff00;
            }
        """)
        
        self.clicked.connect(self._copy_to_clipboard)
        

    def _copy_to_clipboard(self):
        """Copy IP to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.ip_address)
        
        # Visual feedback
        self.setText("✓")
        self.setFixedSize(30, 30)
        self.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                border: 1px solid #00ff00;
                border-radius: 3px;
                font-size: 12px;
            }
        """)
        
        
        # Reset after 1 second
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(1000, self._reset_button)
        
        logger.debug(f"Copied IP to clipboard: {self.ip_address}")
    
    def _reset_button(self):
        """Reset button appearance."""
        self.setText("📋")
        self.setFixedSize(30, 30)
        self.setStyleSheet("""
            QPushButton {
                background-color: #2a2a2a;
                color: #aaa;
                border: 1px solid #444;
                border-radius: 3px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #00aa00;
                color: white;
                border: 1px solid #00ff00;
            }
        """)
        