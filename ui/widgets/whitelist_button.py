"""
Whitelist button widget for alert rows.
"""

from PyQt6.QtWidgets import QPushButton
from PyQt6.QtCore import pyqtSignal
from typing import Dict, Any

from core.logger import get_logger

logger = get_logger(__name__)


class WhitelistButton(QPushButton):
    """Button to add alert to whitelist."""
    
    whitelist_requested = pyqtSignal(dict)  # Emits alert data
    
    def __init__(self, alert: Dict[str, Any], parent=None):
        """
        Initialize whitelist button.
        
        Args:
            alert: Alert dictionary
            parent: Parent widget
        """
        super().__init__(parent)
        self.alert = alert
        
        self.setText("⊕")
        self.setFixedSize(30, 30)
        self.setToolTip("Add to Whitelist")
        
        self.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: #00ff00;
                border: 1px solid #555;
                border-radius: 3px;
                font-size: 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00aa00;
                color: white;
                border: 2px solid #00ff00;
            }
        """)
        
        self.clicked.connect(self._on_clicked)
    
    def _on_clicked(self):
        """Handle button click."""
        self.whitelist_requested.emit(self.alert)