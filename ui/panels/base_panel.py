"""
Base panel class for all dashboard panels.
Provides common styling and functionality.
"""

from PyQt6.QtWidgets import QFrame, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt

from core.logger import get_logger

logger = get_logger(__name__)


class BasePanel(QFrame):
    """Base class for all dashboard panels."""
    
    def __init__(self, title: str, parent=None):
        """
        Initialize base panel.
        
        Args:
            title: Panel title
            parent: Parent widget
        """
        super().__init__(parent)
        self.title = title
        
        # Set frame style (black background, white border)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        self.setLineWidth(3)
        self.setStyleSheet("""
            QFrame {
                background-color: black;
                border: 1px solid white;
            }
        """)
        
        # Create main layout
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(5)
        
        # Create title label
        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignTop)
        self.title_label.setStyleSheet("""
            color: white; 
            font-size: 20px; 
            font-weight: bold;
            padding: 5px;
            background-color: black;
        """)
        
        self.main_layout.addWidget(self.title_label)
        self.setLayout(self.main_layout)
    
    def clear(self) -> None:
        """Clear panel contents (to be implemented by subclasses)."""
        pass