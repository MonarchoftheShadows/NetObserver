"""
Action panel provides capture control buttons.
"""

from PyQt6.QtWidgets import QPushButton, QHBoxLayout
from PyQt6.QtCore import pyqtSignal

from ui.panels.base_panel import BasePanel
from core.logger import get_logger

logger = get_logger(__name__)


class ActionPanel(BasePanel):
    """Panel with action buttons for capture control."""
    
    start_clicked = pyqtSignal()
    stop_clicked = pyqtSignal()
    clear_clicked = pyqtSignal()
    
    def __init__(self, parent=None):
        """Initialize action panel."""
        super().__init__("Actions", parent)
        
        # Create button layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        # Start button
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #2a2a2a;
                color: #00ff00;
                border: 2px solid #00ff00;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00ff00;
                color: black;
            }
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #555;
                border-color: #555;
            }
        """)
        self.start_btn.clicked.connect(self.start_clicked.emit)
        
        # Stop button
        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #2a2a2a;
                color: #ff0000;
                border: 2px solid #ff0000;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ff0000;
                color: black;
            }
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #555;
                border-color: #555;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_clicked.emit)
        
        # Clear button
        self.clear_btn = QPushButton("✖ Clear")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #2a2a2a;
                color: #ffaa00;
                border: 2px solid #ffaa00;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffaa00;
                color: black;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_clicked.emit)
        
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)
        
        self.main_layout.addLayout(button_layout)
        self.main_layout.addStretch()
        
        logger.debug("Action panel initialized")
    
    def set_capture_state(self, is_capturing: bool) -> None:
        """
        Update button states based on capture state.
        
        Args:
            is_capturing: True if currently capturing
        """
        self.start_btn.setEnabled(not is_capturing)
        self.stop_btn.setEnabled(is_capturing)