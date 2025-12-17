"""
Logs panel displays application and event logs.
"""

from PyQt6.QtWidgets import QTextEdit, QMenu
from PyQt6.QtGui import QTextCursor, QAction
from PyQt6.QtCore import Qt
from typing import Dict, Any
import time

from ui.panels.base_panel import BasePanel
from core.logger import get_logger

logger = get_logger(__name__)


class LogsPanel(BasePanel):
    """Panel displaying application logs."""
    
    def __init__(self, parent=None):
        """Initialize logs panel."""
        super().__init__("Event Logs", parent)
        
        # Create text edit
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: black;
                color: #00ff00;
                border: none;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
            QMenu {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #555;
            }
            QMenu::item {
                padding: 5px 20px;
                background-color: transparent;
            }
            QMenu::item:selected {
                background-color: #333;
            }
            QMenu::separator {
                height: 1px;
                background-color: #555;
                margin: 2px 0px;
            }
        """)
        
        # Override context menu to ensure proper styling
        self.text_edit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.text_edit.customContextMenuRequested.connect(self._show_context_menu)
        
        self.main_layout.addWidget(self.text_edit)
        
        self.max_lines = 1000
        self.line_count = 0
        
        logger.debug("Logs panel initialized")
    
    def _show_context_menu(self, position):
        """
        Show custom context menu with proper dark theme styling.
        
        Args:
            position: Position where right-click occurred
        """
        # Create custom context menu
        menu = QMenu(self.text_edit)
        
        # Apply dark theme styling
        menu.setStyleSheet("""
            QMenu {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #555;
                padding: 2px;
            }
            QMenu::item {
                padding: 5px 25px 5px 20px;
                background-color: transparent;
                color: white;
            }
            QMenu::item:selected {
                background-color: #333;
                color: white;
            }
            QMenu::item:disabled {
                color: #666;
            }
            QMenu::separator {
                height: 1px;
                background-color: #555;
                margin: 2px 0px;
            }
        """)
        
        # Copy action
        copy_action = QAction("Copy\t|  Ctrl+C", self)
        copy_action.triggered.connect(self.text_edit.copy)
        copy_action.setEnabled(self.text_edit.textCursor().hasSelection())
        menu.addAction(copy_action)
        
        # Select All action
        select_all_action = QAction("Select All\t|  Ctrl+A", self)
        select_all_action.triggered.connect(self.text_edit.selectAll)
        menu.addAction(select_all_action)
        
        menu.addSeparator()
        
        # Clear action
        clear_action = QAction("Clear Logs", self)
        clear_action.triggered.connect(self.clear)
        menu.addAction(clear_action)
        
        # Show menu at cursor position
        menu.exec(self.text_edit.mapToGlobal(position))
    
    def add_log_entry(self, message: str, level: str = "info") -> None:
        """
        Add log entry to panel.
        
        Args:
            message: Log message
            level: Log level (info, warning, error)
        """
        try:
            # Format timestamp
            timestamp = time.strftime('%H:%M:%S')
            
            # Color based on level
            color_map = {
                'info': '#00ff00',
                'warning': '#ffaa00',
                'error': '#ff0000'
            }
            color = color_map.get(level, '#00ff00')
            
            # Format message
            formatted = f'<span style="color: {color}">[{timestamp}] {message}</span>'
            
            # Append to text edit
            self.text_edit.append(formatted)
            self.line_count += 1
            
            # Limit lines
            if self.line_count > self.max_lines:
                cursor = self.text_edit.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                cursor.movePosition(QTextCursor.MoveOperation.Down, 
                                  QTextCursor.MoveMode.KeepAnchor, 
                                  self.line_count - self.max_lines)
                cursor.removeSelectedText()
                self.line_count = self.max_lines
            
            # Scroll to bottom
            self.text_edit.moveCursor(QTextCursor.MoveOperation.End)
            
        except Exception as e:
            logger.error(f"Error adding log entry: {e}")
    
    def clear(self) -> None:
        """Clear all logs."""
        self.text_edit.clear()
        self.line_count = 0