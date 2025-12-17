"""
Connections panel displays active network connections.
"""

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from typing import Dict, Any

from ui.panels.base_panel import BasePanel
from core.logger import get_logger

logger = get_logger(__name__)


class ConnectionsPanel(BasePanel):
    """Panel displaying active network connections."""
    
    def __init__(self, parent=None):
        """Initialize connections panel."""
        super().__init__("Active Connections", parent)
        
        # Maximum number of rows to keep
        self.max_rows = 10000
        
        # Create table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Protocol", "Source IP", "Src Port", "Dest IP", "Dst Port", "Time"
        ])
        
        # Style table with explicit alternating row colors
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: black;
                color: white;
                gridline-color: #333;
                border: none;
                alternate-background-color: #1a1a1a;
            }
            QHeaderView::section {
                background-color: #1a1a1a;
                color: white;
                padding: 5px;
                border: 1px solid #333;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
                background-color: black;
            }
            QTableWidget::item:alternate {
                background-color: #1a1a1a;
            }
            QTableWidget::item:selected {
                background-color: #333;
            }
        """)
        
        # Configure table
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        # self.table.verticalHeader().setVisible(False)  # Hide row numbers
        
        self.main_layout.addWidget(self.table)
        
        logger.debug("Connections panel initialized")
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """
        Add network event to table.
        
        Args:
            event: Network event dictionary
        """
        try:
            # Insert at top
            self.table.insertRow(0)
            
            # Extract event data
            protocol = event.get('protocol', 'UNKNOWN')
            src_ip = event.get('src_ip', '?')
            src_port = str(event.get('src_port', '?'))
            dst_ip = event.get('dst_ip', '?')
            dst_port = str(event.get('dst_port', '?'))
            
            # Format timestamp
            import time
            timestamp = event.get('timestamp', time.time())
            time_str = time.strftime('%H:%M:%S', time.localtime(timestamp))
            
            # Create items
            items = [
                QTableWidgetItem(protocol),
                QTableWidgetItem(src_ip),
                QTableWidgetItem(src_port),
                QTableWidgetItem(dst_ip),
                QTableWidgetItem(dst_port),
                QTableWidgetItem(time_str)
            ]
            
            # Set items in row
            for col, item in enumerate(items):
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(0, col, item)
            
            # Remove old rows if exceeding limit
            while self.table.rowCount() > self.max_rows:
                self.table.removeRow(self.table.rowCount() - 1)
                
        except Exception as e:
            logger.error(f"Error adding event to connections panel: {e}")
    
    def clear(self) -> None:
        """Clear all connections."""
        self.table.setRowCount(0)