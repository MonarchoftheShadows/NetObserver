"""
Protocols panel displays protocol statistics and distribution.
"""

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from typing import Dict, Any
from collections import defaultdict

from ui.panels.base_panel import BasePanel
from core.logger import get_logger

logger = get_logger(__name__)


class ProtocolsPanel(BasePanel):
    """Panel displaying protocol statistics."""
    
    def __init__(self, parent=None):
        """Initialize protocols panel."""
        super().__init__("Protocol Statistics", parent)
        
        self.protocol_counts = defaultdict(int)
        
        # Create table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Protocol", "Count", "Percentage"])
        
        # Style table
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: black;
                color: white;
                gridline-color: #333;
                border: none;
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
            }
        """)
        
        # Configure table
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        self.main_layout.addWidget(self.table)
        
        logger.debug("Protocols panel initialized")
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """
        Update protocol statistics with new event.
        
        Args:
            event: Network event dictionary
        """
        try:
            protocol = event.get('protocol', 'UNKNOWN')
            self.protocol_counts[protocol] += 1
            
            self._update_table()
            
        except Exception as e:
            logger.error(f"Error updating protocols panel: {e}")
    
    def _update_table(self) -> None:
        """Update table with current statistics."""
        try:
            total = sum(self.protocol_counts.values())
            if total == 0:
                return
            
            # Sort by count
            sorted_protocols = sorted(self.protocol_counts.items(), 
                                    key=lambda x: x[1], reverse=True)
            
            # Update table
            self.table.setRowCount(len(sorted_protocols))
            
            for row, (protocol, count) in enumerate(sorted_protocols):
                percentage = (count / total) * 100
                
                protocol_item = QTableWidgetItem(protocol)
                count_item = QTableWidgetItem(str(count))
                percentage_item = QTableWidgetItem(f"{percentage:.1f}%")
                
                self.table.setItem(row, 0, protocol_item)
                self.table.setItem(row, 1, count_item)
                self.table.setItem(row, 2, percentage_item)
                
        except Exception as e:
            logger.error(f"Error updating protocol table: {e}")
    
    def clear(self) -> None:
        """Clear protocol statistics."""
        self.protocol_counts.clear()
        self.table.setRowCount(0)