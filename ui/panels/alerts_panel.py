"""
Alerts panel displays security alerts with scrollable rows.
"""

from PyQt6.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QLabel, QHBoxLayout, QPushButton
from PyQt6.QtCore import Qt, pyqtSignal
from typing import Dict, Any

from ui.panels.base_panel import BasePanel
from ui.widgets.alert_row import AlertRow
from core.logger import get_logger

logger = get_logger(__name__)


class AlertsPanel(BasePanel):
    """Panel displaying security alerts."""
    
    whitelist_requested = pyqtSignal(dict)  # Emits alert for whitelisting
    
    def __init__(self, parent=None):
        """Initialize alerts panel."""
        super().__init__("Security Alerts", parent)
        
        # Header with filtered count
        header_layout = QHBoxLayout()
        
        self.filtered_count_label = QLabel("🛡️ 0 Filtered")
        self.filtered_count_label.setStyleSheet("""
            color: #00ff00;
            font-size: 12px;
            padding: 5px;
            background-color: transparent;
        """)
        self.filtered_count_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.filtered_count_label.mousePressEvent = self._toggle_filtered_visibility
        self.filtered_count_label.setToolTip("Click to show/hide filtered alerts")
        
        header_layout.addStretch()
        header_layout.addWidget(self.filtered_count_label)
        
        self.main_layout.insertLayout(1, header_layout)
        
        # Create scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: black;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #1a1a1a;
                width: 12px;
                border: 1px solid #333;
            }
            QScrollBar::handle:vertical {
                background-color: #444;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666;
            }
        """)
        
        # Create container widget for alerts
        self.container = QWidget()
        self.container.setStyleSheet("background-color: black;")
        self.container_layout = QVBoxLayout()
        self.container_layout.setContentsMargins(0, 0, 0, 0)
        self.container_layout.setSpacing(2)
        self.container_layout.addStretch()
        self.container.setLayout(self.container_layout)
        
        self.scroll_area.setWidget(self.container)
        self.main_layout.addWidget(self.scroll_area)
        
        self.alert_rows = []
        self.max_alerts = 1000  # Configurable, default 1000
        self.show_filtered = True
        self.filtered_count = 0
        
        logger.debug("Alerts panel initialized")
    
    def add_alert(self, alert: Dict[str, Any]) -> None:
        """
        Add alert to panel.
        
        Args:
            alert: Alert dictionary
        """
        try:
            # Check if filtered
            is_filtered = alert.get('filtered', False)
            
            if is_filtered:
                self.filtered_count += 1
                self._update_filtered_count()
            
            # Create alert row
            alert_row = AlertRow(alert)
            alert_row.whitelist_requested.connect(self.whitelist_requested.emit)
            
            # Hide if filtered and show_filtered is False
            if is_filtered and not self.show_filtered:
                alert_row.hide()
            
            # Insert at top (before stretch)
            self.container_layout.insertWidget(0, alert_row)
            self.alert_rows.insert(0, alert_row)
            
            # Remove old alerts if exceeding limit
            while len(self.alert_rows) > self.max_alerts:
                old_row = self.alert_rows.pop()
                self.container_layout.removeWidget(old_row)
                old_row.deleteLater()
            
            logger.debug(f"Alert added: {alert.get('term', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
    
    def _update_filtered_count(self):
        """Update filtered count label."""
        self.filtered_count_label.setText(f"🛡️ {self.filtered_count} Filtered")
    
    def _toggle_filtered_visibility(self, event):
        """Toggle visibility of filtered alerts."""
        self.show_filtered = not self.show_filtered
        
        for row in self.alert_rows:
            if row.is_filtered:
                if self.show_filtered:
                    row.show()
                else:
                    row.hide()
        
        logger.debug(f"Filtered alerts visibility: {self.show_filtered}")
    
    def set_max_alerts(self, max_alerts: int):
        """Set maximum number of alerts to keep."""
        self.max_alerts = max_alerts
        
        # Remove excess alerts
        while len(self.alert_rows) > self.max_alerts:
            old_row = self.alert_rows.pop()
            self.container_layout.removeWidget(old_row)
            old_row.deleteLater()
    
    def clear(self) -> None:
        """Clear all alerts."""
        for row in self.alert_rows:
            self.container_layout.removeWidget(row)
            row.deleteLater()
        self.alert_rows.clear()
        self.filtered_count = 0
        self._update_filtered_count()