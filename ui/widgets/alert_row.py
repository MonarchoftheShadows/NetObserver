"""
Alert row widget for displaying individual alerts.
"""

from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QPushButton, QMessageBox
from PyQt6.QtCore import Qt, pyqtSignal
from typing import Dict, Any

from core.logger import get_logger
from ui.widgets.copy_ip_button import CopyIPButton
from ui.widgets.whitelist_button import WhitelistButton

logger = get_logger(__name__)


class AlertRow(QWidget):
    """Widget representing a single alert row."""
    
    whitelist_requested = pyqtSignal(dict)  # Emits alert for whitelisting
    
    def __init__(self, alert: Dict[str, Any], parent=None):
        """
        Initialize alert row.
        
        Args:
            alert: Alert dictionary
            parent: Parent widget
        """
        super().__init__(parent)
        self.alert = alert
        self.is_filtered = alert.get('filtered', False)
        
        # Set row style
        if self.is_filtered:
            self.setStyleSheet("""
                QWidget {
                    background-color: #0a0a0a;
                    border: 1px solid #222;
                    border-radius: 3px;
                    opacity: 0.6;
                }
                QWidget:hover {
                    background-color: #151515;
                    border-color: #333;
                }
            """)
        else:
            self.setStyleSheet("""
                QWidget {
                    background-color: #1a1a1a;
                    border: 1px solid #333;
                    border-radius: 3px;
                }
                QWidget:hover {
                    background-color: #2a2a2a;
                    border-color: #555;
                }
            """)
        
        self.setFixedHeight(70)
        
        # Create layout
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(10)
        
        # Severity indicator
        severity = alert.get('severity', 'low')
        severity_colors = {
            'low': '#00ff00',
            'medium': '#ffaa00',
            'high': '#ff6600',
            'critical': '#ff0000'
        }
        severity_color = severity_colors.get(severity, '#00ff00')
        
        severity_label = QLabel("●")
        severity_label.setStyleSheet(f"""
            color: {severity_color};
            font-size: 24px;
            font-weight: bold;
        """)
        severity_label.setFixedWidth(30)
        severity_label.setToolTip(f"Severity: {severity.upper()}")
        
        # Alert ID label
        alert_id = alert.get('alert_id', 'N/A')
        id_label = QLabel(f"[{alert_id}]")
        id_label.setStyleSheet("""
            color: #888;
            font-size: 10px;
            font-family: monospace;
        """)
        id_label.setFixedWidth(100)
        
        # Term label with IPs
        term = alert.get('term', 'Unknown Alert')
        term_label = QLabel(term)
        term_label.setStyleSheet("""
            color: white;
            font-size: 13px;
            font-weight: bold;
        """)
        term_label.setWordWrap(False)
        
        # Extract IPs from metadata for copy buttons
        metadata = alert.get('metadata', {})
        src_ip = metadata.get('src_ip', '')
        dst_ip = metadata.get('dst_ip', '')
        
        # Copy IP buttons container
        copy_layout = QHBoxLayout()
        copy_layout.setSpacing(3)
        
        if src_ip:
            src_copy_btn = CopyIPButton(src_ip)
            copy_layout.addWidget(src_copy_btn)
        
        if dst_ip and dst_ip != src_ip:
            dst_copy_btn = CopyIPButton(dst_ip)
            copy_layout.addWidget(dst_copy_btn)
        
        # Count label (centered)
        count = alert.get('count', 0)
        count_label = QLabel(f"Count: {count}")
        count_label.setStyleSheet("""
            color: #aaa;
            font-size: 11px;
        """)
        count_label.setFixedSize(80,30)
        count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Whitelist badge if filtered
        if self.is_filtered:
            filtered_badge = QLabel("🛡️")       #("🛡️ WHITELISTED")
            filtered_badge.setFixedSize(30, 30)
            filtered_badge.setStyleSheet("""
                color: #00ff00;
                font-size: 12px;
                font-weight: bold;
                background-color: #0a3a0a;
                padding: 3px 8px;
                border-radius: 3px;
            """)
            filtered_badge.setToolTip(alert.get('filter_reason', 'Whitelisted'))
            filtered_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Action buttons
        # Info button
        info_btn = QPushButton("ℹ")
        info_btn.setFixedSize(30, 30)
        info_btn.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                border-radius: 3px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        info_btn.setToolTip(alert.get('explanation', 'No details available'))
        info_btn.clicked.connect(self._show_details)
        
        # Whitelist button
        whitelist_btn = WhitelistButton(alert)
        whitelist_btn.whitelist_requested.connect(self.whitelist_requested.emit)
        
        # Add widgets to layout
        layout.addWidget(severity_label)
        layout.addWidget(id_label)
        layout.addWidget(term_label, 1)  # Stretch
        layout.addWidget(count_label)
        layout.addLayout(copy_layout)
        
        if self.is_filtered:
            layout.addWidget(filtered_badge)
        
        layout.addWidget(info_btn)
        layout.addWidget(whitelist_btn)
        
        self.setLayout(layout)
    
    def _show_details(self) -> None:
        """Show alert details with styled dialog."""
        explanation = self.alert.get('explanation', 'No details available')
        metadata = self.alert.get('metadata', {})
        alert_id = self.alert.get('alert_id', 'N/A')
        
        details = f"Alert ID: {alert_id}\n\n{explanation}\n\n"
        if metadata:
            details += "Additional Information:\n"
            for key, value in metadata.items():
                details += f"  {key}: {value}\n"
        
        if self.is_filtered:
            details += f"\n🛡️ Whitelisted: {self.alert.get('filter_reason', 'No reason provided')}"
        
        # Create custom message box with dark styling
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Alert Details")
        msg_box.setText(details)
        msg_box.setIcon(QMessageBox.Icon.Information)
        
        # Apply dark theme styling
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 12px;
            }
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                padding: 5px 15px;
                min-width: 60px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        
        msg_box.exec()