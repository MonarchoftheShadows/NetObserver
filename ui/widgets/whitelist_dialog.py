"""
Dialog for adding alerts to whitelist.
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QComboBox, QLineEdit, QCheckBox,
                             QFormLayout, QSpinBox, QMessageBox)
from PyQt6.QtCore import Qt
from typing import Dict, Any, Optional

from core.logger import get_logger

logger = get_logger(__name__)


class WhitelistDialog(QDialog):
    """Dialog for adding alert to whitelist."""
    
    def __init__(self, alert: Dict[str, Any], parent=None):
        """
        Initialize whitelist dialog.
        
        Args:
            alert: Alert dictionary
            parent: Parent widget
        """
        super().__init__(parent)
        self.alert = alert
        self.whitelist_data = None
        
        self.setWindowTitle("Add to Whitelist")
        self.setMinimumWidth(500)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                background-color: transparent;
            }
            QComboBox, QLineEdit, QSpinBox {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #444;
                padding: 5px;
            }               
            QComboBox QAbstractItemView {
                background-color: #2a2a2a;
                color: white;
                selection-background-color: #444;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
            }
            QCheckBox {
                color: white;
                background-color: transparent;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #555;
                background-color: #2a2a2a;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff00;
                border: 1px solid #00ff00;
            }
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                padding: 8px 16px;
                min-height: 30px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup dialog UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("Add Alert to Whitelist")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Alert info
        alert_info = QLabel(f"Alert: {self.alert.get('term', 'Unknown')}")
        alert_info.setStyleSheet("color: #aaa; padding: 5px;")
        layout.addWidget(alert_info)
        
        # Form
        form = QFormLayout()
        form.setSpacing(10)
        
        # What to whitelist dropdown
        self.whitelist_type = QComboBox()
        self.whitelist_type.addItem("Source IP", "source_ip")
        self.whitelist_type.addItem("Destination IP", "destination_ip")
        self.whitelist_type.addItem("Source → Destination Pair", "ip_pair")
        self.whitelist_type.addItem("This Rule Only (for this IP)", "rule_specific")
        self.whitelist_type.addItem("Time-Based (during alert hours)", "time_based")
        self.whitelist_type.addItem("Protocol-Based", "protocol_based")
        self.whitelist_type.currentIndexChanged.connect(self._on_type_changed)
        form.addRow("What to whitelist:", self.whitelist_type)
        
        # Additional fields container
        self.additional_fields = QVBoxLayout()
        form.addRow("", self.additional_fields)
        
        # Reason field
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Why is this whitelisted? (e.g., 'ISP router')")
        form.addRow("Reason (required):", self.reason_input)
        
        # Enable immediately checkbox
        self.enable_immediately = QCheckBox("Enable immediately")
        self.enable_immediately.setChecked(True)
        form.addRow("", self.enable_immediately)
        
        layout.addLayout(form)
        
        # Show initial additional fields
        self._on_type_changed()
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        add_btn = QPushButton("Add to Whitelist")
        add_btn.clicked.connect(self._add_to_whitelist)
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                border: 2px solid #00ff00;
                font-weight: bold;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #00cc00;
            }
        """)
        button_layout.addWidget(add_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _clear_additional_fields(self):
        """Clear all widgets AND layouts in the additional_fields layout."""
        while self.additional_fields.count():
            item = self.additional_fields.takeAt(0)

            # If it's a widget, delete it
            if item.widget():
                item.widget().deleteLater()

            # If it's a layout, clear it recursively
            elif item.layout():
                self._clear_layout(item.layout())
                item.layout().deleteLater()


    def _clear_layout(self, layout):
        """Recursively clear a layout."""
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            elif child.layout():
                self._clear_layout(child.layout())
                child.layout().deleteLater()
    
    def _on_type_changed(self):
        """Handle whitelist type change."""
        self._clear_additional_fields()
        
        wl_type = self.whitelist_type.currentData()
        metadata = self.alert.get('metadata', {})
        
        if wl_type == "source_ip":
            src_ip = metadata.get('src_ip', self.alert.get('term', '').split()[-1])
            info = QLabel(f"Will whitelist: {src_ip}")
            info.setStyleSheet("color: #00ff00; padding: 5px;")
            self.additional_fields.addWidget(info)
        
        elif wl_type == "destination_ip":
            dst_ip = metadata.get('dst_ip', '')
            info = QLabel(f"Will whitelist: {dst_ip}")
            info.setStyleSheet("color: #00ff00; padding: 5px;")
            self.additional_fields.addWidget(info)
        
        elif wl_type == "ip_pair":
            src_ip = metadata.get('src_ip', '')
            dst_ip = metadata.get('dst_ip', '')
            info = QLabel(f"Will whitelist: {src_ip} → {dst_ip}")
            info.setStyleSheet("color: #00ff00; padding: 5px;")
            self.additional_fields.addWidget(info)
        
        elif wl_type == "rule_specific":
            rule = self.alert.get('term', '').split(':')[0]
            src_ip = metadata.get('src_ip', '')
            info = QLabel(f"Will disable '{rule}' alerts for {src_ip}")
            info.setStyleSheet("color: #00ff00; padding: 5px;")
            self.additional_fields.addWidget(info)
        
        elif wl_type == "time_based":
            info = QLabel("Configure time window:")
            info.setStyleSheet("color: #aaa; padding: 5px;")
            self.additional_fields.addWidget(info)
            
            time_form = QFormLayout()
            self.start_hour = QSpinBox()  # CREATE NEW INSTANCES
            self.start_hour.setRange(0, 23)
            self.start_hour.setValue(2)
            self.start_hour.setStyleSheet("background-color: #2a2a2a; color: white; border: 1px solid #444; padding: 5px;")
            time_form.addRow(QLabel("Start Hour:"), self.start_hour)
            
            self.end_hour = QSpinBox()  # CREATE NEW INSTANCES
            self.end_hour.setRange(0, 23)
            self.end_hour.setValue(5)
            self.end_hour.setStyleSheet("background-color: #2a2a2a; color: white; border: 1px solid #444; padding: 5px;")
            time_form.addRow(QLabel("End Hour:"), self.end_hour)
            
            self.additional_fields.addLayout(time_form)
        
        elif wl_type == "protocol_based":
            protocol = metadata.get('protocol', '')
            src_ip = metadata.get('src_ip', '')
            info = QLabel(f"Will whitelist {protocol} from {src_ip}")
            info.setStyleSheet("color: #00ff00; padding: 5px;")
            self.additional_fields.addWidget(info)
    
    def _add_to_whitelist(self):
        """Validate and create whitelist entry."""
        # Validate reason
        reason = self.reason_input.text().strip()
        if not reason:
            QMessageBox.warning(self, "Missing Reason", 
                              "Please provide a reason for whitelisting.")
            return
        
        wl_type = self.whitelist_type.currentData()
        metadata = self.alert.get('metadata', {})
        
        # Build whitelist entry based on type
        try:
            if wl_type == "source_ip":
                src_ip = metadata.get('src_ip', self.alert.get('term', '').split()[-1])
                self.whitelist_data = {
                    'category': 'source_ip',
                    'data': {
                        'ip': src_ip,
                        'reason': reason,
                        'enabled': self.enable_immediately.isChecked()
                    }
                }
            
            elif wl_type == "destination_ip":
                dst_ip = metadata.get('dst_ip', '')
                self.whitelist_data = {
                    'category': 'destination_ip',
                    'data': {
                        'ip': dst_ip,
                        'reason': reason,
                        'enabled': self.enable_immediately.isChecked()
                    }
                }
            
            elif wl_type == "ip_pair":
                src_ip = metadata.get('src_ip', '')
                dst_ip = metadata.get('dst_ip', '')
                self.whitelist_data = {
                    'category': 'ip_pair',
                    'data': {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'reason': reason,
                        'enabled': self.enable_immediately.isChecked()
                    }
                }
            
            elif wl_type == "rule_specific":
                rule = self.alert.get('term', '').split(':')[0]
                src_ip = metadata.get('src_ip', '')
                self.whitelist_data = {
                    'category': 'rule_specific',
                    'data': {
                        'rule_name': rule,
                        'source_ip': src_ip,
                        'reason': reason,
                        'enabled': self.enable_immediately.isChecked()
                    }
                }
            
            elif wl_type == "time_based":
                src_ip = metadata.get('src_ip', '')
                self.whitelist_data = {
                    'category': 'time_based',
                    'data': {
                        'source_ip': src_ip,
                        'start_hour': self.start_hour.value() if hasattr(self, 'start_hour') else 2,
                        'end_hour': self.end_hour.value() if hasattr(self, 'end_hour') else 5,
                        'reason': reason,
                        'enabled': self.enable_immediately.isChecked()
                    }
                }
            
            elif wl_type == "protocol_based":
                protocol = metadata.get('protocol', self.alert.get('protocol', 'TCP'))  # Get from alert if not in metadata
                src_ip = metadata.get('src_ip', '')
                
                if not protocol:  # If still no protocol, use a default or show error
                    QMessageBox.warning(self, "Missing Protocol", 
                                      "Cannot determine protocol for this alert. "
                                      "Try using Source IP whitelist instead.")
                    return
                
                self.whitelist_data = {
                    'category': 'protocol_based',
                    'data': {
                        'protocol': protocol,
                        'source_ip': src_ip,
                        'reason': reason,
                        'enabled': self.enable_immediately.isChecked()
                    }
                }
                   
            self.accept()
            
        except Exception as e:
            logger.error(f"Error creating whitelist entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create whitelist entry: {e}")