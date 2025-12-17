"""
Whitelist management panel for settings with inline editing.
This version supports both alert-based and manual whitelist entries with inline add/edit.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem,
                             QTabWidget, QScrollArea, QMessageBox, QFileDialog,
                             QHeaderView, QSpinBox, QFormLayout, QLineEdit,
                             QComboBox)
from PyQt6.QtCore import Qt
from pathlib import Path
import uuid

from core.logger import get_logger
from core.app_config import AppConfig, SmallToggleButton

logger = get_logger(__name__)


class WhitelistPanel(QWidget):
    """Panel for managing whitelist in settings."""
    
    def __init__(self, config: AppConfig, whitelist_manager, parent=None):
        """
        Initialize whitelist panel.
        
        Args:
            config: Application configuration
            whitelist_manager: WhitelistManager instance
            parent: Parent widget
        """
        super().__init__(parent)
        self.config = config
        self.whitelist_manager = whitelist_manager
        
        # Track editing rows per category
        self.editing_rows = {}  # {category: {row_index: entry_id}}
        
        self.setStyleSheet("background-color: #1a1a1a; color: white;")
        
        self._setup_ui()
        self._load_whitelist_data()
    
    def _setup_ui(self):
        """Setup UI components."""
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Whitelist Management")
        title.setStyleSheet("font-size: 18px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)
        
        # Global settings
        global_group = self._create_global_settings()
        layout.addWidget(global_group)
        
        # Tabs for different whitelist types
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: white;
                padding: 8px 16px;
                border: 1px solid #444;
            }
            QTabBar::tab:selected {
                background-color: #333;
            }
        """)
        
        # Add tabs for each whitelist type
        tabs.addTab(self._create_whitelist_table('source_ip', 'Source IP'), "Source IP")
        tabs.addTab(self._create_whitelist_table('destination_ip', 'Destination IP'), "Destination IP")
        tabs.addTab(self._create_whitelist_table('ip_pair', 'IP Pairs'), "IP Pairs")
        tabs.addTab(self._create_whitelist_table('cidr_subnet', 'CIDR/Subnets'), "Subnets")
        tabs.addTab(self._create_whitelist_table('port_based', 'Port-Based'), "Ports")
        tabs.addTab(self._create_whitelist_table('rule_specific', 'Rule Exceptions'), "Rules")
        tabs.addTab(self._create_whitelist_table('time_based', 'Time-Based'), "Time")
        tabs.addTab(self._create_whitelist_table('protocol_based', 'Protocol-Based'), "Protocols")
        tabs.addTab(self._create_statistics_view(), "Statistics")
        tabs.addTab(self._create_audit_log_view(), "Audit Log")
        
        layout.addWidget(tabs)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        export_btn = QPushButton("Export Whitelist")
        export_btn.clicked.connect(self._export_whitelist)
        button_layout.addWidget(export_btn)
        
        import_btn = QPushButton("Import Whitelist")
        import_btn.clicked.connect(self._import_whitelist)
        button_layout.addWidget(import_btn)
        
        review_btn = QPushButton("Mark as Reviewed")
        review_btn.clicked.connect(self._mark_reviewed)
        review_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff8800;
                color: white;
                border: 2px solid #ffaa00;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffaa00;
            }
        """)
        button_layout.addWidget(review_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _create_global_settings(self) -> QWidget:
        """Create global whitelist settings section."""
        from PyQt6.QtWidgets import QGroupBox
        
        group = QGroupBox("Global Settings")
        group.setStyleSheet("""
            QGroupBox {
                color: white;
                border: 1px solid #444;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                color: white;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout()
        
        # Enable/Disable all
        self.enable_all_toggle = SmallToggleButton()
        self.enable_all_toggle.setEnabled(self.whitelist_manager.whitelist.get('whitelist_enabled', True))
        layout.addRow("Enable Whitelist:", self.enable_all_toggle)
        
        # Review interval
        self.review_interval_spin = QSpinBox()
        self.review_interval_spin.setRange(30, 365)
        self.review_interval_spin.setValue(self.whitelist_manager.whitelist.get('review_interval_days', 180))
        self.review_interval_spin.setSuffix(" days")
        layout.addRow("Review Interval:", self.review_interval_spin)
        
        # Last review date
        last_review = self.whitelist_manager.whitelist.get('last_review', 'Never')
        last_review_label = QLabel(last_review[:10] if len(last_review) > 10 else last_review)
        layout.addRow("Last Review:", last_review_label)
        
        # Next review date
        next_review = self.whitelist_manager.whitelist.get('next_review', 'Not set')
        next_review_label = QLabel(next_review[:10] if len(next_review) > 10 else next_review)
        layout.addRow("Next Review:", next_review_label)
        
        group.setLayout(layout)
        return group
    
    def _create_whitelist_table(self, category: str, title: str) -> QWidget:
        """Create table for whitelist category."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # One-liner description
        descriptions = {
            'source_ip': "Ignore alerts from these source IPs",
            'destination_ip': "Ignore alerts to these destination IPs",
            'ip_pair': "Ignore specific source→destination connections",
            'cidr_subnet': "Ignore entire IP ranges (e.g., 192.168.1.0/24)",
            'port_based': "Ignore alerts for specific IP:Port combinations",
            'rule_specific': "Disable specific detection rules for certain IPs",
            'time_based': "Ignore alerts during specific time windows",
            'protocol_based': "Ignore specific protocols from certain IPs"
        }
        
        desc_label = QLabel(f"ℹ️ {descriptions.get(category, '')}")
        desc_label.setStyleSheet("color: #888; padding: 5px; font-size: 11px;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        # Table
        table = QTableWidget()
        table.setStyleSheet("""
            QTableWidget {
                background-color: black;
                color: white;
                gridline-color: #333;
            }
            QHeaderView::section {
                background-color: #1a1a1a;
                color: white;
                padding: 5px;
                border: 1px solid #333;
            }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #555;
                padding: 2px;
            }
        """)
        
        # Set columns based on category
        if category == 'source_ip' or category == 'destination_ip':
            table.setColumnCount(7)
            table.setHorizontalHeaderLabels(["ID", "IP", "Reason", "Added", "Hits", "Enabled", "Actions"])
        elif category == 'ip_pair':
            table.setColumnCount(8)
            table.setHorizontalHeaderLabels(["ID", "Source IP", "Dest IP", "Reason", "Added", "Hits", "Enabled", "Actions"])
        elif category == 'cidr_subnet':
            table.setColumnCount(8)
            table.setHorizontalHeaderLabels(["ID", "Subnet", "Direction", "Reason", "Added", "Hits", "Enabled", "Actions"])
        elif category == 'port_based':
            table.setColumnCount(9)
            table.setHorizontalHeaderLabels(["ID", "IP", "Port", "Direction", "Reason", "Added", "Hits", "Enabled", "Actions"])
        elif category == 'rule_specific':
            table.setColumnCount(8)
            table.setHorizontalHeaderLabels(["ID", "Rule Name", "Source IP", "Reason", "Added", "Hits", "Enabled", "Actions"])
        elif category == 'time_based':
            table.setColumnCount(8)
            table.setHorizontalHeaderLabels(["ID", "Source IP", "Time Window", "Reason", "Added", "Hits", "Enabled", "Actions"])
        elif category == 'protocol_based':
            table.setColumnCount(8)
            table.setHorizontalHeaderLabels(["ID", "Protocol", "Source IP", "Reason", "Added", "Hits", "Enabled", "Actions"])
        
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        
        layout.addWidget(table)
        
        # Add/Remove buttons
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add New")
        add_btn.clicked.connect(lambda: self._add_empty_row(category))
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                border: 1px solid #00ff00;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #00cc00;
            }
        """)
        btn_layout.addWidget(add_btn)
        
        # Remove All button
        remove_all_btn = QPushButton("Remove All")
        remove_all_btn.clicked.connect(lambda: self._remove_all_entries(category))
        remove_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #aa0000;
                color: white;
                border: 1px solid #ff0000;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        btn_layout.addWidget(remove_all_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        widget.setLayout(layout)
        
        # Store table reference
        setattr(self, f'{category}_table', table)
        
        # Initialize editing rows tracker for this category
        self.editing_rows[category] = {}
        
        return widget
    
    def _create_statistics_view(self) -> QWidget:
        """Create statistics view."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        stats_label = QLabel("Whitelist Statistics")
        stats_label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px;")
        layout.addWidget(stats_label)
        
        # Get statistics
        stats = self.whitelist_manager.get_statistics()
        
        # Create table
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Metric", "Value"])
        table.setStyleSheet("""
            QTableWidget {
                background-color: black;
                color: white;
                gridline-color: #333;
            }
            QHeaderView::section {
                background-color: #1a1a1a;
                color: white;
                padding: 5px;
            }
        """)
        
        # Populate with statistics
        metrics = [
            ("Total Filtered Alerts", stats.get('total_filtered', 0)),
            ("Total Alerted", stats.get('total_alerted', 0)),
            ("Filter Rate", f"{stats.get('filter_rate', 0):.1f}%"),
            ("Active Source IP Rules", stats.get('active_entries', {}).get('source_ip', 0)),
            ("Active Destination IP Rules", stats.get('active_entries', {}).get('destination_ip', 0)),
            ("Active IP Pair Rules", stats.get('active_entries', {}).get('ip_pair', 0)),
            ("Active CIDR Rules", stats.get('active_entries', {}).get('cidr_subnet', 0)),
            ("Total Active Rules", stats.get('total_active', 0)),
        ]
        
        table.setRowCount(len(metrics))
        for row, (metric, value) in enumerate(metrics):
            table.setItem(row, 0, QTableWidgetItem(metric))
            table.setItem(row, 1, QTableWidgetItem(str(value)))
        
        table.resizeColumnsToContents()
        layout.addWidget(table)
        
        widget.setLayout(layout)
        return widget
    
    def _create_audit_log_view(self) -> QWidget:
        """Create audit log view."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        label = QLabel("Audit Log - Recent Changes")
        label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px;")
        layout.addWidget(label)
        
        # Read audit log
        from PyQt6.QtWidgets import QTextEdit
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("""
            QTextEdit {
                background-color: black;
                color: #00ff00;
                font-family: monospace;
                font-size: 10px;
            }
        """)
        
        try:
            if self.whitelist_manager.audit_log_file.exists():
                with open(self.whitelist_manager.audit_log_file, 'r') as f:
                    lines = f.readlines()
                    # Show last 100 lines
                    text_edit.setPlainText(''.join(lines[-100:]))
        except Exception as e:
            text_edit.setPlainText(f"Error loading audit log: {e}")
        
        layout.addWidget(text_edit)
        
        widget.setLayout(layout)
        return widget
    
    def _load_whitelist_data(self):
        """Load whitelist data into tables."""
        for category in ['source_ip', 'destination_ip', 'ip_pair', 'cidr_subnet',
                        'port_based', 'rule_specific', 'time_based', 'protocol_based']:
            self._populate_table(category)
    
    def _add_empty_row(self, category: str):
        """Add an empty editable row to the table."""
        try:
            table = getattr(self, f'{category}_table', None)
            if not table:
                return
            
            # Generate temporary ID for new entry
            temp_id = f"new_{uuid.uuid4().hex[:8]}"
            
            # Add new row at the end
            row = table.rowCount()
            table.insertRow(row)
            
            # Track this as an editing row
            self.editing_rows[category][row] = temp_id
            
            # Populate with editable widgets
            self._populate_empty_row(table, row, category, temp_id)
            
        except Exception as e:
            logger.error(f"Error adding empty row to {category}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add new row: {e}")
    
    def _populate_empty_row(self, table: QTableWidget, row: int, category: str, temp_id: str):
        """Populate a row with empty/default editable widgets."""
        col = 0
        
        # ID (non-editable, shows temp ID)
        id_item = QTableWidgetItem(temp_id)
        id_item.setFlags(id_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        id_item.setForeground(Qt.GlobalColor.darkGray)
        table.setItem(row, col, id_item)
        col += 1
        
        # Category-specific editable fields
        if category in ['source_ip', 'destination_ip']:
            # IP field
            ip_input = QLineEdit()
            ip_input.setPlaceholderText("Enter IP address")
            table.setCellWidget(row, col, ip_input)
            col += 1
        
        elif category == 'ip_pair':
            # Source IP
            src_input = QLineEdit()
            src_input.setPlaceholderText("Source IP")
            table.setCellWidget(row, col, src_input)
            col += 1
            
            # Destination IP
            dst_input = QLineEdit()
            dst_input.setPlaceholderText("Dest IP")
            table.setCellWidget(row, col, dst_input)
            col += 1
        
        elif category == 'cidr_subnet':
            # Subnet
            subnet_input = QLineEdit()
            subnet_input.setPlaceholderText("e.g., 192.168.1.0/24")
            table.setCellWidget(row, col, subnet_input)
            col += 1
            
            # Direction
            direction_combo = QComboBox()
            direction_combo.addItems(["source", "destination", "both"])
            table.setCellWidget(row, col, direction_combo)
            col += 1
        
        elif category == 'port_based':
            # IP
            ip_input = QLineEdit()
            ip_input.setPlaceholderText("IP address")
            table.setCellWidget(row, col, ip_input)
            col += 1
            
            # Port
            port_input = QLineEdit()
            port_input.setPlaceholderText("Port number")
            table.setCellWidget(row, col, port_input)
            col += 1
            
            # Direction
            direction_combo = QComboBox()
            direction_combo.addItems(["source", "destination", "both"])
            table.setCellWidget(row, col, direction_combo)
            col += 1
        
        elif category == 'rule_specific':
            # Rule name
            rule_input = QLineEdit()
            rule_input.setPlaceholderText("Rule name")
            table.setCellWidget(row, col, rule_input)
            col += 1
            
            # Source IP
            ip_input = QLineEdit()
            ip_input.setPlaceholderText("Source IP")
            table.setCellWidget(row, col, ip_input)
            col += 1
        
        elif category == 'time_based':
            # Source IP
            ip_input = QLineEdit()
            ip_input.setPlaceholderText("Source IP")
            table.setCellWidget(row, col, ip_input)
            col += 1
            
            # Time window (using a container widget)
            time_widget = QWidget()
            time_layout = QHBoxLayout(time_widget)
            time_layout.setContentsMargins(0, 0, 0, 0)
            
            start_spin = QSpinBox()
            start_spin.setRange(0, 23)
            start_spin.setPrefix("Start: ")
            time_layout.addWidget(start_spin)
            
            end_spin = QSpinBox()
            end_spin.setRange(0, 23)
            end_spin.setPrefix("End: ")
            time_layout.addWidget(end_spin)
            
            table.setCellWidget(row, col, time_widget)
            col += 1
        
        elif category == 'protocol_based':
            # Protocol
            protocol_combo = QComboBox()
            protocol_combo.addItems(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"])
            table.setCellWidget(row, col, protocol_combo)
            col += 1
            
            # Source IP
            ip_input = QLineEdit()
            ip_input.setPlaceholderText("Source IP")
            table.setCellWidget(row, col, ip_input)
            col += 1
        
        # Reason (always editable)
        reason_input = QLineEdit()
        reason_input.setPlaceholderText("Reason for whitelist")
        table.setCellWidget(row, col, reason_input)
        col += 1
        
        # Added date (auto-filled when applied)
        date_item = QTableWidgetItem("(pending)")
        date_item.setFlags(date_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        date_item.setForeground(Qt.GlobalColor.darkGray)
        table.setItem(row, col, date_item)
        col += 1
        
        # Hit count (default 0)
        hits_item = QTableWidgetItem("0")
        hits_item.setFlags(hits_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        table.setItem(row, col, hits_item)
        col += 1
        
        # Enabled (default checked)
        enabled_item = QTableWidgetItem("✓")
        enabled_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        enabled_item.setForeground(Qt.GlobalColor.green)
        table.setItem(row, col, enabled_item)
        col += 1
        
        # Actions: Apply and Remove buttons
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(2, 2, 2, 2)
        actions_layout.setSpacing(3)
        
        apply_btn = QPushButton("Apply")
        apply_btn.setFixedSize(80, 30)
        apply_btn.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                border: 1px solid #00ff00;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #00cc00;
            }
        """)
        apply_btn.clicked.connect(lambda: self._apply_row(category, row, temp_id))
        actions_layout.addWidget(apply_btn)
        
        remove_btn = QPushButton("Remove")
        remove_btn.setFixedSize(80, 30)
        remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #aa3333;
                color: white;
                border: 1px solid #ff4444;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #cc4444;
            }
        """)
        remove_btn.clicked.connect(lambda: self._cancel_new_row(category, row))
        actions_layout.addWidget(remove_btn)
        
        table.setCellWidget(row, col, actions_widget)
    
    def _apply_row(self, category: str, row: int, temp_id: str):
        """Apply/save the row data to whitelist."""
        try:
            table = getattr(self, f'{category}_table', None)
            if not table:
                return
            
            # Extract data from widgets
            entry_data = self._extract_row_data(table, row, category)
            
            if not entry_data:
                QMessageBox.warning(self, "Validation Error", 
                                  "Please fill in all required fields.")
                return
            
            # Add to whitelist manager
            success = self.whitelist_manager.add_whitelist_entry(category, entry_data)
            
            if success:
                # Remove from editing tracker
                if row in self.editing_rows[category]:
                    del self.editing_rows[category][row]
                
                # Refresh table to show as normal entry with Edit button
                self._populate_table(category)
                
                QMessageBox.information(self, "Success", 
                                      "Whitelist entry added successfully.")
            else:
                QMessageBox.critical(self, "Error", 
                                   "Failed to add whitelist entry.")
        
        except Exception as e:
            logger.error(f"Error applying row in {category}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to apply entry: {e}")
    
    def _extract_row_data(self, table: QTableWidget, row: int, category: str) -> dict:
        """Extract data from editable widgets in a row."""
        data = {
            'enabled': True,  # Default
            'hit_count': 0
        }
        
        col = 1  # Skip ID column
        
        try:
            if category in ['source_ip', 'destination_ip']:
                ip_widget = table.cellWidget(row, col)
                if not ip_widget or not ip_widget.text().strip():
                    return None
                data['ip'] = ip_widget.text().strip()
                col += 1
            
            elif category == 'ip_pair':
                src_widget = table.cellWidget(row, col)
                if not src_widget or not src_widget.text().strip():
                    return None
                data['source_ip'] = src_widget.text().strip()
                col += 1
                
                dst_widget = table.cellWidget(row, col)
                if not dst_widget or not dst_widget.text().strip():
                    return None
                data['destination_ip'] = dst_widget.text().strip()
                col += 1
            
            elif category == 'cidr_subnet':
                subnet_widget = table.cellWidget(row, col)
                if not subnet_widget or not subnet_widget.text().strip():
                    return None
                data['subnet'] = subnet_widget.text().strip()
                col += 1
                
                direction_widget = table.cellWidget(row, col)
                data['direction'] = direction_widget.currentText() if direction_widget else 'both'
                col += 1
            
            elif category == 'port_based':
                ip_widget = table.cellWidget(row, col)
                if not ip_widget or not ip_widget.text().strip():
                    return None
                data['ip'] = ip_widget.text().strip()
                col += 1
                
                port_widget = table.cellWidget(row, col)
                if not port_widget or not port_widget.text().strip():
                    return None
                data['port'] = int(port_widget.text().strip())
                col += 1
                
                direction_widget = table.cellWidget(row, col)
                data['direction'] = direction_widget.currentText() if direction_widget else 'both'
                col += 1
            
            elif category == 'rule_specific':
                rule_widget = table.cellWidget(row, col)
                if not rule_widget or not rule_widget.text().strip():
                    return None
                data['rule_name'] = rule_widget.text().strip()
                col += 1
                
                ip_widget = table.cellWidget(row, col)
                if not ip_widget or not ip_widget.text().strip():
                    return None
                data['source_ip'] = ip_widget.text().strip()
                col += 1
            
            elif category == 'time_based':
                ip_widget = table.cellWidget(row, col)
                if not ip_widget or not ip_widget.text().strip():
                    return None
                data['source_ip'] = ip_widget.text().strip()
                col += 1
                
                time_widget = table.cellWidget(row, col)
                if time_widget:
                    layout = time_widget.layout()
                    start_spin = layout.itemAt(0).widget()
                    end_spin = layout.itemAt(1).widget()
                    data['start_hour'] = start_spin.value()
                    data['end_hour'] = end_spin.value()
                col += 1
            
            elif category == 'protocol_based':
                protocol_widget = table.cellWidget(row, col)
                data['protocol'] = protocol_widget.currentText() if protocol_widget else 'TCP'
                col += 1
                
                ip_widget = table.cellWidget(row, col)
                if not ip_widget or not ip_widget.text().strip():
                    return None
                data['source_ip'] = ip_widget.text().strip()
                col += 1
            
            # Reason (required)
            reason_widget = table.cellWidget(row, col)
            if not reason_widget or not reason_widget.text().strip():
                return None
            data['reason'] = reason_widget.text().strip()
            
            return data
            
        except Exception as e:
            logger.error(f"Error extracting row data: {e}")
            return None
    
    def _cancel_new_row(self, category: str, row: int):
        """Cancel adding new entry and remove the row."""
        table = getattr(self, f'{category}_table', None)
        if not table:
            return
        
        # Remove from editing tracker
        if row in self.editing_rows[category]:
            del self.editing_rows[category][row]
        
        # Remove the row
        table.removeRow(row)
    
    def _populate_table(self, category: str):
        """Populate table with whitelist entries."""
        try:
            table = getattr(self, f'{category}_table', None)
            if not table:
                return
            
            entries = self.whitelist_manager.whitelist.get(category, [])
            
            # Handle empty or corrupted entries
            if not isinstance(entries, list):
                logger.error(f"Invalid entries for {category}: {type(entries)}")
                entries = []
            
            # Clear table
            table.setRowCount(0)
            
            # Clear editing tracker
            self.editing_rows[category] = {}
            
            table.setRowCount(len(entries))
            
            for row, entry in enumerate(entries):
                col = 0
                if not isinstance(entry, dict):
                    logger.error(f"Invalid entry in {category}: {entry}")
                    continue
                
                # ID
                id_item = QTableWidgetItem(entry.get('id', ''))
                id_item.setFlags(id_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, col, id_item)
                col += 1
                
                # Category-specific columns (non-editable display)
                if category in ['source_ip', 'destination_ip']:
                    ip_item = QTableWidgetItem(entry.get('ip', ''))
                    ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, ip_item)
                    col += 1
                
                elif category == 'ip_pair':
                    src_item = QTableWidgetItem(entry.get('source_ip', ''))
                    src_item.setFlags(src_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, src_item)
                    col += 1
                    
                    dst_item = QTableWidgetItem(entry.get('destination_ip', ''))
                    dst_item.setFlags(dst_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, dst_item)
                    col += 1
                
                elif category == 'cidr_subnet':
                    subnet_item = QTableWidgetItem(entry.get('subnet', ''))
                    subnet_item.setFlags(subnet_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, subnet_item)
                    col += 1
                    
                    direction_item = QTableWidgetItem(entry.get('direction', ''))
                    direction_item.setFlags(direction_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, direction_item)
                    col += 1
                
                elif category == 'port_based':
                    ip_item = QTableWidgetItem(entry.get('ip', ''))
                    ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, ip_item)
                    col += 1
                    
                    port_item = QTableWidgetItem(str(entry.get('port', '')))
                    port_item.setFlags(port_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, port_item)
                    col += 1
                    
                    direction_item = QTableWidgetItem(entry.get('direction', ''))
                    direction_item.setFlags(direction_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, direction_item)
                    col += 1
                
                elif category == 'rule_specific':
                    rule_item = QTableWidgetItem(entry.get('rule_name', ''))
                    rule_item.setFlags(rule_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, rule_item)
                    col += 1
                    
                    ip_item = QTableWidgetItem(entry.get('source_ip', ''))
                    ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, ip_item)
                    col += 1
                
                elif category == 'time_based':
                    ip_item = QTableWidgetItem(entry.get('source_ip', ''))
                    ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, ip_item)
                    col += 1
                    
                    time_item = QTableWidgetItem(f"{entry.get('start_hour', 0)}-{entry.get('end_hour', 0)}")
                    time_item.setFlags(time_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, time_item)
                    col += 1
                
                elif category == 'protocol_based':
                    protocol_item = QTableWidgetItem(entry.get('protocol', ''))
                    protocol_item.setFlags(protocol_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, protocol_item)
                    col += 1
                    
                    ip_item = QTableWidgetItem(entry.get('source_ip', ''))
                    ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, col, ip_item)
                    col += 1
                
                # Reason
                reason_item = QTableWidgetItem(entry.get('reason', ''))
                reason_item.setFlags(reason_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, col, reason_item)
                col += 1
                
                # Added date
                added_date = entry.get('added_date', '')
                date_str = added_date[:10] if len(added_date) > 10 else added_date
                date_item = QTableWidgetItem(date_str)
                date_item.setFlags(date_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, col, date_item)
                col += 1
                
                # Hit count
                hits_item = QTableWidgetItem(str(entry.get('hit_count', 0)))
                hits_item.setFlags(hits_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, col, hits_item)
                col += 1
                
                # Enabled toggle
                enabled = entry.get('enabled', True)
                enabled_item = QTableWidgetItem("✓" if enabled else "✗")
                enabled_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if enabled:
                    enabled_item.setForeground(Qt.GlobalColor.green)
                else:
                    enabled_item.setForeground(Qt.GlobalColor.red)
                table.setItem(row, col, enabled_item)
                col += 1
                
                # Actions: Edit and Remove buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                actions_layout.setSpacing(3)
                
                edit_btn = QPushButton("Edit")
                edit_btn.setFixedSize(80, 30)
                edit_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #5555aa;
                        color: white;
                        border: 1px solid #7777cc;
                        font-size: 10px;
                    }
                    QPushButton:hover {
                        background-color: #6666bb;
                    }
                """)
                entry_id = entry.get('id', '')
                edit_btn.clicked.connect(lambda checked, cat=category, eid=entry_id: self._edit_entry(cat, eid))
                actions_layout.addWidget(edit_btn)
                
                remove_btn = QPushButton("Remove")
                remove_btn.setFixedSize(80, 30)
                remove_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #aa3333;
                        color: white;
                        border: 1px solid #ff4444;
                        font-size: 10px;
                    }
                    QPushButton:hover {
                        background-color: #cc4444;
                    }
                """)
                remove_btn.clicked.connect(lambda checked, cat=category, eid=entry_id: self._remove_whitelist_entry(cat, eid))
                actions_layout.addWidget(remove_btn)
                
                table.setCellWidget(row, col, actions_widget)
            
            table.resizeColumnsToContents()
            
        except Exception as e:
            logger.error(f"Error populating table {category}: {e}")
    
    def _edit_entry(self, category: str, entry_id: str):
        """Convert existing entry to editable mode."""
        try:
            table = getattr(self, f'{category}_table', None)
            if not table:
                return
            
            # Find the row with this entry_id
            for row in range(table.rowCount()):
                id_item = table.item(row, 0)
                if id_item and id_item.text() == entry_id:
                    # Get the entry data
                    entries = self.whitelist_manager.whitelist.get(category, [])
                    entry = next((e for e in entries if e.get('id') == entry_id), None)
                    
                    if not entry:
                        return
                    
                    # Convert row to editable mode
                    self._convert_row_to_editable(table, row, category, entry)
                    break
        
        except Exception as e:
            logger.error(f"Error editing entry {entry_id}: {e}")
    
    def _convert_row_to_editable(self, table: QTableWidget, row: int, category: str, entry: dict):
        """Convert a display row to editable mode."""
        col = 1  # Skip ID
        
        # Track as editing
        self.editing_rows[category][row] = entry.get('id', '')
        
        # Replace display items with editable widgets based on category
        if category in ['source_ip', 'destination_ip']:
            ip_input = QLineEdit(entry.get('ip', ''))
            table.setCellWidget(row, col, ip_input)
            col += 1
        
        elif category == 'ip_pair':
            src_input = QLineEdit(entry.get('source_ip', ''))
            table.setCellWidget(row, col, src_input)
            col += 1
            
            dst_input = QLineEdit(entry.get('destination_ip', ''))
            table.setCellWidget(row, col, dst_input)
            col += 1
        
        elif category == 'cidr_subnet':
            subnet_input = QLineEdit(entry.get('subnet', ''))
            table.setCellWidget(row, col, subnet_input)
            col += 1
            
            direction_combo = QComboBox()
            direction_combo.addItems(["source", "destination", "both"])
            direction_combo.setCurrentText(entry.get('direction', 'both'))
            table.setCellWidget(row, col, direction_combo)
            col += 1
        
        elif category == 'port_based':
            ip_input = QLineEdit(entry.get('ip', ''))
            table.setCellWidget(row, col, ip_input)
            col += 1
            
            port_input = QLineEdit(str(entry.get('port', '')))
            table.setCellWidget(row, col, port_input)
            col += 1
            
            direction_combo = QComboBox()
            direction_combo.addItems(["source", "destination", "both"])
            direction_combo.setCurrentText(entry.get('direction', 'both'))
            table.setCellWidget(row, col, direction_combo)
            col += 1
        
        elif category == 'rule_specific':
            rule_input = QLineEdit(entry.get('rule_name', ''))
            table.setCellWidget(row, col, rule_input)
            col += 1
            
            ip_input = QLineEdit(entry.get('source_ip', ''))
            table.setCellWidget(row, col, ip_input)
            col += 1
        
        elif category == 'time_based':
            ip_input = QLineEdit(entry.get('source_ip', ''))
            table.setCellWidget(row, col, ip_input)
            col += 1
            
            time_widget = QWidget()
            time_layout = QHBoxLayout(time_widget)
            time_layout.setContentsMargins(0, 0, 0, 0)
            
            start_spin = QSpinBox()
            start_spin.setRange(0, 23)
            start_spin.setValue(entry.get('start_hour', 0))
            start_spin.setPrefix("Start: ")
            time_layout.addWidget(start_spin)
            
            end_spin = QSpinBox()
            end_spin.setRange(0, 23)
            end_spin.setValue(entry.get('end_hour', 0))
            end_spin.setPrefix("End: ")
            time_layout.addWidget(end_spin)
            
            table.setCellWidget(row, col, time_widget)
            col += 1
        
        elif category == 'protocol_based':
            protocol_combo = QComboBox()
            protocol_combo.addItems(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"])
            protocol_combo.setCurrentText(entry.get('protocol', 'TCP'))
            table.setCellWidget(row, col, protocol_combo)
            col += 1
            
            ip_input = QLineEdit(entry.get('source_ip', ''))
            table.setCellWidget(row, col, ip_input)
            col += 1
        
        # Reason (editable)
        reason_input = QLineEdit(entry.get('reason', ''))
        table.setCellWidget(row, col, reason_input)
        col += 1
        
        # Skip Added date, Hits, Enabled (keep as is)
        col += 3
        
        # Replace actions with Apply/Cancel
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(2, 2, 2, 2)
        actions_layout.setSpacing(3)
        
        apply_btn = QPushButton("Apply")
        apply_btn.setFixedSize(80, 30)
        apply_btn.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                border: 1px solid #00ff00;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #00cc00;
            }
        """)
        entry_id = entry.get('id', '')
        apply_btn.clicked.connect(lambda: self._update_entry(category, row, entry_id))
        actions_layout.addWidget(apply_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedSize(80, 30)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #aa5500;
                color: white;
                border: 1px solid #ff7700;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #cc6600;
            }
        """)
        cancel_btn.clicked.connect(lambda: self._cancel_edit(category))
        actions_layout.addWidget(cancel_btn)
        
        table.setCellWidget(row, col, actions_widget)
    
    def _update_entry(self, category: str, row: int, entry_id: str):
        """Update existing entry with edited data."""
        try:
            table = getattr(self, f'{category}_table', None)
            if not table:
                return
            
            # Extract updated data
            updated_data = self._extract_row_data(table, row, category)
            
            if not updated_data:
                QMessageBox.warning(self, "Validation Error", 
                                  "Please fill in all required fields.")
                return
            
            # Update in whitelist manager
            success = self.whitelist_manager.update_whitelist_entry(category, entry_id, updated_data)
            
            if success:
                # Remove from editing tracker
                if row in self.editing_rows[category]:
                    del self.editing_rows[category][row]
                
                # Refresh table
                self._populate_table(category)
                
                QMessageBox.information(self, "Success", 
                                      "Whitelist entry updated successfully.")
            else:
                QMessageBox.critical(self, "Error", 
                                   "Failed to update whitelist entry.")
        
        except Exception as e:
            logger.error(f"Error updating entry {entry_id}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update entry: {e}")
    
    def _cancel_edit(self, category: str):
        """Cancel editing and restore original display."""
        self._populate_table(category)
    
    def _remove_all_entries(self, category: str):
        """Remove all whitelist entries in a category."""
        entries = self.whitelist_manager.whitelist.get(category, [])
        
        if not entries:
            QMessageBox.information(self, "No Entries", 
                                  f"No whitelist entries in {category} category.")
            return
        
        reply = QMessageBox.question(
            self,
            "Confirm Remove All",
            f"Are you sure you want to remove ALL {len(entries)} whitelist entries from {category}?\n\n"
            "This action cannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Remove all entries
            for entry in entries[:]:
                entry_id = entry.get('id', '')
                self.whitelist_manager.remove_whitelist_entry(category, entry_id)
            
            # Refresh the table
            self._populate_table(category)
            QMessageBox.information(self, "Success", 
                                  f"All whitelist entries removed from {category}.")
    
    def _remove_whitelist_entry(self, category: str, entry_id: str):
        """Remove whitelist entry with confirmation."""
        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to remove this whitelist entry?\n\nID: {entry_id}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success = self.whitelist_manager.remove_whitelist_entry(category, entry_id)
            
            if success:
                # Refresh the table
                self._populate_table(category)
                QMessageBox.information(self, "Success", "Whitelist entry removed.")
            else:
                QMessageBox.critical(self, "Error", "Failed to remove whitelist entry.")
    
    def _export_whitelist(self):
        """Export whitelist to JSON file."""
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Whitelist",
            str(Path.home() / "netgui_whitelist.json"),
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filepath:
            success = self.whitelist_manager.export_whitelist(filepath)
            if success:
                QMessageBox.information(self, "Success", 
                                      f"Whitelist exported to:\n{filepath}")
            else:
                QMessageBox.critical(self, "Error", "Failed to export whitelist")
    
    def _import_whitelist(self):
        """Import whitelist from JSON file."""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Import Whitelist",
            str(Path.home()),
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filepath:
            reply = QMessageBox.question(
                self,
                "Import Mode",
                "Merge with existing whitelist or replace?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            
            if reply == QMessageBox.StandardButton.Cancel:
                return
            
            merge = (reply == QMessageBox.StandardButton.Yes)
            
            success = self.whitelist_manager.import_whitelist(filepath, merge=merge)
            
            if success:
                self._load_whitelist_data()
                QMessageBox.information(self, "Success", 
                                      f"Whitelist imported from:\n{filepath}")
            else:
                QMessageBox.critical(self, "Error", "Failed to import whitelist")
    
    def _mark_reviewed(self):
        """Mark whitelist as reviewed."""
        self.whitelist_manager.mark_reviewed()
        
        # Refresh display
        self._setup_ui()
        self._load_whitelist_data()
        
        QMessageBox.information(self, "Success", 
                              "Whitelist marked as reviewed.\n"
                              "Next review date has been updated.")
    
    def save_settings(self):
        """Save whitelist settings when closing."""
        # Save global settings
        self.whitelist_manager.whitelist['whitelist_enabled'] = self.enable_all_toggle.isEnabled()
        self.whitelist_manager.whitelist['review_interval_days'] = self.review_interval_spin.value()
        self.whitelist_manager._save_whitelist()