"""
Main application window for NetObserver.
Extends the baseline dashboard layout with functional panels.
"""

from PyQt6.QtWidgets import (QMainWindow, QWidget, QGridLayout, QMenuBar, 
                             QMenu, QMessageBox, QFileDialog, QDialog, 
                             QVBoxLayout, QLabel, QCheckBox, QPushButton)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QAction
import platform

from typing import Dict, Any
from pathlib import Path

from core.logger import get_logger
from core.orchestrator import Orchestrator
from ui.panels.connections_panel import ConnectionsPanel
from ui.panels.protocols_panel import ProtocolsPanel
from ui.panels.logs_panel import LogsPanel
from ui.panels.alerts_panel import AlertsPanel
from ui.panels.helper_panel import HelperPanel
from ui.panels.action_panel import ActionPanel
from ui.widgets.ring_indicator import RingIndicator

logger = get_logger(__name__)


class SettingsReminderDialog(QDialog):
    """Dialog reminding users to configure settings for optimal performance."""
    
    def __init__(self, parent=None):
        """Initialize reminder dialog."""
        super().__init__(parent)
        self.setWindowTitle("NetObserver - First Time Setup")
        self.setMinimumSize(600, 400)  # Set minimum instead of fixed
        self.dont_show_again = False
        
        # Use same styling as "Things You Should Know" dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                background-color: transparent;
            }
            QCheckBox {
                color: white;
                background-color: transparent;
                spacing: 5px;
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
            QCheckBox::indicator:unchecked {
                background-color: #2a2a2a;
                border: 1px solid #555;
            }
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                padding: 10px 20px;
                min-height: 35px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)
        
        # Icon and title
        title_label = QLabel("⚙️ Optimize Your Experience")
        title_label.setStyleSheet("""
            font-size: 20px; 
            font-weight: bold; 
            padding: 15px;
            color: white;
            background-color: transparent;
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Message
        message = QLabel(
            "For peak performance and accurate threat detection, it's recommended to:\n\n"
            "  •  Configure your detection rules in Settings → Preferences → Detection Rules\n\n"
            "  •  Adjust thresholds based on your network environment\n\n"
            "  •  Enable/disable rules relevant to your use case\n\n"
            "This ensures you get meaningful alerts without false positives."
        )
        message.setWordWrap(True)
        message.setStyleSheet("""
            padding: 15px; 
            color: white;
            background-color: #0a0a0a;
            border: 1px solid #333;
            border-radius: 5px;
            font-size: 13px;
            line-height: 150%;
        """)
        layout.addWidget(message)
        
        layout.addSpacing(10)
        
        # Don't show again checkbox
        self.dont_show_checkbox = QCheckBox("Don't show this message again")
        self.dont_show_checkbox.setStyleSheet("""
            padding: 10px;
            color: white;
            background-color: transparent;
            font-size: 12px;
        """)
        layout.addWidget(self.dont_show_checkbox)
        
        layout.addSpacing(10)
        
        # Buttons
        button_layout = QVBoxLayout()
        button_layout.setSpacing(10)
        
        settings_btn = QPushButton("Open Settings Now")
        settings_btn.clicked.connect(self._open_settings)
        settings_btn.setMinimumHeight(20)
        settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                border: 2px solid #00ff00;
                padding: 12px;
                font-weight: bold;
                font-size: 14px;
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: #00cc00;
            }
        """)
        button_layout.addWidget(settings_btn)
        
        continue_btn = QPushButton("Continue Without Configuring")
        continue_btn.clicked.connect(self._continue)
        continue_btn.setMinimumHeight(20)
        continue_btn.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                padding: 10px;
                font-size: 13px;
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        button_layout.addWidget(continue_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Adjust size to content
        self.adjustSize()
    
    def _open_settings(self):
        """Open settings and close dialog."""
        self.dont_show_again = self.dont_show_checkbox.isChecked()
        self.done(2)  # Custom return code for "open settings"
    
    def _continue(self):
        """Continue without opening settings."""
        self.dont_show_again = self.dont_show_checkbox.isChecked()
        self.accept()

class WhitelistReviewDialog(QDialog):
    """Dialog reminding users to review whitelist."""
    
    def __init__(self, parent=None):
        """Initialize whitelist review dialog."""
        super().__init__(parent)
        self.setWindowTitle("Whitelist Review Due")
        self.setMinimumSize(500, 300)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                background-color: transparent;
            }
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                padding: 10px 20px;
                min-height: 35px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)
        
        # Icon and title
        title_label = QLabel("🛡️ Whitelist Review Due")
        title_label.setStyleSheet("""
            font-size: 20px; 
            font-weight: bold; 
            padding: 15px;
            color: #ffaa00;
            background-color: transparent;
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Message
        message = QLabel(
            "It's time to review your whitelist entries!\n\n"
            "Regular reviews help ensure:\n\n"
            "  •  Whitelist entries are still valid\n\n"
            "  •  No outdated rules are hiding real threats\n\n"
            "  •  Configurations match current network state\n\n"
            "Click 'Review Now' to open whitelist settings."
        )
        message.setWordWrap(True)
        message.setStyleSheet("""
            padding: 15px; 
            color: white;
            background-color: #0a0a0a;
            border: 1px solid #333;
            border-radius: 5px;
            font-size: 13px;
            line-height: 150%;
        """)
        layout.addWidget(message)
        
        layout.addSpacing(10)
        
        # Buttons
        button_layout = QVBoxLayout()
        button_layout.setSpacing(10)
        
        review_btn = QPushButton("Review Now")
        review_btn.clicked.connect(self.accept)
        review_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff8800;
                color: white;
                border: 2px solid #ffaa00;
                padding: 12px;
                font-weight: bold;
                font-size: 14px;
                min-height: 45px;
            }
            QPushButton:hover {
                background-color: #ffaa00;
            }
        """)
        button_layout.addWidget(review_btn)
        
        later_btn = QPushButton("Remind Me Later")
        later_btn.clicked.connect(self.reject)
        later_btn.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid #555;
                padding: 10px;
                font-size: 13px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        button_layout.addWidget(later_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, orchestrator: Orchestrator):
        """
        Initialize main window.
        
        Args:
            orchestrator: Central application orchestrator
        """
        super().__init__()
        self.orchestrator = orchestrator
        self.has_started_capture = False  # Track if capture has been started
        
        self.setWindowTitle("NetObserver - Defensive Network Visibility")
        self.setGeometry(50, 100, 1800, 900)
        self.setStyleSheet("background-color: black;")
        
        self._setup_menu()
        self._setup_ui()
        self._connect_signals()
        
        # Update initial API status
        self.helper_panel.set_api_status(self.orchestrator.has_api_keys())
        
        logger.info("Main window initialized")

        # Update whitelist info periodically
        from PyQt6.QtCore import QTimer
        self.whitelist_update_timer = QTimer()
        self.whitelist_update_timer.timeout.connect(self._update_whitelist_info)
        self.whitelist_update_timer.start(5000)  # Every 5 seconds
        
        # Initial update
        self._update_whitelist_info()

    def _update_whitelist_info(self):
        """Update whitelist information in UI."""
        try:
            stats = self.orchestrator.get_statistics()
            if 'whitelist' in stats:
                active_rules = stats['whitelist'].get('total_active', 0)
                self.helper_panel.set_whitelist_info(active_rules)
        except Exception as e:
            logger.error(f"Error updating whitelist info: {e}")

        
    def _setup_menu(self) -> None:
        """Setup menu bar."""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #1a1a1a;
                color: white;
            }
            QMenuBar::item:selected {
                background-color: #333;
            }
            QMenu {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid white;
            }
            QMenu::item:selected {
                background-color: #333;
            }
        """)
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        export_action = QAction("Export PCAP...", self)
        export_action.triggered.connect(self._export_pcap)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Capture menu
        capture_menu = menubar.addMenu("Capture")
        
        start_action = QAction("Start Capture", self)
        start_action.triggered.connect(self._start_capture)
        capture_menu.addAction(start_action)
        
        stop_action = QAction("Stop Capture", self)
        stop_action.triggered.connect(self._stop_capture)
        capture_menu.addAction(stop_action)
        
        # Settings menu
        settings_menu = menubar.addMenu("Settings")
        
        settings_action = QAction("Preferences...", self)
        settings_action.triggered.connect(self._open_settings)
        settings_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        things_to_know_action = QAction("Things You Should Know", self)
        things_to_know_action.triggered.connect(self._show_things_to_know)
        help_menu.addAction(things_to_know_action)
        
        help_menu.addSeparator()
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_ui(self) -> None:
        """Setup user interface layout."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main grid layout (matching baseline layout)
        main_layout = QGridLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Create functional panels
        self.connections_panel = ConnectionsPanel()
        self.protocols_panel = ProtocolsPanel()
        self.logs_panel = LogsPanel()
        self.alerts_panel = AlertsPanel()

        # Set max alerts from config (NEW)
        max_alerts = self.orchestrator.config.get('ui.max_alert_rows', 1000)
        self.alerts_panel.set_max_alerts(max_alerts)

        self.helper_panel = HelperPanel()
        self.action_panel = ActionPanel()
        
        # Create central status indicator
        self.ring_indicator = RingIndicator()
        
        # Set minimum sizes
        self.connections_panel.setMinimumSize(380, 250)
        self.protocols_panel.setMinimumSize(380, 250)
        self.logs_panel.setMinimumSize(380, 250)
        self.alerts_panel.setMinimumSize(380, 250)
        self.helper_panel.setMinimumSize(250, 100)
        self.action_panel.setMinimumSize(250, 100)
        
        # Position elements in grid (matching baseline layout)
        main_layout.addWidget(self.connections_panel, 0, 0, 2, 2)
        main_layout.addWidget(self.helper_panel, 0, 2, 1, 2)
        main_layout.addWidget(self.protocols_panel, 0, 4, 2, 2)
        
        # Central ring indicator
        main_layout.addWidget(self.ring_indicator, 1, 2, 2, 2)
        
        # Bottom row
        main_layout.addWidget(self.logs_panel, 2, 0, 2, 2)
        main_layout.addWidget(self.action_panel, 3, 2, 1, 2)
        main_layout.addWidget(self.alerts_panel, 2, 4, 2, 2)
        
        # Set stretch factors for responsive layout
        main_layout.setRowStretch(0, 1)
        main_layout.setRowStretch(1, 1)
        main_layout.setRowStretch(2, 1)
        main_layout.setRowStretch(3, 1)
        
        main_layout.setColumnStretch(0, 2)
        main_layout.setColumnStretch(1, 2)
        main_layout.setColumnStretch(2, 1)
        main_layout.setColumnStretch(3, 1)
        main_layout.setColumnStretch(4, 2)
        main_layout.setColumnStretch(5, 2)
        
        central_widget.setLayout(main_layout)
    
    def _connect_signals(self) -> None:
        """Connect orchestrator signals to UI slots."""
        # Orchestrator signals
        self.orchestrator.new_event.connect(self._on_new_event)
        self.orchestrator.new_alert.connect(self._on_new_alert)
        self.orchestrator.capture_started.connect(self._on_capture_started)
        self.orchestrator.capture_stopped.connect(self._on_capture_stopped)
        self.orchestrator.status_changed.connect(self._on_status_changed)
        self.orchestrator.threat_level_changed.connect(self._on_threat_level_changed)
        self.orchestrator.whitelist_review_due.connect(self._on_whitelist_review_due)  # NEW
        
        # Action panel signals
        self.action_panel.start_clicked.connect(self._start_capture)
        self.action_panel.stop_clicked.connect(self._stop_capture)
        self.action_panel.clear_clicked.connect(self._clear_all)
        
        # Alerts panel whitelist signal (NEW)
        self.alerts_panel.whitelist_requested.connect(self._handle_whitelist_request)

    def _on_whitelist_review_due(self):
        """Handle whitelist review reminder."""
        dialog = WhitelistReviewDialog(self)
        result = dialog.exec()
        
        if result == QDialog.DialogCode.Accepted:
            # Open settings to whitelist tab
            self._open_whitelist_settings()
    
    def _open_whitelist_settings(self):
        """Open settings dialog directly to whitelist tab."""
        # This will be implemented when we create the whitelist panel
        self.orchestrator.open_settings()
    
    def _handle_whitelist_request(self, alert: Dict[str, Any]):
        """
        Handle request to add alert to whitelist.
        
        Args:
            alert: Alert dictionary
        """
        from ui.widgets.whitelist_dialog import WhitelistDialog
        
        dialog = WhitelistDialog(alert, self)
        result = dialog.exec()
        
        if result == QDialog.DialogCode.Accepted and dialog.whitelist_data:
            success = self.orchestrator.add_to_whitelist(dialog.whitelist_data)
            
            if success:
                msg = QMessageBox(self)
                msg.setWindowTitle("Success")
                msg.setText("Entry added to whitelist successfully!")
                msg.setIcon(QMessageBox.Icon.Information)

                msg.setStyleSheet("""
                    QMessageBox { background-color: #2a2a2a; }
                    QMessageBox QLabel { color: white; }
                    QPushButton { background-color: #444; color: white; }
                """)

                msg.exec()

    
    @pyqtSlot(dict)
    def _on_new_event(self, event: dict) -> None:
        """Handle new network event."""
        self.connections_panel.add_event(event)
        self.protocols_panel.add_event(event)
        self.logs_panel.add_log_entry(f"Event: {event.get('protocol', 'UNKNOWN')} "
                                      f"{event.get('src_ip', '')} -> {event.get('dst_ip', '')}")
    
    @pyqtSlot(dict)
    def _on_new_alert(self, alert: dict) -> None:
        """Handle new alert."""
        self.alerts_panel.add_alert(alert)
        
        # Log with different color for whitelisted alerts
        alert_text = f"ALERT: {alert.get('term', '')} - {alert.get('explanation', '')}"
        
        if alert.get('filtered', False):
            # Green for whitelisted/filtered alerts
            self.logs_panel.add_log_entry(f"🛡️ WHITELISTED: {alert_text}", level="info")
        else:
            # Orange/warning for real alerts
            self.logs_panel.add_log_entry(alert_text, level="warning")
    @pyqtSlot()
    def _on_capture_started(self) -> None:
        """Handle capture started event."""
        self.helper_panel.set_status("Capturing...")
        self.action_panel.set_capture_state(True)
        self.logs_panel.add_log_entry("Capture started", level="info")
    
    @pyqtSlot()
    def _on_capture_stopped(self) -> None:
        """Handle capture stopped event."""
        self.helper_panel.set_status("Stopped")
        self.action_panel.set_capture_state(False)
        self.logs_panel.add_log_entry("Capture stopped", level="info")
    
    @pyqtSlot(str)
    def _on_status_changed(self, status: str) -> None:
        """Handle status change."""
        self.helper_panel.set_status(status)
    
    @pyqtSlot(int)
    def _on_threat_level_changed(self, level: int) -> None:
        """Handle threat level change."""
        self.ring_indicator.set_value(level)
    
    def _start_capture(self) -> None:
        """Start network capture."""
        # Show settings reminder on first capture start
        if not self.has_started_capture and self.orchestrator.config.get('ui.show_settings_reminder', True):
            dialog = SettingsReminderDialog(self)
            result = dialog.exec()
            
            # Save preference if user checked "don't show again"
            if dialog.dont_show_again:
                self.orchestrator.config.set('ui.show_settings_reminder', False)
            
            # If user chose to open settings
            if result == 2:
                self._open_settings()
                return  # Don't start capture yet
        
        self.has_started_capture = True
        
        success = self.orchestrator.start_capture("auto")
        if not success:
            QMessageBox.critical(self, "Error", "Failed to start capture. Check logs for details.")
    
    def _stop_capture(self) -> None:
        """Stop network capture."""
        self.orchestrator.stop_capture()
    
    def _export_pcap(self) -> None:
        """Export capture to PCAP file."""
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export PCAP",
            "",
            "PCAP Files (*.pcap);;All Files (*)"
        )
        
        if filepath:
            success = self.orchestrator.export_pcap(filepath)
            
            # Create message box with dark theme styling
            msg = QMessageBox(self)
            
            if success:
                msg.setWindowTitle("Success")
                msg.setText(f"PCAP exported successfully to:\n{filepath}")
                msg.setIcon(QMessageBox.Icon.Information)
            else:
                msg.setWindowTitle("Export Failed")
                msg.setText(f"Failed to export PCAP to:\n{filepath}\n\nCheck logs for details.")
                msg.setIcon(QMessageBox.Icon.Critical)
            
            # Apply dark theme styling
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #1a1a1a;
                }
                QMessageBox QLabel {
                    color: white;
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
            
            msg.exec()
    
    def _open_settings(self) -> None:
        """Open settings dialog."""
        self.orchestrator.open_settings()
        # Update API status after settings might have changed
        self.helper_panel.set_api_status(self.orchestrator.has_api_keys())
    
    def _clear_all(self) -> None:
        """Clear all panels."""
        self.connections_panel.clear()
        self.protocols_panel.clear()
        self.logs_panel.clear()
        self.alerts_panel.clear()
        self.ring_indicator.set_value(0)
    
    def _show_things_to_know(self) -> None:
        """Show 'Things You Should Know' information dialog."""
        
        import os
        project_root = Path(__file__).parent.parent
        config_path = str(project_root / "configs")
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Things You Should Know")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(
            "<h2 style='color: white;'>NetObserver - Important Information</h2>"
            "<div style='color: white; line-height: 1.6;'>"
            "<h3 style='color: #00ff00;'>📁 Data Storage Location</h3>"
            f"<p>All logs, configuration, and API keys are stored in:<br>"
            f"<code style='background-color: #2a2a2a; padding: 5px; color: #00ff00;'>{config_path}</code></p>"
            "<p><b>Location:</b> Inside the NetObserver application folder → configs subfolder</p>"
            # ... rest of the message stays the same ...
            "<ul>"
            "<li><b>config.json</b> - Your application settings and detection rules</li>"
            "<li><b>keys.json</b> - API keys (stored with file permissions 0600)</li>"
            "<li><b>netgui.db</b> - SQLite database with captured events and alerts</li>"
            "<li><b>logs/</b> - Application log files</li>"
            "</ul>"
            "<h3 style='color: #ffaa00;'>⚙️ Optimize Performance</h3>"
            "<p><b>It's highly recommended to customize your detection rules!</b></p>"
            "<p>Go to <b>Settings → Preferences → Detection Rules</b> to:</p>"
            "<ul>"
            "<li>Enable/disable rules based on your environment</li>"
            "<li>Adjust thresholds to reduce false positives</li>"
            "<li>Configure time windows and sensitivity</li>"
            "</ul>"
            "<p>Default settings work for general use, but tuning them to your specific "
            "network will provide much better threat detection and fewer false alarms.</p>"
            "<h3 style='color: #ff6b6b;'>⚠️ Security Reminders</h3>"
            "<ul>"
            "<li>API keys are stored in <b>plaintext</b> (protected by file permissions)</li>"
            "<li>Use only on <b>authorized networks</b> you own or have permission to monitor</li>"
            "<li>This tool is for <b>defensive use only</b> - incident response and threat hunting</li>"
            "<li>Live capture may require <b>root/administrator privileges</b></li>"
            "</ul>"
            "</div>"
        )
        
        # Apply dark theme styling
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
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
    
    def _show_about(self) -> None:
        """Show about dialog with styled text."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("About NetObserver")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(
            "<h2 style='color: white;'>NetObserver - Defensive Network Visibility</h2>"
            "<p style='color: white;'>Version 1.0</p>"
            "<p style='color: white;'>A PyQt6-based network monitoring and incident response tool.</p>"
            "<p style='color: #ff6666;'><b>⚠️ For authorized defensive use only</b></p>"
            "<p style='color: white;'>This tool is designed for incident response, threat hunting, "
            "and forensic analysis on authorized networks.</p>"
        )
        
        # Apply dark theme styling
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
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