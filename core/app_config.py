"""
Application configuration management.
Handles settings, API keys, and user preferences.
"""

import json
import os
import stat
from pathlib import Path
from typing import Dict, Any, Optional
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QFormLayout, QLineEdit, 
                             QPushButton, QLabel, QMessageBox, QTabWidget,
                             QWidget, QCheckBox, QSpinBox, QGroupBox, QScrollArea,
                             QHBoxLayout)
from PyQt6.QtCore import Qt, pyqtSignal

from core.logger import get_logger

logger = get_logger(__name__)


class ToggleButton(QPushButton):
    """Custom toggle button that shows Enabled/Disabled state."""
    
    toggled = pyqtSignal(bool)  # Emits True when enabled, False when disabled
    
    def __init__(self, parent=None):
        """Initialize toggle button."""
        super().__init__(parent)
        self._is_enabled = False
        self.setCheckable(True)
        self.setFixedHeight(35)
        self.setMinimumWidth(120)
        self.clicked.connect(self._on_clicked)
        self._update_appearance()
    
    def _on_clicked(self):
        """Handle button click."""
        self._is_enabled = self.isChecked()
        self._update_appearance()
        self.toggled.emit(self._is_enabled)
    
    def _update_appearance(self):
        """Update button appearance based on state."""
        if self._is_enabled:
            self.setText("✓ Enabled")
            self.setStyleSheet("""
                QPushButton {
                    background-color: #00aa00;
                    color: white;
                    border: 2px solid #00ff00;
                    border-radius: 5px;
                    font-weight: bold;
                    font-size: 13px;
                    padding: 5px 15px;
                }
                QPushButton:hover {
                    background-color: #00cc00;
                }
                QPushButton:pressed {
                    background-color: #008800;
                }
            """)
        else:
            self.setText("✗ Disabled")
            self.setStyleSheet("""
                QPushButton {
                    background-color: #aa0000;
                    color: white;
                    border: 2px solid #ff0000;
                    border-radius: 5px;
                    font-weight: bold;
                    font-size: 13px;
                    padding: 5px 15px;
                }
                QPushButton:hover {
                    background-color: #cc0000;
                }
                QPushButton:pressed {
                    background-color: #880000;
                }
            """)
    
    def setEnabled(self, enabled: bool):
        """Set the enabled state."""
        self._is_enabled = enabled
        self.setChecked(enabled)
        self._update_appearance()
    
    def isEnabled(self) -> bool:
        """Get the enabled state."""
        return self._is_enabled


class SmallToggleButton(QPushButton):
    """Small toggle button for inline use."""
    
    toggled = pyqtSignal(bool)
    
    def __init__(self, parent=None):
        """Initialize small toggle button."""
        super().__init__(parent)
        self._is_enabled = False
        self.setCheckable(True)
        self.setFixedSize(80, 30)
        self.clicked.connect(self._on_clicked)
        self._update_appearance()
    
    def _on_clicked(self):
        """Handle button click."""
        self._is_enabled = self.isChecked()
        self._update_appearance()
        self.toggled.emit(self._is_enabled)
    
    def _update_appearance(self):
        """Update button appearance based on state."""
        if self._is_enabled:
            self.setText("ON")
            self.setStyleSheet("""
                QPushButton {
                    background-color: #00aa00;
                    color: white;
                    border: 2px solid #00ff00;
                    border-radius: 3px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #00cc00;
                }
            """)
        else:
            self.setText("OFF")
            self.setStyleSheet("""
                QPushButton {
                    background-color: #aa0000;
                    color: white;
                    border: 2px solid #ff0000;
                    border-radius: 3px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #cc0000;
                }
            """)
    
    def setEnabled(self, enabled: bool):
        """Set the enabled state."""
        self._is_enabled = enabled
        self.setChecked(enabled)
        self._update_appearance()
    
    def isEnabled(self) -> bool:
        """Get the enabled state."""
        return self._is_enabled


class AppConfig:
    """Manages application configuration and settings."""
    
    def __init__(self):
        """Initialize configuration manager."""
        # Change from home directory to local configs folder
        import os
        project_root = Path(__file__).parent.parent  # NetObserver root directory
        self.config_dir = project_root / "configs"
        self.config_file = self.config_dir / "config.json"
        self.keys_file = self.config_dir / "keys.json"
        
        self._ensure_config_dir()
        self.config = self._load_config()
        self.keys = self._load_keys()
    
    def _ensure_config_dir(self) -> None:
        """Create configuration directory if it doesn't exist."""
        try:
            self.config_dir.mkdir(mode=0o700, exist_ok=True)
            logger.info(f"Configuration directory: {self.config_dir}")
        except Exception as e:
            logger.error(f"Failed to create config directory: {e}")
            raise
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        default_config = {
            "capture": {
                "interface": "any",
                "buffer_size": 65536,
                "promiscuous": True,
                "timeout_ms": 100
            },
            "analytics": {
                "enable_heuristics": True,
                "alert_threshold": 3
            },
            "heuristics": {
                "port_scan": {
                    "enabled": True,
                    "threshold": 20,
                    "description": "Detect when a host scans multiple ports"
                },
                "dns_failures": {
                    "enabled": True,
                    "threshold": 5,
                    "description": "Detect repeated DNS resolution failures"
                },
                "dga_detection": {
                    "enabled": True,
                    "description": "Detect algorithmically-generated domains"
                },
                "outbound_spike": {
                    "enabled": True,
                    "threshold": 100,
                    "time_window": 300,
                    "description": "Detect unusual outbound connection spikes"
                },
                "failed_auth": {
                    "enabled": True,
                    "threshold": 10,
                    "description": "Detect brute force authentication attempts"
                },
                "suspicious_ports": {
                    "enabled": True,
                    "description": "Detect connections to known malware ports"
                },
                "large_transfers": {
                    "enabled": True,
                    "threshold": 104857600,
                    "description": "Detect large data transfers (bytes)"
                },
                "unusual_protocols": {
                    "enabled": False,
                    "description": "Detect use of insecure protocols (Telnet, FTP)"
                },
                "repeated_connections": {
                    "enabled": True,
                    "threshold": 50,
                    "description": "Detect repeated connections to same destination"
                },
                "time_anomalies": {
                    "enabled": False,
                    "threshold": 20,
                    "start_hour": 2,
                    "end_hour": 5,
                    "description": "Detect unusual activity during off-hours"
                }
            },
            "storage": {
                "max_events": 100000,
                "auto_export": False,
                "export_path": str(Path.home() / "NetObserver_exports")
            },
            "ui": {
                "refresh_rate_ms": 500,
                "max_alert_rows": 1000,  # Changed from 100 to 1000
                "show_settings_reminder": True
            }
        }
        
        if not self.config_file.exists():
            self._save_config(default_config)
            return default_config
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self._merge_defaults(config, default_config)
                logger.info("Configuration loaded successfully")
                return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return default_config
    
    def _merge_defaults(self, config: Dict[str, Any], defaults: Dict[str, Any]) -> None:
        """Merge default values for any missing keys."""
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
            elif isinstance(value, dict) and isinstance(config[key], dict):
                self._merge_defaults(config[key], value)
    
    def _load_keys(self) -> Dict[str, str]:
        """Load API keys from secure file."""
        if not self.keys_file.exists():
            return {}
        
        try:
            file_stat = os.stat(self.keys_file)
            if file_stat.st_mode & 0o077:
                logger.warning("Keys file has insecure permissions!")
            
            with open(self.keys_file, 'r') as f:
                keys = json.load(f)
                logger.info("API keys loaded")
                return keys
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            return {}
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info("Configuration saved")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def _save_keys(self, keys: Dict[str, str]) -> None:
        """Save API keys to secure file."""
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(keys, f, indent=2)
            
            os.chmod(self.keys_file, stat.S_IRUSR | stat.S_IWUSR)
            logger.info("API keys saved with secure permissions")
        except Exception as e:
            logger.error(f"Failed to save keys: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation."""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
        self._save_config(self.config)
    
    def get_key(self, key_name: str) -> Optional[str]:
        """Retrieve an API key."""
        return self.keys.get(key_name)
    
    def set_key(self, key_name: str, key_value: str) -> None:
        """Store an API key securely."""
        self.keys[key_name] = key_value
        self._save_keys(self.keys)
    
    def remove_key(self, key_name: str) -> None:
        """Remove an API key."""
        if key_name in self.keys:
            del self.keys[key_name]
            self._save_keys(self.keys)
            logger.info(f"API key '{key_name}' removed")
    
    def clear_all_keys(self) -> None:
        """Remove all API keys."""
        self.keys.clear()
        self._save_keys(self.keys)
        logger.info("All API keys cleared")


class SettingsDialog(QDialog):
    """Settings dialog for user configuration."""
    
    def __init__(self, config: AppConfig, whitelist_manager=None, parent=None):
        """Initialize settings dialog."""
        super().__init__(parent)
        self.config = config
        self.whitelist_manager = whitelist_manager  # NEW
        self.setWindowTitle("NetObserver Settings")
        self.setMinimumWidth(830)
        self.setMinimumHeight(500)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
                color: white;
            }
            QLabel {
                color: white;
            }
            QLineEdit, QSpinBox {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #444;
                padding: 5px;
            }
            QPushButton {
                background-color: #333;
                color: white;
                border: 1px solid white;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #444;
            }
            QCheckBox {
                color: white;
                spacing: 5px;
            }
            QGroupBox {
                color: white;
                border: 1px solid #444;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #1a1a1a;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: white;
            }
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
            QScrollArea {
                border: none;
                background-color: #1a1a1a;
            }
            QWidget {
                background-color: #1a1a1a;
                color: white;
            }
        """)
        
        self._setup_ui()
        self._load_values()
    
    def _setup_ui(self) -> None:
        """Setup the UI components."""
        layout = QVBoxLayout()
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Capture settings tab
        capture_tab = self._create_capture_tab()
        tabs.addTab(capture_tab, "Capture")
        
        # Heuristics settings tab
        heuristics_tab = self._create_heuristics_tab()
        tabs.addTab(heuristics_tab, "Detection Rules")
        
        # Analytics settings tab
        analytics_tab = self._create_analytics_tab()
        tabs.addTab(analytics_tab, "Analytics")
        
        # API Keys tab
        keys_tab = self._create_keys_tab()
        tabs.addTab(keys_tab, "API Keys")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_layout = QVBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self._save_settings)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

        # Add whitelist tab (NEW)
        # Note: We need to pass whitelist_manager from orchestrator
        # This will be done when opening settings
        if hasattr(self, 'whitelist_manager') and self.whitelist_manager:
            from ui.panels.whitelist_panel import WhitelistPanel
            whitelist_tab = WhitelistPanel(self.config, self.whitelist_manager)
            tabs.addTab(whitelist_tab, "Whitelist")
    
    def _create_capture_tab(self) -> QWidget:
        """Create capture settings tab."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        form = QFormLayout()
        
        # Interface
        self.interface_input = QLineEdit()
        form.addRow("Interface:", self.interface_input)
        
        # Buffer size
        self.buffer_size_input = QSpinBox()
        self.buffer_size_input.setRange(1024, 1048576)
        self.buffer_size_input.setSingleStep(1024)
        form.addRow("Buffer Size:", self.buffer_size_input)
        
        # Promiscuous mode with toggle button
        promiscuous_layout = QHBoxLayout()
        self.promiscuous_input = SmallToggleButton()
        promiscuous_layout.addWidget(self.promiscuous_input)
        promiscuous_layout.addStretch()
        form.addRow("Promiscuous Mode:", promiscuous_layout)
        
        # Hint for promiscuous mode
        promiscuous_hint = QLabel(
            "ℹ️ Promiscuous mode allows capturing all packets on the network segment, "
            "not just packets destined for this machine. If disabled, you'll only see "
            "traffic to/from this host. Requires elevated privileges (root/admin)."
        )
        promiscuous_hint.setWordWrap(True)
        promiscuous_hint.setStyleSheet("""
            color: #888;
            font-size: 12px;
            padding: 5px 10px;
            background-color: #0a0a0a;
            border-left: 3px solid #555;
            margin-top: 5px;
        """)
        form.addRow("", promiscuous_hint)
        
        layout.addLayout(form)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def _create_heuristics_tab(self) -> QWidget:
        """Create heuristics settings tab with scrollable area."""
        # [Keep the existing implementation from previous code]
        widget = QWidget()
        widget.setStyleSheet("background-color: #1a1a1a;")
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #1a1a1a;
            }
            QScrollBar:vertical {
                background-color: #1a1a1a;
                width: 12px;
                border: 1px solid #333;
            }
            QScrollBar::handle:vertical {
                background-color: #444;
                min-height: 20px;
                border-radius: 3px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666;
            }
        """)
        
        content = QWidget()
        content.setStyleSheet("QWidget { background-color: #1a1a1a; color: white; }")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        self.heuristic_inputs = {}
        
        # Create all heuristic groups
        for name, key, desc, has_thresh, label, min_v, max_v, mult, extra in [
            ("Port Scan Detection", "port_scan", "Detect when a host scans multiple ports", 
             True, "Unique Ports Threshold:", 5, 100, 1, None),
            ("DNS Failure Detection", "dns_failures", "Detect repeated DNS resolution failures (NXDOMAIN)", 
             True, "Failure Count Threshold:", 1, 50, 1, None),
            ("DGA Domain Detection", "dga_detection", "Detect algorithmically-generated domains (malware C&C)", 
             False, "", 0, 0, 1, None),
            ("Outbound Traffic Spike", "outbound_spike", "Detect unusual number of outbound connections", 
             True, "Connection Count:", 10, 1000, 1, [("Time Window (seconds):", "time_window", 60, 3600)]),
            ("Brute Force Detection", "failed_auth", "Detect repeated authentication failures (SSH/RDP)", 
             True, "Attempt Threshold:", 3, 100, 1, None),
            ("Suspicious Port Detection", "suspicious_ports", "Detect connections to known malware/backdoor ports", 
             False, "", 0, 0, 1, None),
            ("Large Data Transfer Detection", "large_transfers", "Detect potential data exfiltration", 
             True, "Size Threshold (MB):", 1, 10000, 1048576, None),
            ("Insecure Protocol Detection", "unusual_protocols", "Detect use of insecure protocols (Telnet, FTP, TFTP)", 
             False, "", 0, 0, 1, None),
            ("Repeated Connection Detection", "repeated_connections", "Detect beaconing behavior (malware C&C)", 
             True, "Connection Count:", 10, 500, 1, None),
            ("Off-Hours Activity Detection", "time_anomalies", "Detect unusual network activity during specified hours", 
             True, "Connection Threshold:", 5, 200, 1, [("Start Hour (0-23):", "start_hour", 0, 23), ("End Hour (0-23):", "end_hour", 0, 23)])
        ]:
            group = self._create_heuristic_group(name, key, desc, has_thresh, label, min_v, max_v, mult, extra)
            layout.addWidget(group)
        
        layout.addStretch()
        content.setLayout(layout)
        scroll.setWidget(content)
        
        main_layout.addWidget(scroll)
        widget.setLayout(main_layout)
        return widget
    
    def _create_heuristic_group(self, title: str, key: str, description: str,
                                has_threshold: bool = True, threshold_label: str = "Threshold:",
                                threshold_min: int = 1, threshold_max: int = 100,
                                threshold_multiplier: int = 1,
                                extra_fields: list = None) -> QGroupBox:
        """Create a group box for a heuristic setting with toggle button."""
        group = QGroupBox(title)
        group.setStyleSheet("""
            QGroupBox {
                background-color: #1a1a1a;
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
        
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        toggle_btn = ToggleButton()
        toggle_btn.setToolTip(description)
        layout.addWidget(toggle_btn)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: #aaa; font-size: 10px; padding-left: 5px; padding-top: 5px; background-color: transparent;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        self.heuristic_inputs[key] = {'enabled': toggle_btn}
        
        if has_threshold:
            form = QFormLayout()
            form.setContentsMargins(5, 10, 0, 0)
            
            threshold_spin = QSpinBox()
            threshold_spin.setRange(threshold_min, threshold_max)
            threshold_spin.setStyleSheet("QSpinBox { background-color: #2a2a2a; color: white; border: 1px solid #444; padding: 5px; }")
            
            threshold_label_widget = QLabel(threshold_label)
            threshold_label_widget.setStyleSheet("color: white; background-color: transparent;")
            
            form.addRow(threshold_label_widget, threshold_spin)
            layout.addLayout(form)
            self.heuristic_inputs[key]['threshold'] = threshold_spin
            self.heuristic_inputs[key]['threshold_multiplier'] = threshold_multiplier
        
        if extra_fields:
            form = QFormLayout()
            form.setContentsMargins(5, 5, 0, 0)
            
            for label, field_key, min_val, max_val in extra_fields:
                spin = QSpinBox()
                spin.setRange(min_val, max_val)
                spin.setStyleSheet("QSpinBox { background-color: #2a2a2a; color: white; border: 1px solid #444; padding: 5px; }")
                
                label_widget = QLabel(label)
                label_widget.setStyleSheet("color: white; background-color: transparent;")
                
                form.addRow(label_widget, spin)
                self.heuristic_inputs[key][field_key] = spin
            
            layout.addLayout(form)
        
        group.setLayout(layout)
        return group
    
    def _create_analytics_tab(self) -> QWidget:
        """Create analytics settings tab."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        form = QFormLayout()
        
        # Enable heuristics with toggle button
        heuristics_layout = QHBoxLayout()
        self.enable_heuristics_input = SmallToggleButton()
        heuristics_layout.addWidget(self.enable_heuristics_input)
        heuristics_layout.addStretch()
        form.addRow("Enable Heuristics:", heuristics_layout)
        
        # Hint for heuristics
        heuristics_hint = QLabel(
            "ℹ️ Heuristics enable automatic threat detection based on behavioral patterns. "
            "When enabled, the system analyzes network traffic for suspicious activity "
            "(port scans, brute force attempts, etc.). Disable if you only want to collect "
            "raw data without alerts."
        )
        heuristics_hint.setWordWrap(True)
        heuristics_hint.setStyleSheet("""
            color: #888;
            font-size: 12px;
            padding: 5px 10px;
            background-color: #0a0a0a;
            border-left: 3px solid #555;
            margin-top: 5px;
        """)
        form.addRow("", heuristics_hint)
        
        # Alert threshold
        self.alert_threshold_input = QSpinBox()
        self.alert_threshold_input.setRange(1, 100)
        form.addRow("Alert Threshold:", self.alert_threshold_input)
        
        layout.addLayout(form)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def _create_keys_tab(self) -> QWidget:
        """Create API keys tab."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        warning = QLabel(
            "⚠️ WARNING: API keys are stored in plaintext with file permissions 0600.\n"
            "Only store keys necessary for defensive analysis.\n"
            "Never store sensitive credentials here."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #ff6b6b; padding: 10px;")
        layout.addWidget(warning)
        
        form = QFormLayout()
        
        # VirusTotal API Key
        vt_layout = QHBoxLayout()
        self.virustotal_key_input = QLineEdit()
        self.virustotal_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        vt_layout.addWidget(self.virustotal_key_input)
        
        remove_vt_btn = QPushButton("Remove")
        remove_vt_btn.setFixedWidth(90)
        remove_vt_btn.setStyleSheet("""
            QPushButton {
                background-color: #aa3333;
                color: white;
                border: 1px solid #ff4444;
            }
            QPushButton:hover {
                background-color: #cc4444;
            }
        """)
        remove_vt_btn.clicked.connect(self._remove_virustotal_key)
        vt_layout.addWidget(remove_vt_btn)
        
        form.addRow("VirusTotal API Key:", vt_layout)
        
        layout.addLayout(form)
        
        # Remove all keys button
        remove_all_btn = QPushButton("Remove All API Keys")
        remove_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #aa0000;
                color: white;
                border: 2px solid #ff0000;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        remove_all_btn.clicked.connect(self._remove_all_keys)
        layout.addWidget(remove_all_btn)
        
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def _remove_virustotal_key(self):
        """Remove VirusTotal API key."""
        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            "Are you sure you want to remove the VirusTotal API key?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.virustotal_key_input.clear()
            self.config.remove_key('virustotal')
            QMessageBox.information(self, "Success", "VirusTotal API key removed.")
    
    def _remove_all_keys(self):
        """Remove all API keys."""
        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            "Are you sure you want to remove ALL API keys? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.virustotal_key_input.clear()
            self.config.clear_all_keys()
            QMessageBox.information(self, "Success", "All API keys removed.")
    
    def _load_values(self) -> None:
        """Load current configuration values."""
        # Capture settings
        self.interface_input.setText(self.config.get('capture.interface', 'any'))
        self.buffer_size_input.setValue(self.config.get('capture.buffer_size', 65536))
        self.promiscuous_input.setEnabled(self.config.get('capture.promiscuous', True))
        
        # Heuristics settings
        for key, widgets in self.heuristic_inputs.items():
            enabled = self.config.get(f'heuristics.{key}.enabled', True)
            widgets['enabled'].setEnabled(enabled)
            
            if 'threshold' in widgets:
                multiplier = widgets.get('threshold_multiplier', 1)
                threshold = self.config.get(f'heuristics.{key}.threshold', 10)
                display_value = threshold // multiplier if multiplier > 1 else threshold
                widgets['threshold'].setValue(display_value)
            
            # Load extra fields
            for field_key, widget in widgets.items():
                if field_key not in ['enabled', 'threshold', 'threshold_multiplier']:
                    value = self.config.get(f'heuristics.{key}.{field_key}', 0)
                    widget.setValue(value)
        
        # Analytics settings
        self.enable_heuristics_input.setEnabled(self.config.get('analytics.enable_heuristics', True))
        self.alert_threshold_input.setValue(self.config.get('analytics.alert_threshold', 3))
        
        # API Keys
        vt_key = self.config.get_key('virustotal')
        if vt_key:
            self.virustotal_key_input.setText(vt_key)
    
    def _save_settings(self) -> None:
        """Save all settings."""
        try:
            # Capture settings
            self.config.set('capture.interface', self.interface_input.text())
            self.config.set('capture.buffer_size', self.buffer_size_input.value())
            self.config.set('capture.promiscuous', self.promiscuous_input.isEnabled())
            
            # Heuristics settings
            for key, widgets in self.heuristic_inputs.items():
                self.config.set(f'heuristics.{key}.enabled', widgets['enabled'].isEnabled())
                
                if 'threshold' in widgets:
                    multiplier = widgets.get('threshold_multiplier', 1)
                    display_value = widgets['threshold'].value()
                    stored_value = display_value * multiplier
                    self.config.set(f'heuristics.{key}.threshold', stored_value)
                
                # Save extra fields
                for field_key, widget in widgets.items():
                    if field_key not in ['enabled', 'threshold', 'threshold_multiplier']:
                        self.config.set(f'heuristics.{key}.{field_key}', widget.value())
            
            # Analytics settings
            self.config.set('analytics.enable_heuristics', self.enable_heuristics_input.isEnabled())
            self.config.set('analytics.alert_threshold', self.alert_threshold_input.value())
            
            # API Keys
            vt_key = self.virustotal_key_input.text()
            if vt_key:
                self.config.set_key('virustotal', vt_key)
            
            # Save whitelist settings (NEW)
            if hasattr(self, 'whitelist_manager') and self.whitelist_manager:
                # Find whitelist panel and save its settings
                for i in range(self.findChild(QTabWidget).count()):
                    widget = self.findChild(QTabWidget).widget(i)
                    if hasattr(widget, 'save_settings'):
                        widget.save_settings()

            QMessageBox.information(self, "Success", "Settings saved successfully!")
            self.accept()
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")