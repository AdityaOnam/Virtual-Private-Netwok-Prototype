"""
Settings panel for LeAmitVPN
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
    QWidget, QLabel, QPushButton, QCheckBox, QComboBox,
    QSpinBox, QGroupBox, QFormLayout, QLineEdit, QTextEdit,
    QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
import json
from pathlib import Path

from vpn_core.logger import get_logger


class SettingsPanel(QDialog):
    """Settings dialog for LeAmitVPN"""
    
    settings_changed = Signal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = get_logger(__name__)
        self.settings = {}
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize settings UI"""
        self.setWindowTitle("OnamVPN Settings")
        self.setModal(True)
        self.resize(600, 500)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # General settings tab
        general_tab = self.create_general_tab()
        tab_widget.addTab(general_tab, "General")
        
        # Network settings tab
        network_tab = self.create_network_tab()
        tab_widget.addTab(network_tab, "Network")
        
        # Advanced settings tab
        advanced_tab = self.create_advanced_tab()
        tab_widget.addTab(advanced_tab, "Advanced")
        
        # About tab
        about_tab = self.create_about_tab()
        tab_widget.addTab(about_tab, "About")
        
        main_layout.addWidget(tab_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_settings)
        self.save_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
        """)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        
        self.reset_button = QPushButton("Reset to Defaults")
        self.reset_button.clicked.connect(self.reset_settings)
        self.reset_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        
        button_layout.addWidget(self.reset_button)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.save_button)
        
        main_layout.addLayout(button_layout)
    
    def create_general_tab(self) -> QWidget:
        """Create general settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Appearance group
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QFormLayout(appearance_group)
        
        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "Auto"])
        appearance_layout.addRow("Theme:", self.theme_combo)
        
        # Language selection
        self.language_combo = QComboBox()
        self.language_combo.addItems(["English", "Spanish", "French", "German"])
        appearance_layout.addRow("Language:", self.language_combo)
        
        # Startup settings
        startup_group = QGroupBox("Startup")
        startup_layout = QVBoxLayout(startup_group)
        
        self.start_minimized_check = QCheckBox("Start minimized to system tray")
        self.auto_connect_check = QCheckBox("Auto-connect to last server")
        self.show_notifications_check = QCheckBox("Show connection notifications")
        
        startup_layout.addWidget(self.start_minimized_check)
        startup_layout.addWidget(self.auto_connect_check)
        startup_layout.addWidget(self.show_notifications_check)
        
        layout.addWidget(appearance_group)
        layout.addWidget(startup_group)
        layout.addStretch()
        
        return tab
    
    def create_network_tab(self) -> QWidget:
        """Create network settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # DNS settings
        dns_group = QGroupBox("DNS Settings")
        dns_layout = QFormLayout(dns_group)
        
        self.custom_dns_check = QCheckBox("Use custom DNS servers")
        self.primary_dns_edit = QLineEdit()
        self.primary_dns_edit.setPlaceholderText("8.8.8.8")
        self.secondary_dns_edit = QLineEdit()
        self.secondary_dns_edit.setPlaceholderText("1.1.1.1")
        
        dns_layout.addRow(self.custom_dns_check)
        dns_layout.addRow("Primary DNS:", self.primary_dns_edit)
        dns_layout.addRow("Secondary DNS:", self.secondary_dns_edit)
        
        # Connection settings
        connection_group = QGroupBox("Connection Settings")
        connection_layout = QFormLayout(connection_group)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" seconds")
        connection_layout.addRow("Connection timeout:", self.timeout_spin)
        
        self.keepalive_spin = QSpinBox()
        self.keepalive_spin.setRange(10, 300)
        self.keepalive_spin.setValue(25)
        self.keepalive_spin.setSuffix(" seconds")
        connection_layout.addRow("Keep-alive interval:", self.keepalive_spin)
        
        # Kill switch
        killswitch_group = QGroupBox("Security")
        killswitch_layout = QVBoxLayout(killswitch_group)
        
        self.killswitch_check = QCheckBox("Enable kill switch (block all traffic if VPN disconnects)")
        self.dns_leak_protection_check = QCheckBox("Enable DNS leak protection")
        
        killswitch_layout.addWidget(self.killswitch_check)
        killswitch_layout.addWidget(self.dns_leak_protection_check)
        
        layout.addWidget(dns_group)
        layout.addWidget(connection_group)
        layout.addWidget(killswitch_group)
        layout.addStretch()
        
        return tab
    
    def create_advanced_tab(self) -> QWidget:
        """Create advanced settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Logging settings
        logging_group = QGroupBox("Logging")
        logging_layout = QFormLayout(logging_group)
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        logging_layout.addRow("Log level:", self.log_level_combo)
        
        self.log_to_file_check = QCheckBox("Save logs to file")
        logging_layout.addRow(self.log_to_file_check)
        
        # Performance settings
        performance_group = QGroupBox("Performance")
        performance_layout = QFormLayout(performance_group)
        
        self.mtu_spin = QSpinBox()
        self.mtu_spin.setRange(1280, 1500)
        self.mtu_spin.setValue(1420)
        performance_layout.addRow("MTU size:", self.mtu_spin)
        
        self.thread_count_spin = QSpinBox()
        self.thread_count_spin.setRange(1, 8)
        self.thread_count_spin.setValue(2)
        performance_layout.addRow("Worker threads:", self.thread_count_spin)
        
        # Configuration files
        config_group = QGroupBox("Configuration Files")
        config_layout = QVBoxLayout(config_group)
        
        config_buttons_layout = QHBoxLayout()
        
        self.import_config_button = QPushButton("Import Configuration")
        self.import_config_button.clicked.connect(self.import_config)
        
        self.export_config_button = QPushButton("Export Configuration")
        self.export_config_button.clicked.connect(self.export_config)
        
        self.reset_config_button = QPushButton("Reset Configuration")
        self.reset_config_button.clicked.connect(self.reset_config)
        
        config_buttons_layout.addWidget(self.import_config_button)
        config_buttons_layout.addWidget(self.export_config_button)
        config_buttons_layout.addWidget(self.reset_config_button)
        
        config_layout.addLayout(config_buttons_layout)
        
        layout.addWidget(logging_group)
        layout.addWidget(performance_group)
        layout.addWidget(config_group)
        layout.addStretch()
        
        return tab
    
    def create_about_tab(self) -> QWidget:
        """Create about tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Application info
        info_group = QGroupBox("Application Information")
        info_layout = QVBoxLayout(info_group)
        
        app_info = QTextEdit()
        app_info.setReadOnly(True)
        app_info.setMaximumHeight(200)
        app_info.setPlainText("""
OnamVPN - Local VPN with GUI

Version: 1.0.0
Author: Addy
Based on: OnamVPN architecture

A modern VPN client with a beautiful GUI built on top of OnamVPN's core architecture, using WireGuard for secure tunneling.

Features:
• Modern PySide6 GUI with dark/light themes
• WireGuard integration for secure tunneling
• Server selection with real-time ping testing
• Local development and testing capabilities
• Cross-platform support

This is a prototype VPN implementation for educational purposes.
Use responsibly and in accordance with local laws and regulations.
        """)
        
        info_layout.addWidget(app_info)
        
        # System info
        system_group = QGroupBox("System Information")
        system_layout = QVBoxLayout(system_group)
        
        system_info = QTextEdit()
        system_info.setReadOnly(True)
        system_info.setMaximumHeight(150)
        
        import platform
        import sys
        system_text = f"""
Operating System: {platform.system()} {platform.release()}
Python Version: {sys.version}
Architecture: {platform.machine()}
        """
        
        system_info.setPlainText(system_text)
        system_layout.addWidget(system_info)
        
        layout.addWidget(info_group)
        layout.addWidget(system_group)
        layout.addStretch()
        
        return tab
    
    def load_settings(self):
        """Load settings from file"""
        try:
            settings_file = Path("config") / "settings.json"
            
            if settings_file.exists():
                with open(settings_file, 'r') as f:
                    self.settings = json.load(f)
            else:
                self.settings = self.get_default_settings()
            
            self.apply_settings_to_ui()
            self.logger.info("Settings loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load settings: {e}")
            self.settings = self.get_default_settings()
    
    def get_default_settings(self) -> dict:
        """Get default settings"""
        return {
            "theme": "Light",
            "language": "English",
            "start_minimized": False,
            "auto_connect": False,
            "show_notifications": True,
            "custom_dns": False,
            "primary_dns": "8.8.8.8",
            "secondary_dns": "1.1.1.1",
            "connection_timeout": 30,
            "keepalive_interval": 25,
            "killswitch": False,
            "dns_leak_protection": True,
            "log_level": "INFO",
            "log_to_file": True,
            "mtu_size": 1420,
            "thread_count": 2
        }
    
    def apply_settings_to_ui(self):
        """Apply loaded settings to UI elements"""
        # General settings
        self.theme_combo.setCurrentText(self.settings.get("theme", "Light"))
        self.language_combo.setCurrentText(self.settings.get("language", "English"))
        self.start_minimized_check.setChecked(self.settings.get("start_minimized", False))
        self.auto_connect_check.setChecked(self.settings.get("auto_connect", False))
        self.show_notifications_check.setChecked(self.settings.get("show_notifications", True))
        
        # Network settings
        self.custom_dns_check.setChecked(self.settings.get("custom_dns", False))
        self.primary_dns_edit.setText(self.settings.get("primary_dns", "8.8.8.8"))
        self.secondary_dns_edit.setText(self.settings.get("secondary_dns", "1.1.1.1"))
        self.timeout_spin.setValue(self.settings.get("connection_timeout", 30))
        self.keepalive_spin.setValue(self.settings.get("keepalive_interval", 25))
        self.killswitch_check.setChecked(self.settings.get("killswitch", False))
        self.dns_leak_protection_check.setChecked(self.settings.get("dns_leak_protection", True))
        
        # Advanced settings
        self.log_level_combo.setCurrentText(self.settings.get("log_level", "INFO"))
        self.log_to_file_check.setChecked(self.settings.get("log_to_file", True))
        self.mtu_spin.setValue(self.settings.get("mtu_size", 1420))
        self.thread_count_spin.setValue(self.settings.get("thread_count", 2))
    
    def save_settings(self):
        """Save settings to file"""
        try:
            # Collect settings from UI
            self.settings = {
                "theme": self.theme_combo.currentText(),
                "language": self.language_combo.currentText(),
                "start_minimized": self.start_minimized_check.isChecked(),
                "auto_connect": self.auto_connect_check.isChecked(),
                "show_notifications": self.show_notifications_check.isChecked(),
                "custom_dns": self.custom_dns_check.isChecked(),
                "primary_dns": self.primary_dns_edit.text(),
                "secondary_dns": self.secondary_dns_edit.text(),
                "connection_timeout": self.timeout_spin.value(),
                "keepalive_interval": self.keepalive_spin.value(),
                "killswitch": self.killswitch_check.isChecked(),
                "dns_leak_protection": self.dns_leak_protection_check.isChecked(),
                "log_level": self.log_level_combo.currentText(),
                "log_to_file": self.log_to_file_check.isChecked(),
                "mtu_size": self.mtu_spin.value(),
                "thread_count": self.thread_count_spin.value()
            }
            
            # Save to file
            settings_file = Path("config") / "settings.json"
            settings_file.parent.mkdir(exist_ok=True)
            
            with open(settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            
            self.logger.info("Settings saved successfully")
            self.settings_changed.emit(self.settings)
            
            QMessageBox.information(self, "Success", "Settings saved successfully!")
            self.accept()
            
        except Exception as e:
            self.logger.error(f"Failed to save settings: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(
            self, "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.settings = self.get_default_settings()
            self.apply_settings_to_ui()
            self.logger.info("Settings reset to defaults")
    
    def import_config(self):
        """Import configuration from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration", "", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    imported_settings = json.load(f)
                
                self.settings.update(imported_settings)
                self.apply_settings_to_ui()
                
                QMessageBox.information(self, "Success", "Configuration imported successfully!")
                
            except Exception as e:
                self.logger.error(f"Failed to import configuration: {e}")
                QMessageBox.critical(self, "Error", f"Failed to import configuration: {e}")
    
    def export_config(self):
        """Export configuration to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Configuration", "leamitvpn_config.json", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.settings, f, indent=2)
                
                QMessageBox.information(self, "Success", "Configuration exported successfully!")
                
            except Exception as e:
                self.logger.error(f"Failed to export configuration: {e}")
                QMessageBox.critical(self, "Error", f"Failed to export configuration: {e}")
    
    def reset_config(self):
        """Reset configuration files"""
        reply = QMessageBox.question(
            self, "Reset Configuration",
            "This will delete all configuration files and reset to defaults.\nAre you sure?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                config_dir = Path("config")
                if config_dir.exists():
                    import shutil
                    shutil.rmtree(config_dir)
                    config_dir.mkdir()
                
                QMessageBox.information(self, "Success", "Configuration reset successfully!")
                
            except Exception as e:
                self.logger.error(f"Failed to reset configuration: {e}")
                QMessageBox.critical(self, "Error", f"Failed to reset configuration: {e}")
