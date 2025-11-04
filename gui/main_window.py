"""
Main window for LeAmitVPN GUI
"""

import sys
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QFrame, QStatusBar, QMessageBox,
    QProgressBar, QGroupBox, QGridLayout, QScrollArea, QSystemTrayIcon, QMenu
)
from PySide6.QtCore import Qt, QTimer, Signal, QThread
from PySide6.QtGui import QFont, QPixmap, QIcon, QAction
from typing import Optional

from .server_grid import ServerGrid
from .settings_panel import SettingsPanel
from vpn_core.logger import get_logger
from pathlib import Path
import json


class ConnectionMonitor(QThread):
    """Thread for monitoring connection status"""
    status_updated = Signal(dict)
    
    def __init__(self, vpn_handler):
        super().__init__()
        self.vpn_handler = vpn_handler
        self.running = True
    
    def run(self):
        """Monitor connection status"""
        while self.running:
            try:
                status = self.vpn_handler.get_connection_status()
                self.status_updated.emit(status)
                self.msleep(2000)  # Update every 2 seconds
            except Exception as e:
                print(f"Connection monitor error: {e}")
                self.msleep(5000)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, vpn_handler):
        super().__init__()
        self.vpn_handler = vpn_handler
        self.logger = get_logger(__name__)
        self.selected_server = None
        
        # Initialize UI
        self.init_ui()
        self.setup_connections()
        
        # Start connection monitoring
        self.connection_monitor = ConnectionMonitor(vpn_handler)
        self.connection_monitor.status_updated.connect(self.update_connection_status)
        self.connection_monitor.start()
        
        # Load servers
        self.load_servers()

        # Apply saved theme if present
        self.apply_saved_theme()
        # Load preferences
        self.settings = self.load_settings()
        # Apply saved language
        self.apply_language(self.settings.get("language", "English"))
        # Start minimized if requested
        if self.settings.get("start_minimized", False):
            self.hide()
        # Apply saved language
        self.apply_saved_language()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("OnamVPN - Local VPN Client")
        self.setMinimumSize(800, 600)
        self.resize(1000, 700)
        
        # Set application icon (if available)
        self.setWindowIcon(QIcon())
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        self.create_header(main_layout)
        
        # Connection status panel
        self.create_status_panel(main_layout)
        
        # Server selection
        self.create_server_selection(main_layout)
        
        # Control buttons
        self.create_control_buttons(main_layout)
        
        # Status bar
        self.create_status_bar()
        
        # Apply styles
        self.apply_styles()
    
    def create_header(self, parent_layout):
        """Create header section"""
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        # Title
        self.title_label = QLabel("OnamVPN")
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        self.title_label.setStyleSheet("color: #2c3e50; margin: 10px;")
        
        # Subtitle
        self.subtitle_label = QLabel("Local VPN with GUI - Secure & Fast")
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        self.subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 10px;")
        
        header_layout.addWidget(self.title_label)
        header_layout.addWidget(self.subtitle_label)
        
        parent_layout.addWidget(header_frame)
    
    def create_status_panel(self, parent_layout):
        """Create connection status panel"""
        status_group = QGroupBox("Connection Status")
        status_layout = QGridLayout(status_group)
        
        # Status indicator
        self.status_label = QLabel("Disconnected")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                background-color: #e74c3c;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
        """)
        
        # Connection info
        self.connection_info = QLabel("Ready to connect")
        self.connection_info.setAlignment(Qt.AlignCenter)
        self.connection_info.setStyleSheet("color: #7f8c8d;")
        
        # Progress bar for connection
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        status_layout.addWidget(self.status_label, 0, 0)
        status_layout.addWidget(self.connection_info, 1, 0)
        status_layout.addWidget(self.progress_bar, 2, 0)
        
        parent_layout.addWidget(status_group)
        # keep reference for language updates
        self.status_group = status_group
    
    def create_server_selection(self, parent_layout):
        """Create server selection section"""
        self.server_group = QGroupBox("Select Server")
        server_layout = QVBoxLayout(self.server_group)
        
        # Server grid
        self.server_grid = ServerGrid()
        self.server_grid.server_selected.connect(self.on_server_selected)
        
        # Scroll area for servers
        scroll_area = QScrollArea()
        scroll_area.setWidget(self.server_grid)
        scroll_area.setWidgetResizable(True)
        scroll_area.setMaximumHeight(300)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        server_layout.addWidget(scroll_area)
        parent_layout.addWidget(self.server_group)
    
    def create_control_buttons(self, parent_layout):
        """Create control buttons"""
        button_layout = QHBoxLayout()
        
        # Connect button
        self.connect_button = QPushButton("Connect")
        self.connect_button.setEnabled(False)
        self.connect_button.setMinimumHeight(50)
        self.connect_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        
        # Disconnect button
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.setMinimumHeight(50)
        self.disconnect_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        
        # Settings button
        self.settings_button = QPushButton("Settings")
        self.settings_button.setMinimumHeight(50)
        self.settings_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        
        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.disconnect_button)
        button_layout.addWidget(self.settings_button)
        
        parent_layout.addLayout(button_layout)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status messages
        self.status_bar.showMessage("Ready")
        
        # WireGuard status
        self.wg_status_label = QLabel("WireGuard: Checking...")
        self.status_bar.addPermanentWidget(self.wg_status_label)
        # Setup tray after status bar exists
        self.setup_tray()

    def setup_tray(self):
        """Setup system tray icon and basic menu"""
        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setIcon(self.windowIcon())
            menu = QMenu(self)
            show_action = QAction("Show", self)
            quit_action = QAction("Quit", self)
            show_action.triggered.connect(self.showNormal)
            quit_action.triggered.connect(self.close)
            menu.addAction(show_action)
            menu.addAction(quit_action)
            self.tray_icon.setContextMenu(menu)
            self.tray_icon.show()
        except Exception:
            pass
    
    def apply_styles(self):
        """Apply default (light) application styles"""
        self.setStyleSheet(self.light_stylesheet())

    def light_stylesheet(self) -> str:
        return (
            """
            QMainWindow { background-color: #ecf0f1; }
            QGroupBox { font-weight: bold; border: 2px solid #bdc3c7; border-radius: 5px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }
            QLabel { color: #2c3e50; }
        """
        )

    def dark_stylesheet(self) -> str:
        return (
            """
            QMainWindow { background-color: #1e1f22; }
            QGroupBox { font-weight: bold; border: 2px solid #3a3d41; border-radius: 5px; margin-top: 10px; padding-top: 10px; color: #e0e0e0; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px 0 5px; }
            QLabel { color: #e0e0e0; }
            QPushButton { background-color: #2d2f34; color: #e0e0e0; border: 1px solid #3a3d41; border-radius: 5px; }
            QPushButton:hover { background-color: #36383d; }
            QStatusBar { color: #e0e0e0; }
            QScrollArea { background-color: #1e1f22; }
        """
        )

    def apply_saved_theme(self):
        """Read config/settings.json and apply theme if Dark selected"""
        try:
            settings_file = Path("config") / "settings.json"
            if settings_file.exists():
                with open(settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                theme = (settings or {}).get("theme", "Light")
                self.apply_theme(theme)
        except Exception as e:
            self.logger.warning(f"Failed to apply saved theme: {e}")

    def apply_theme(self, theme: str):
        """Switch between Light/Dark stylesheets"""
        theme = (theme or "Light").lower()
        if theme == "dark":
            self.setStyleSheet(self.dark_stylesheet())
        else:
            self.setStyleSheet(self.light_stylesheet())

    def load_settings(self) -> dict:
        try:
            settings_file = Path("config") / "settings.json"
            if settings_file.exists():
                with open(settings_file, 'r', encoding='utf-8') as f:
                    return json.load(f) or {}
        except Exception:
            pass
        return {}

    # ---------------- Language support -----------------
    def apply_saved_language(self):
        """Apply language from settings.json if available"""
        try:
            settings_file = Path("config") / "settings.json"
            language = "English"
            if settings_file.exists():
                with open(settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    language = (settings or {}).get("language", "English")
            self.apply_language(language)
        except Exception as e:
            self.logger.warning(f"Failed to apply saved language: {e}")

    def apply_language(self, language: str):
        """Update key UI texts according to the selected language"""
        lang = (language or "English").lower()
        t = self._translations()
        tr = t.get(lang, t['english'])

        # Header
        self.title_label.setText(tr['app_title'])
        self.subtitle_label.setText(tr['app_subtitle'])

        # Group titles
        self.status_group.setTitle(tr['connection_status'])
        self.server_group.setTitle(tr['select_server'])

        # Buttons and status bar
        self.connect_button.setText(tr['connect'])
        self.disconnect_button.setText(tr['disconnect'])
        self.settings_button.setText(tr['settings'])
        self.status_bar.showMessage(tr['status_ready'])

    def _translations(self):
        return {
            'english': {
                'app_title': 'OnamVPN',
                'app_subtitle': 'Local VPN with GUI - Secure & Fast',
                'connection_status': 'Connection Status',
                'select_server': 'Select Server',
                'connect': 'Connect',
                'disconnect': 'Disconnect',
                'settings': 'Settings',
                'status_ready': 'Ready',
            },
            'spanish': {
                'app_title': 'OnamVPN',
                'app_subtitle': 'VPN local con GUI - Segura y Rápida',
                'connection_status': 'Estado de Conexión',
                'select_server': 'Seleccionar Servidor',
                'connect': 'Conectar',
                'disconnect': 'Desconectar',
                'settings': 'Ajustes',
                'status_ready': 'Listo',
            },
            'french': {
                'app_title': 'OnamVPN',
                'app_subtitle': 'VPN local avec interface graphique - Sécurisé et Rapide',
                'connection_status': 'État de Connexion',
                'select_server': 'Sélectionner un Serveur',
                'connect': 'Connexion',
                'disconnect': 'Déconnexion',
                'settings': 'Paramètres',
                'status_ready': 'Prêt',
            },
            'german': {
                'app_title': 'OnamVPN',
                'app_subtitle': 'Lokales VPN mit GUI – Sicher & Schnell',
                'connection_status': 'Verbindungsstatus',
                'select_server': 'Server auswählen',
                'connect': 'Verbinden',
                'disconnect': 'Trennen',
                'settings': 'Einstellungen',
                'status_ready': 'Bereit',
            },
        }
    
    def setup_connections(self):
        """Setup signal connections"""
        self.connect_button.clicked.connect(self.connect_to_server)
        self.disconnect_button.clicked.connect(self.disconnect_from_server)
        self.settings_button.clicked.connect(self.show_settings)
    
    def load_servers(self):
        """Load available servers"""
        try:
            servers = self.vpn_handler.get_available_servers()
            self.server_grid.load_servers(servers)
            self.logger.info(f"Loaded {len(servers)} servers")
        except Exception as e:
            self.logger.error(f"Failed to load servers: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load servers: {e}")

    def try_auto_connect(self):
        """Attempt auto-connect to last or default server"""
        try:
            # Prefer last_connected in servers.json
            servers_file = Path("config") / "servers.json"
            server_id = None
            if servers_file.exists():
                import json as _json
                with open(servers_file, 'r', encoding='utf-8') as f:
                    data = _json.load(f)
                server_id = data.get('last_connected') or data.get('default_server')
            if not server_id:
                return
            # Kick off connection silently
            self.selected_server = {'id': server_id, 'name': server_id, 'flag': ''}
            self.connect_to_server()
        except Exception as e:
            self.logger.warning(f"Auto-connect skipped: {e}")
    
    def on_server_selected(self, server):
        """Handle server selection"""
        self.selected_server = server
        self.connect_button.setEnabled(True)
        self.connection_info.setText(f"Selected: {server['name']} {server['flag']}")
        self.logger.info(f"Selected server: {server['name']}")
    
    def connect_to_server(self):
        """Connect to selected server"""
        if not self.selected_server:
            return
        
        try:
            self.logger.info(f"Connecting to {self.selected_server['name']}")
            
            # Update UI
            self.progress_bar.setVisible(True)
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(False)
            self.status_label.setText("Connecting...")
            self.status_label.setStyleSheet("""
                QLabel {
                    background-color: #f39c12;
                    color: white;
                    padding: 10px;
                    border-radius: 5px;
                    font-weight: bold;
                }
            """)
            self.connection_info.setText(f"Connecting to {self.selected_server['name']}...")
            
            # Start connection
            success = self.vpn_handler.connect_to_server(self.selected_server['id'])
            
            if success:
                self.status_bar.showMessage("Connection initiated")
                if getattr(self, 'settings', {}).get("show_notifications", True) and hasattr(self, 'tray_icon'):
                    self.tray_icon.showMessage("OnamVPN", f"Connecting to {self.selected_server['name']}", QSystemTrayIcon.Information, 3000)
            else:
                self.handle_connection_error("Failed to initiate connection")
                
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            self.handle_connection_error(str(e))
    
    def disconnect_from_server(self):
        """Disconnect from current server"""
        try:
            self.logger.info("Disconnecting from server")
            
            # Update UI
            self.progress_bar.setVisible(True)
            self.disconnect_button.setEnabled(False)
            self.status_label.setText("Disconnecting...")
            self.connection_info.setText("Disconnecting...")
            
            # Disconnect
            success = self.vpn_handler.disconnect()
            
            if success:
                self.status_bar.showMessage("Disconnected successfully")
                if getattr(self, 'settings', {}).get("show_notifications", True) and hasattr(self, 'tray_icon'):
                    self.tray_icon.showMessage("OnamVPN", "Disconnected", QSystemTrayIcon.Information, 3000)
            else:
                self.handle_disconnection_error("Failed to disconnect")
                
        except Exception as e:
            self.logger.error(f"Disconnection error: {e}")
            self.handle_disconnection_error(str(e))
    
    def update_connection_status(self, status):
        """Update connection status display"""
        try:
            if status['connected']:
                self.progress_bar.setVisible(False)
                self.connect_button.setEnabled(False)
                self.disconnect_button.setEnabled(True)
                self.status_label.setText("Connected")
                self.status_label.setStyleSheet("""
                    QLabel {
                        background-color: #27ae60;
                        color: white;
                        padding: 10px;
                        border-radius: 5px;
                        font-weight: bold;
                    }
                """)
                
                if status['server']:
                    server = status['server']
                    self.connection_info.setText(f"Connected to {server['name']} {server['flag']}")
                
                self.status_bar.showMessage("Connected to VPN")
                if getattr(self, 'settings', {}).get("show_notifications", True) and hasattr(self, 'tray_icon'):
                    self.tray_icon.showMessage("OnamVPN", "Connected", QSystemTrayIcon.Information, 3000)
                
            else:
                self.progress_bar.setVisible(False)
                self.connect_button.setEnabled(bool(self.selected_server))
                self.disconnect_button.setEnabled(False)
                self.status_label.setText("Disconnected")
                self.status_label.setStyleSheet("""
                    QLabel {
                        background-color: #e74c3c;
                        color: white;
                        padding: 10px;
                        border-radius: 5px;
                        font-weight: bold;
                    }
                """)
                
                if self.selected_server:
                    self.connection_info.setText(f"Ready to connect to {self.selected_server['name']}")
                else:
                    self.connection_info.setText("Select a server to connect")
                
                self.status_bar.showMessage("Disconnected")
                
        except Exception as e:
            self.logger.error(f"Status update error: {e}")
    
    def handle_connection_error(self, error_message):
        """Handle connection error"""
        self.progress_bar.setVisible(False)
        self.connect_button.setEnabled(bool(self.selected_server))
        self.status_label.setText("Connection Failed")
        self.status_label.setStyleSheet("""
            QLabel {
                background-color: #e74c3c;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
        """)
        self.connection_info.setText("Connection failed")
        self.status_bar.showMessage("Connection failed")
        
        QMessageBox.critical(self, "Connection Error", error_message)
    
    def handle_disconnection_error(self, error_message):
        """Handle disconnection error"""
        self.progress_bar.setVisible(False)
        self.disconnect_button.setEnabled(True)
        self.status_bar.showMessage("Disconnection failed")
        
        QMessageBox.critical(self, "Disconnection Error", error_message)
    
    def show_settings(self):
        """Show settings dialog"""
        try:
            settings_dialog = SettingsPanel(self)
            # Apply theme and language immediately when user saves
            settings_dialog.settings_changed.connect(lambda s: (self.apply_theme(s.get("theme", "Light")), self.apply_language(s.get("language", "English"))))
            settings_dialog.exec()
        except Exception as e:
            self.logger.error(f"Settings error: {e}")
            QMessageBox.critical(self, "Settings Error", f"Failed to open settings: {e}")
    
    def closeEvent(self, event):
        """Handle application close"""
        try:
            # Stop connection monitoring
            if hasattr(self, 'connection_monitor'):
                self.connection_monitor.stop()
                self.connection_monitor.wait()
            
            # Disconnect if connected
            if self.vpn_handler.is_connected:
                self.vpn_handler.disconnect()
            
            self.logger.info("Application closed")
            event.accept()
            
        except Exception as e:
            self.logger.error(f"Close error: {e}")
            event.accept()
