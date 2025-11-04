"""
Server selection grid component
"""

from PySide6.QtWidgets import (
    QWidget, QGridLayout, QPushButton, QLabel, 
    QFrame, QVBoxLayout, QHBoxLayout
)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QFont
from typing import List, Dict, Optional
import threading
import time

from vpn_core.logger import get_logger


class PingTestThread(QThread):
    """Thread for testing server ping"""
    ping_result = Signal(str, int)  # server_id, ping_time
    
    def __init__(self, servers):
        super().__init__()
        self.servers = servers
        self.running = True
    
    def run(self):
        """Test ping for all servers"""
        import subprocess
        import socket
        
        for server in self.servers:
            if not self.running:
                break
                
            try:
                # Extract host and port from endpoint
                endpoint = server['endpoint']
                if ':' in endpoint:
                    host, port = endpoint.split(':')
                else:
                    host = endpoint
                    port = 51820
                
                # Test ping (simplified - just test if port is open)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                
                start_time = time.time()
                result = sock.connect_ex((host, int(port)))
                end_time = time.time()
                
                sock.close()
                
                if result == 0:
                    ping_time = int((end_time - start_time) * 1000)
                else:
                    ping_time = -1  # Connection failed
                
                self.ping_result.emit(server['id'], ping_time)
                
            except Exception:
                self.ping_result.emit(server['id'], -1)
            
            time.sleep(0.5)  # Small delay between tests
    
    def stop(self):
        """Stop ping testing"""
        self.running = False


class ServerCard(QFrame):
    """Individual server card widget"""
    
    server_selected = Signal(dict)
    
    def __init__(self, server: Dict):
        super().__init__()
        self.server = server
        self.is_selected = False
        self.ping_time = -1
        
        self.init_ui()
        self.apply_styles()
    
    def init_ui(self):
        """Initialize server card UI"""
        self.setFrameStyle(QFrame.StyledPanel)
        self.setMinimumHeight(120)
        self.setMaximumWidth(200)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # Flag and country
        flag_layout = QHBoxLayout()
        self.flag_label = QLabel(self.server['flag'])
        self.flag_label.setFont(QFont("Arial", 16))
        
        self.country_label = QLabel(self.server['country'])
        country_font = QFont()
        country_font.setBold(True)
        country_font.setPointSize(10)
        self.country_label.setFont(country_font)
        
        flag_layout.addWidget(self.flag_label)
        flag_layout.addWidget(self.country_label)
        flag_layout.addStretch()
        
        # Server name
        self.name_label = QLabel(self.server['name'])
        name_font = QFont()
        name_font.setPointSize(12)
        name_font.setBold(True)
        self.name_label.setFont(name_font)
        
        # Ping indicator
        self.ping_label = QLabel("Testing...")
        self.ping_label.setFont(QFont("Arial", 9))
        
        # Description (if available)
        if 'description' in self.server:
            self.desc_label = QLabel(self.server['description'])
            self.desc_label.setFont(QFont("Arial", 8))
            self.desc_label.setWordWrap(True)
            self.desc_label.setStyleSheet("color: #7f8c8d;")
        else:
            self.desc_label = None
        
        # Add widgets to layout
        layout.addLayout(flag_layout)
        layout.addWidget(self.name_label)
        layout.addWidget(self.ping_label)
        if self.desc_label:
            layout.addWidget(self.desc_label)
        layout.addStretch()
        
        # Make clickable
        self.setCursor(Qt.PointingHandCursor)
    
    def apply_styles(self):
        """Apply card styles"""
        self.update_style()
    
    def update_style(self):
        """Update card style based on selection state"""
        if self.is_selected:
            style = """
                QFrame {
                    background-color: #3498db;
                    border: 2px solid #2980b9;
                    border-radius: 8px;
                }
                QLabel {
                    color: white;
                }
            """
        else:
            style = """
                QFrame {
                    background-color: white;
                    border: 1px solid #bdc3c7;
                    border-radius: 8px;
                }
                QFrame:hover {
                    border: 2px solid #3498db;
                    background-color: #f8f9fa;
                }
                QLabel {
                    color: #2c3e50;
                }
            """
        
        self.setStyleSheet(style)
    
    def mousePressEvent(self, event):
        """Handle mouse click"""
        if event.button() == Qt.LeftButton:
            self.select_server()
    
    def select_server(self):
        """Select this server"""
        self.is_selected = True
        self.update_style()
        self.server_selected.emit(self.server)
    
    def deselect(self):
        """Deselect this server"""
        self.is_selected = False
        self.update_style()
    
    def update_ping(self, ping_time: int):
        """Update ping time display"""
        self.ping_time = ping_time
        
        if ping_time == -1:
            self.ping_label.setText("❌ Offline")
            self.ping_label.setStyleSheet("color: #e74c3c;")
        elif ping_time < 50:
            self.ping_label.setText(f"🟢 {ping_time}ms")
            self.ping_label.setStyleSheet("color: #27ae60;")
        elif ping_time < 100:
            self.ping_label.setText(f"🟡 {ping_time}ms")
            self.ping_label.setStyleSheet("color: #f39c12;")
        else:
            self.ping_label.setText(f"🔴 {ping_time}ms")
            self.ping_label.setStyleSheet("color: #e74c3c;")


class ServerGrid(QWidget):
    """Grid of server cards"""
    
    server_selected = Signal(dict)
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.servers = []
        self.server_cards = {}
        self.selected_card = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize server grid UI"""
        self.layout = QGridLayout(self)
        self.layout.setSpacing(15)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Placeholder message
        self.placeholder = QLabel("Loading servers...")
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setStyleSheet("""
            QLabel {
                color: #7f8c8d;
                font-size: 14px;
                padding: 20px;
            }
        """)
        self.layout.addWidget(self.placeholder)
    
    def load_servers(self, servers: List[Dict]):
        """Load servers into the grid"""
        self.servers = servers
        self.server_cards.clear()
        
        # Clear existing widgets
        for i in reversed(range(self.layout.count())):
            self.layout.itemAt(i).widget().setParent(None)
        
        if not servers:
            self.show_no_servers_message()
            return
        
        # Create server cards
        self.create_server_cards()
        
        # Start ping testing
        self.start_ping_testing()
    
    def create_server_cards(self):
        """Create server card widgets"""
        cards_per_row = 3
        row = 0
        col = 0
        
        for server in self.servers:
            card = ServerCard(server)
            card.server_selected.connect(self.on_server_selected)
            
            self.server_cards[server['id']] = card
            self.layout.addWidget(card, row, col)
            
            col += 1
            if col >= cards_per_row:
                col = 0
                row += 1
        
        self.logger.info(f"Created {len(self.servers)} server cards")
    
    def show_no_servers_message(self):
        """Show message when no servers are available"""
        self.placeholder.setText("No servers available.\nPlease check your configuration.")
        self.layout.addWidget(self.placeholder)
    
    def on_server_selected(self, server: Dict):
        """Handle server selection"""
        # Deselect previously selected card
        if self.selected_card:
            self.selected_card.deselect()
        
        # Select new card
        self.selected_card = self.server_cards.get(server['id'])
        if self.selected_card:
            self.selected_card.select_server()
        
        # Emit signal
        self.server_selected.emit(server)
        self.logger.info(f"Selected server: {server['name']}")
    
    def start_ping_testing(self):
        """Start ping testing for all servers"""
        if not self.servers:
            return
        
        self.ping_thread = PingTestThread(self.servers)
        self.ping_thread.ping_result.connect(self.update_server_ping)
        self.ping_thread.start()
        
        self.logger.info("Started ping testing for all servers")
    
    def update_server_ping(self, server_id: str, ping_time: int):
        """Update ping time for a server"""
        card = self.server_cards.get(server_id)
        if card:
            card.update_ping(ping_time)
    
    def get_selected_server(self) -> Optional[Dict]:
        """Get currently selected server"""
        if self.selected_card:
            return self.selected_card.server
        return None
    
    def refresh_servers(self):
        """Refresh server list and ping times"""
        if hasattr(self, 'ping_thread') and self.ping_thread.isRunning():
            self.ping_thread.stop()
            self.ping_thread.wait()
        
        self.start_ping_testing()
        self.logger.info("Refreshed server list")
