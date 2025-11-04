"""
Simple VPN handler for testing without WireGuard
This simulates VPN functionality for demonstration purposes
"""

import json
import time
import threading
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .logger import get_logger


class SimpleVPNHandler:
    """Simple VPN handler that simulates VPN functionality"""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize simple VPN handler
        
        Args:
            config_dir (str): Directory containing config files
        """
        self.config_dir = Path(config_dir)
        self.logger = get_logger(__name__)
        self.is_connected = False
        self.current_server = None
        self.connection_thread = None
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Load server configurations
        self.servers = self._load_servers()
        
    def _load_servers(self) -> List[Dict]:
        """Load server configurations from JSON file"""
        servers_file = self.config_dir / "servers.json"
        
        if not servers_file.exists():
            self.logger.warning("Servers.json not found, creating default configuration")
            self._create_default_servers()
            
        try:
            with open(servers_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('servers', [])
        except Exception as e:
            self.logger.error(f"Failed to load servers: {e}")
            return []
    
    def _create_default_servers(self):
        """Create default server configuration"""
        default_servers = {
            "servers": [
                {
                    "id": "local-server",
                    "name": "Local Server",
                    "country": "Local",
                    "flag": "HOME",
                    "endpoint": "127.0.0.1:51820",
                    "public_key": "DEMO_KEY_FOR_TESTING",
                    "description": "Local development server for testing"
                }
            ]
        }
        
        servers_file = self.config_dir / "servers.json"
        with open(servers_file, 'w', encoding='utf-8') as f:
            json.dump(default_servers, f, indent=2)
        
        self.logger.info("Created default server configuration")
    
    def get_available_servers(self) -> List[Dict]:
        """Get list of available servers"""
        return self.servers
    
    def test_wireguard_installation(self) -> bool:
        """Test if WireGuard is properly installed (always returns False for demo)"""
        return False  # Always return False to use simple mode
    
    def generate_keys(self) -> Tuple[str, str]:
        """Generate demo keys"""
        private_key = "DEMO_PRIVATE_KEY_" + str(int(time.time()))
        public_key = "DEMO_PUBLIC_KEY_" + str(int(time.time()))
        return private_key, public_key
    
    def connect_to_server(self, server_id: str) -> bool:
        """
        Simulate connection to a VPN server
        
        Args:
            server_id (str): ID of the server to connect to
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        if self.is_connected:
            self.logger.warning("Already connected to a server")
            return False
        
        # Find server configuration
        server = None
        for s in self.servers:
            if s['id'] == server_id:
                server = s
                break
        
        if not server:
            self.logger.error(f"Server {server_id} not found")
            return False
        
        try:
            self.logger.info(f"Simulating connection to {server['name']}...")
            
            # Start connection in separate thread
            self.connection_thread = threading.Thread(
                target=self._simulate_connection,
                args=(server,)
            )
            self.connection_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to server {server_id}: {e}")
            return False
    
    def _simulate_connection(self, server: Dict):
        """Simulate VPN connection"""
        try:
            self.logger.info(f"Connecting to {server['name']}...")
            time.sleep(2)  # Simulate connection time
            
            self.is_connected = True
            self.current_server = server
            self.logger.info(f"Successfully connected to {server['name']} (DEMO MODE)")
            
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
    
    def disconnect(self) -> bool:
        """Simulate disconnection from current VPN server"""
        if not self.is_connected:
            self.logger.warning("Not connected to any server")
            return False
        
        try:
            if self.current_server:
                server_name = self.current_server['name']
                self.is_connected = False
                self.current_server = None
                self.logger.info(f"Disconnected from {server_name} (DEMO MODE)")
                return True
            
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")
            return False
    
    def get_connection_status(self) -> Dict:
        """Get current connection status"""
        status = {
            'connected': self.is_connected,
            'server': self.current_server,
            'interface': "DEMO_INTERFACE",
            'public_ip': "127.0.0.1"
        }
        
        return status
    
    def start_dummy_tcp_server(self, port: int):
        """Start a dummy TCP server for GUI online detection"""
        import socket
        import threading
        def tcp_server():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(1)
            self.logger.info(f"Dummy TCP server started on 0.0.0.0:{port} for GUI ping test.")
            while True:
                try:
                    client_sock, _ = s.accept()
                    client_sock.close()
                except Exception:
                    break
            s.close()
        t = threading.Thread(target=tcp_server, daemon=True)
        t.start()
        self.dummy_tcp_thread = t
    
    def start_server(self, port: int = 51820, enable_tcp: bool = False) -> bool:
        """
        Simulate starting VPN server. If enable_tcp==True, also start dummy TCP server for status check.
        """
        try:
            self.logger.info(f"Starting demo VPN server on port {port}")
            self.logger.info("DEMO MODE: This is a simulation for testing purposes")
            self.logger.info("In a real deployment, this would start a WireGuard server")
            if enable_tcp:
                self.start_dummy_tcp_server(port)
            # Simulate server startup
            time.sleep(1)
            self.logger.info("Demo VPN server started successfully")
            self.logger.info("Note: This is running in DEMO MODE - no actual VPN tunnel is created")
            return True
        except Exception as e:
            self.logger.error(f"Server start error: {e}")
            return False
    
    def stop_server(self):
        """Simulate stopping VPN server"""
        try:
            self.logger.info("Stopping demo VPN server")
            self.logger.info("Demo VPN server stopped")
            
        except Exception as e:
            self.logger.error(f"Server stop error: {e}")

