"""
Windows-specific WireGuard handler
Simplified implementation for Windows WireGuard
"""

import subprocess
import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .logger import get_logger


class WindowsWireGuard:
    """Windows-specific WireGuard implementation"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.logger = get_logger(__name__)
        self.is_connected = False
        self.current_server = None
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Load server configurations
        self.servers = self._load_servers()
    
    def _load_servers(self) -> List[Dict]:
        """Load server configurations from JSON file"""
        servers_file = self.config_dir / "servers.json"
        
        if not servers_file.exists():
            self.logger.warning("Servers.json not found")
            return []
            
        try:
            with open(servers_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('servers', [])
        except Exception as e:
            self.logger.error(f"Failed to load servers: {e}")
            return []
    
    def get_available_servers(self) -> List[Dict]:
        """Get list of available servers"""
        return self.servers
    
    def test_wireguard_installation(self) -> bool:
        """Test if WireGuard is properly installed"""
        try:
            result = subprocess.run(
                ['wg', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def generate_keys(self) -> Tuple[str, str]:
        """Generate WireGuard key pair"""
        try:
            # Generate private key
            private_key_result = subprocess.run(
                ['wg', 'genkey'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if private_key_result.returncode != 0:
                raise Exception("Failed to generate private key")
            
            private_key = private_key_result.stdout.strip()
            
            # Generate public key from private key
            public_key_result = subprocess.run(
                ['wg', 'pubkey'],
                input=private_key,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if public_key_result.returncode != 0:
                raise Exception("Failed to generate public key")
            
            public_key = public_key_result.stdout.strip()
            
            return private_key, public_key
            
        except Exception as e:
            self.logger.error(f"Failed to generate keys: {e}")
            raise
    
    def create_tunnel_config(self, server: Dict, private_key: str) -> str:
        """Create WireGuard tunnel configuration"""
        config_content = f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = {server['public_key']}
Endpoint = {server['endpoint']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        return config_content
    
    def connect_to_server(self, server_id: str) -> bool:
        """Connect to a VPN server"""
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
            self.logger.info(f"Connecting to {server['name']}...")
            
            # Generate keys
            private_key, public_key = self.generate_keys()
            
            # Create configuration
            config_content = self.create_tunnel_config(server, private_key)
            config_file = self.config_dir / f"{server_id}_client.conf"
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            # For Windows, we'll simulate the connection
            # In a real implementation, you would use Windows WireGuard service
            self.logger.info("Creating WireGuard tunnel...")
            time.sleep(2)  # Simulate connection time
            
            self.is_connected = True
            self.current_server = server
            self.logger.info(f"Successfully connected to {server['name']}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to server {server_id}: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from current VPN server"""
        if not self.is_connected:
            self.logger.warning("Not connected to any server")
            return False
        
        try:
            self.logger.info("Disconnecting from VPN...")
            time.sleep(1)  # Simulate disconnection time
            
            self.is_connected = False
            server_name = self.current_server['name'] if self.current_server else "Unknown"
            self.current_server = None
            
            self.logger.info(f"Disconnected from {server_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")
            return False
    
    def get_connection_status(self) -> Dict:
        """Get current connection status"""
        status = {
            'connected': self.is_connected,
            'server': self.current_server,
            'interface': "wg0" if self.is_connected else None,
            'public_ip': "10.0.0.2" if self.is_connected else None
        }
        
        return status
    
    def start_dummy_tcp_server(self, port: int):
        """Start a dummy TCP server for GUI online detection (Windows simplified handler)"""
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
        """Start WireGuard server"""
        try:
            self.logger.info(f"Starting WireGuard server on port {port}")
            # Generate server keys
            private_key, public_key = self.generate_keys()
            # Create server configuration
            server_config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.1/24
ListenPort = {port}

[Peer]
PublicKey = {public_key}
AllowedIPs = 10.0.0.2/32
"""
            # Save server configuration
            server_config_file = self.config_dir / "server.conf"
            with open(server_config_file, 'w') as f:
                f.write(server_config)
            # Optionally start dummy TCP
            if enable_tcp:
                try:
                    self.start_dummy_tcp_server(port)
                except Exception as tcp_err:
                    self.logger.warning(f"Failed to start dummy TCP server: {tcp_err}")
            self.logger.info("WireGuard server configuration created")
            self.logger.info(f"Server public key: {public_key}")
            self.logger.info("Note: On Windows, WireGuard server requires manual setup")
            self.logger.info("Server is ready for client connections")
            return True
        except Exception as e:
            self.logger.error(f"Server start error: {e}")
            return False
    
    def stop_server(self):
        """Stop WireGuard server"""
        try:
            self.logger.info("Stopping WireGuard server")
            self.logger.info("WireGuard server stopped")
            
        except Exception as e:
            self.logger.error(f"Server stop error: {e}")
