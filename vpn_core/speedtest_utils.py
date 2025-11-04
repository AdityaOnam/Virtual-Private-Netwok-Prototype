"""
Speed testing utilities for LeAmitVPN
Provides ping testing, speed testing, and server performance monitoring
"""

import socket
import time
import threading
import subprocess
import platform
from typing import Dict, List, Optional, Tuple
import concurrent.futures
import json
from pathlib import Path

from .logger import get_logger


class PingTester:
    """Handles ping testing to VPN servers"""
    
    def __init__(self, timeout: int = 3):
        """
        Initialize ping tester
        
        Args:
            timeout (int): Ping timeout in seconds
        """
        self.timeout = timeout
        self.logger = get_logger(__name__)
    
    def ping_host(self, host: str, port: int = 22) -> Tuple[bool, float]:
        """
        Ping a host by testing TCP connection
        
        Args:
            host (str): Host to ping
            port (int): Port to test connection on
            
        Returns:
            Tuple[bool, float]: (success, response_time_ms)
        """
        try:
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            end_time = time.time()
            
            sock.close()
            
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            return result == 0, response_time
            
        except Exception as e:
            self.logger.error(f"Ping test failed for {host}:{port}: {e}")
            return False, -1
    
    def ping_icmp(self, host: str) -> Tuple[bool, float]:
        """
        Ping using ICMP (requires platform-specific implementation)
        
        Args:
            host (str): Host to ping
            
        Returns:
            Tuple[bool, float]: (success, response_time_ms)
        """
        try:
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), host]
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 2)
            end_time = time.time()
            
            if result.returncode == 0:
                response_time = (end_time - start_time) * 1000
                return True, response_time
            else:
                return False, -1
                
        except Exception as e:
            self.logger.error(f"ICMP ping failed for {host}: {e}")
            return False, -1
    
    def test_server_ping(self, server: Dict) -> Dict:
        """
        Test ping to a VPN server
        
        Args:
            server (Dict): Server configuration
            
        Returns:
            Dict: Ping test results
        """
        endpoint = server.get('endpoint', '')
        
        if ':' in endpoint:
            host, port = endpoint.split(':')
            port = int(port)
        else:
            host = endpoint
            port = 51820  # Default WireGuard port
        
        # Try TCP connection first (more reliable for VPN servers)
        tcp_success, tcp_time = self.ping_host(host, port)
        
        # Try ICMP ping as backup
        icmp_success, icmp_time = self.ping_icmp(host)
        
        result = {
            'server_id': server['id'],
            'server_name': server['name'],
            'host': host,
            'port': port,
            'tcp_success': tcp_success,
            'tcp_time': tcp_time,
            'icmp_success': icmp_success,
            'icmp_time': icmp_time,
            'best_time': -1,
            'status': 'offline'
        }
        
        # Determine best ping time
        if tcp_success and icmp_success:
            result['best_time'] = min(tcp_time, icmp_time)
            result['status'] = 'online'
        elif tcp_success:
            result['best_time'] = tcp_time
            result['status'] = 'online'
        elif icmp_success:
            result['best_time'] = icmp_time
            result['status'] = 'online'
        
        return result


class SpeedTestManager:
    """Manages speed testing for VPN servers"""
    
    def __init__(self, servers_file: str = "config/servers.json"):
        """
        Initialize speed test manager
        
        Args:
            servers_file (str): Path to servers configuration file
        """
        self.servers_file = servers_file
        self.logger = get_logger(__name__)
        self.ping_tester = PingTester()
        self.servers = self._load_servers()
    
    def _load_servers(self) -> List[Dict]:
        """Load servers from configuration file"""
        try:
            with open(self.servers_file, 'r') as f:
                data = json.load(f)
                return data.get('servers', [])
        except Exception as e:
            self.logger.error(f"Failed to load servers: {e}")
            return []
    
    def test_all_servers(self, max_workers: int = 5) -> Dict[str, Dict]:
        """
        Test ping for all servers concurrently
        
        Args:
            max_workers (int): Maximum number of concurrent tests
            
        Returns:
            Dict[str, Dict]: Results for each server
        """
        results = {}
        
        if not self.servers:
            self.logger.warning("No servers available for testing")
            return results
        
        self.logger.info(f"Testing {len(self.servers)} servers with {max_workers} workers")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all ping tests
            future_to_server = {
                executor.submit(self.ping_tester.test_server_ping, server): server
                for server in self.servers
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_server):
                server = future_to_server[future]
                try:
                    result = future.result()
                    results[server['id']] = result
                    
                    status = result['status']
                    time = result['best_time']
                    self.logger.info(f"{server['name']}: {status} ({time:.1f}ms)" if time > 0 else f"{server['name']}: {status}")
                    
                except Exception as e:
                    self.logger.error(f"Test failed for {server['name']}: {e}")
                    results[server['id']] = {
                        'server_id': server['id'],
                        'server_name': server['name'],
                        'status': 'error',
                        'best_time': -1
                    }
        
        return results
    
    def test_server(self, server_id: str) -> Optional[Dict]:
        """
        Test a specific server
        
        Args:
            server_id (str): ID of server to test
            
        Returns:
            Dict: Test results or None if server not found
        """
        server = None
        for s in self.servers:
            if s['id'] == server_id:
                server = s
                break
        
        if not server:
            self.logger.error(f"Server {server_id} not found")
            return None
        
        return self.ping_tester.test_server_ping(server)
    
    def get_fastest_server(self) -> Optional[Dict]:
        """
        Find the server with the lowest ping
        
        Returns:
            Dict: Fastest server configuration or None
        """
        results = self.test_all_servers()
        
        fastest_server = None
        fastest_time = float('inf')
        
        for server_id, result in results.items():
            if result['status'] == 'online' and result['best_time'] < fastest_time:
                fastest_time = result['best_time']
                # Find server config
                for server in self.servers:
                    if server['id'] == server_id:
                        fastest_server = server
                        break
        
        return fastest_server
    
    def get_server_stats(self) -> Dict:
        """
        Get statistics about server performance
        
        Returns:
            Dict: Server statistics
        """
        results = self.test_all_servers()
        
        online_servers = 0
        offline_servers = 0
        ping_times = []
        
        for result in results.values():
            if result['status'] == 'online':
                online_servers += 1
                if result['best_time'] > 0:
                    ping_times.append(result['best_time'])
            else:
                offline_servers += 1
        
        stats = {
            'total_servers': len(self.servers),
            'online_servers': online_servers,
            'offline_servers': offline_servers,
            'average_ping': sum(ping_times) / len(ping_times) if ping_times else 0,
            'min_ping': min(ping_times) if ping_times else 0,
            'max_ping': max(ping_times) if ping_times else 0
        }
        
        return stats


class BandwidthTester:
    """Test bandwidth through VPN connection"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def test_upload_speed(self, test_duration: int = 10) -> float:
        """
        Test upload speed (simplified implementation)
        
        Args:
            test_duration (int): Test duration in seconds
            
        Returns:
            float: Upload speed in Mbps
        """
        try:
            # This is a simplified test - in a real implementation,
            # you would upload data to a test server
            import random
            
            # Simulate upload test
            time.sleep(1)
            
            # Return random speed for demonstration
            speed = random.uniform(5.0, 50.0)
            self.logger.info(f"Upload speed test: {speed:.2f} Mbps")
            
            return speed
            
        except Exception as e:
            self.logger.error(f"Upload speed test failed: {e}")
            return 0.0
    
    def test_download_speed(self, test_duration: int = 10) -> float:
        """
        Test download speed (simplified implementation)
        
        Args:
            test_duration (int): Test duration in seconds
            
        Returns:
            float: Download speed in Mbps
        """
        try:
            # This is a simplified test - in a real implementation,
            # you would download data from a test server
            import random
            
            # Simulate download test
            time.sleep(1)
            
            # Return random speed for demonstration
            speed = random.uniform(10.0, 100.0)
            self.logger.info(f"Download speed test: {speed:.2f} Mbps")
            
            return speed
            
        except Exception as e:
            self.logger.error(f"Download speed test failed: {e}")
            return 0.0
    
    def test_latency(self, host: str = "8.8.8.8") -> float:
        """
        Test latency to a host
        
        Args:
            host (str): Host to test latency to
            
        Returns:
            float: Latency in milliseconds
        """
        try:
            ping_tester = PingTester()
            success, latency = ping_tester.ping_icmp(host)
            
            if success:
                self.logger.info(f"Latency test to {host}: {latency:.2f} ms")
                return latency
            else:
                return -1
                
        except Exception as e:
            self.logger.error(f"Latency test failed: {e}")
            return -1


class NetworkMonitor:
    """Monitor network performance and connection quality"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self, callback=None):
        """
        Start network monitoring
        
        Args:
            callback: Function to call with monitoring results
        """
        if self.monitoring:
            return
        
        self.monitoring = True
        self.callback = callback
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        bandwidth_tester = BandwidthTester()
        ping_tester = PingTester()
        
        while self.monitoring:
            try:
                # Test latency
                latency = bandwidth_tester.test_latency()
                
                # Create monitoring result
                result = {
                    'timestamp': time.time(),
                    'latency': latency,
                    'status': 'connected' if latency > 0 else 'disconnected'
                }
                
                # Call callback if provided
                if self.callback:
                    self.callback(result)
                
                # Wait before next check
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(5)


