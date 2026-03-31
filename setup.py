#!/usr/bin/env python3
"""
Setup script for ONAMVPN
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_wireguard():
    """Check if WireGuard is installed"""
    try:
        result = subprocess.run(['wg', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ WireGuard is installed")
            return True
    except FileNotFoundError:
        pass
    
    print("❌ WireGuard is not installed or not in PATH")
    print("\n📥 Install WireGuard:")
    
    system = platform.system().lower()
    if system == "windows":
        print("   Download from: https://www.wireguard.com/install/")
    elif system == "darwin":  # macOS
        print("   Run: brew install wireguard-tools")
    elif system == "linux":
        print("   Ubuntu/Debian: sudo apt install wireguard")
        print("   CentOS/RHEL: sudo yum install wireguard-tools")
    
    return False

def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        "config",
        "logs",
        "keys"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   Created: {directory}/")
    
    return True

def generate_sample_keys():
    """Generate sample WireGuard keys for testing"""
    print("\n🔑 Generating sample keys...")
    
    try:
        # Generate server keys
        private_key_result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True)
        if private_key_result.returncode != 0:
            print("❌ Failed to generate server private key")
            return False
        
        server_private_key = private_key_result.stdout.strip()
        
        public_key_result = subprocess.run(['wg', 'pubkey'], input=server_private_key, capture_output=True, text=True)
        if public_key_result.returncode != 0:
            print("❌ Failed to generate server public key")
            return False
        
        server_public_key = public_key_result.stdout.strip()
        
        # Generate client keys
        private_key_result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True)
        if private_key_result.returncode != 0:
            print("❌ Failed to generate client private key")
            return False
        
        client_private_key = private_key_result.stdout.strip()
        
        public_key_result = subprocess.run(['wg', 'pubkey'], input=client_private_key, capture_output=True, text=True)
        if public_key_result.returncode != 0:
            print("❌ Failed to generate client public key")
            return False
        
        client_public_key = public_key_result.stdout.strip()
        
        # Save keys to files
        with open('keys/server_private.key', 'w') as f:
            f.write(server_private_key)
        
        with open('keys/server_public.key', 'w') as f:
            f.write(server_public_key)
        
        with open('keys/client_private.key', 'w') as f:
            f.write(client_private_key)
        
        with open('keys/client_public.key', 'w') as f:
            f.write(client_public_key)
        
        print("   Generated server keys")
        print("   Generated client keys")
        print("   Keys saved to keys/ directory")
        
        # Update server configuration
        update_server_config(server_private_key, server_public_key, client_public_key)
        
        return True
        
    except Exception as e:
        print(f"❌ Key generation failed: {e}")
        return False

def update_server_config(server_private_key, server_public_key, client_public_key):
    """Update server configuration with generated keys"""
    try:
        # Read servers.json
        import json
        
        with open('config/servers.json', 'r') as f:
            servers_data = json.load(f)
        
        # Update server configurations
        for server in servers_data['servers']:
            server['public_key'] = server_public_key
        
        # Save updated configuration
        with open('config/servers.json', 'w') as f:
            json.dump(servers_data, f, indent=2)
        
        print("   Updated server configuration")
        
    except Exception as e:
        print(f"   Warning: Failed to update server config: {e}")

def create_sample_configs():
    """Create sample configuration files"""
    print("\n📝 Creating sample configurations...")
    
    # Server configuration
    server_config = """[Interface]
PrivateKey = REPLACE_WITH_SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = REPLACE_WITH_CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
"""
    
    with open('config/server.conf', 'w') as f:
        f.write(server_config)
    
    print("   Created: config/server.conf")
    
    # Client configuration
    client_config = """[Interface]
PrivateKey = REPLACE_WITH_CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = REPLACE_WITH_SERVER_PUBLIC_KEY
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    
    with open('config/client.conf', 'w') as f:
        f.write(client_config)
    
    print("   Created: config/client.conf")

def main():
    """Main setup function"""
    print("🚀 OnamVPN Setup")
    print("=" * 50)
    
    # Check requirements
    if not check_python_version():
        return False
    
    if not check_wireguard():
        print("\n⚠️  Please install WireGuard and run setup again")
        return False
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Create directories
    if not create_directories():
        return False
    
    # Generate keys
    if not generate_sample_keys():
        print("⚠️  Key generation failed, but setup can continue")
    
    # Create sample configs
    create_sample_configs()
    
    print("\n" + "=" * 50)
    print("✅ Setup completed successfully!")
    print("\n🎯 Next steps:")
    print("   1. Review and update config/servers.json with your server details")
    print("   2. Update config/server.conf and config/client.conf with your keys")
    print("   3. Run the application:")
    print("      python main.py --mode server    # Start VPN server")
    print("      python main.py                  # Start GUI client")
    print("\n📖 See README.md for detailed instructions")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
