# OnamVPN - Local VPN with GUI

A modern, local VPN implementation with a beautiful GUI built on top of OnamVPN's core architecture, using WireGuard for secure tunneling.

## 🌟 Features

- **Modern GUI**: Clean PySide6 interface with dark/light themes
- **WireGuard Integration**: Secure, fast VPN tunneling
- **Server Selection**: Choose from multiple regions (India, EU, US)
- **Real-time Monitoring**: Ping, speed tests, and connection status
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Local Testing**: Perfect for learning VPN concepts and local development

## 🏗️ Architecture

```
OnamVPN/
├── vpn_core/              # Core VPN functionality
│   ├── wireguard_handler.py
│   ├── encryption_utils.py
│   ├── speedtest_utils.py
│   └── logger.py
├── gui/                   # PySide6 GUI components
│   ├── main_window.py
│   ├── server_grid.py
│   └── settings_panel.py
├── config/                # Configuration files
│   ├── client.conf
│   ├── server.conf
│   └── servers.json
├── requirements.txt
└── main.py               # Application entry point
```

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+** installed
2. **WireGuard** installed on your system
3. **Git** for cloning the repository

### Installation

1. Clone or download the project:
```bash
# If you have git:
git clone <repository-url>
cd OnamVPN

# Or simply download and extract the ZIP file
```

2. Run the setup script:
```bash
# Windows
python setup.py

# Linux/macOS
python3 setup.py
```

3. Install WireGuard (if not already installed):
   - **Windows**: Download from [wireguard.com](https://www.wireguard.com/install/)
   - **macOS**: `brew install wireguard-tools`
   - **Linux**: `sudo apt install wireguard` (Ubuntu/Debian)

### Running the Application

#### Option 1: Using the provided scripts
```bash
# Windows
run.bat

# Linux/macOS
./run.sh
```

#### Option 2: Manual execution
1. Start the VPN server (local):
```bash
python main.py --mode server --port 51821 --enable-tcp   # Recommended: enables TCP server for GUI detection
```

2. Start the GUI client:
```bash
python main.py
```

#### Option 3: Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## 🔧 Configuration

### Server Configuration

Edit `config/server.conf` to configure your VPN server:

```ini
[Interface]
PrivateKey = YOUR_SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = YOUR_CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
```

### Client Configuration

Edit `config/client.conf` to configure the client:

```ini
[Interface]
PrivateKey = YOUR_CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = YOUR_SERVER_PUBLIC_KEY
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
```

### Server List

Edit `config/servers.json` to add your VPN servers:

```json
{
  "servers": [
    {
      "id": "india-mumbai",
      "name": "Mumbai",
      "country": "India",
      "flag": "🇮🇳",
      "endpoint": "127.0.0.1:51820",
      "public_key": "YOUR_SERVER_PUBLIC_KEY"
    }
  ]
}
```

## 🎯 Usage

### GUI Interface

1. **Server Selection**: Click on any server card to select it
2. **Connect**: Click the "Connect" button to establish VPN connection
3. **Monitor**: View real-time ping, speed, and connection status
4. **Disconnect**: Click "Disconnect" to close the VPN tunnel

### Command Line Interface

```bash
# Start as server
python main.py --mode server --port 51820 --enable-tcp     # Will also show as online in GUI

# Start as client with specific server
python main.py --server india-mumbai

# Run speed test
python main.py --speedtest
```

## 🔒 Security Features

- **WireGuard Encryption**: Modern, secure tunneling protocol
- **DNS Leak Protection**: Prevents DNS queries from leaking
- **Kill Switch**: Automatically blocks traffic if VPN disconnects
- **AES Encryption**: Optional additional encryption layer

## 💡 Dummy TCP Server for GUI Online Status

By default, LeAmitVPN servers (WireGuard) listen only on UDP ports. The GUI checks server status using TCP, so even if your tunnel is up, the GUI may say 'Offline'.

**Solution:** Enable a dummy TCP server for GUI online detection.

**How to use:**

```bash
python main.py --mode server --port 51821 --enable-tcp
```
This will start the VPN server and also a dummy TCP server on port 51821. The GUI will then show this server as 'Online'.

- Works for all server modes (demo and real)
- No impact on VPN data—it's only for visual/GUI status

## 🛠️ Development

### Adding New Servers

1. Generate WireGuard keys:
```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

2. Add server configuration to `config/servers.json`
3. Update client configurations accordingly

### Customizing the GUI

The GUI is built with PySide6 and can be customized by modifying files in the `gui/` directory:

- `main_window.py`: Main application window
- `server_grid.py`: Server selection interface
- `settings_panel.py`: Settings and preferences

## 📊 Monitoring

The application provides real-time monitoring of:

- **Connection Status**: Connected/Disconnected/Connecting
- **Ping Latency**: Round-trip time to server
- **Bandwidth**: Upload/download speeds
- **Data Usage**: Bytes transferred through VPN

If VPN server is running (UDP), but the GUI still says 'Offline', you may not have enabled the TCP dummy mode. Use --enable-tcp when starting the server to allow the GUI to check online status.

## 🐛 Troubleshooting

### Common Issues

1. **WireGuard not found**: Ensure WireGuard is installed and in PATH
2. **Permission denied**: Run with administrator/sudo privileges
3. **Port already in use**: Change the port in configuration files
4. **Connection timeout**: Check firewall settings and network connectivity

### Logs

Application logs are stored in:
- **Windows**: `%APPDATA%/LeAmitVPN/logs/`
- **macOS/Linux**: `~/.local/share/LeAmitVPN/logs/`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built on top of [LeAmitVPN](https://github.com/leamitvpn) architecture
- Uses [WireGuard](https://www.wireguard.com/) for secure tunneling
- GUI powered by [PySide6](https://pypi.org/project/PySide6/)

## 🖥️ Windows (REAL WireGuard) – How to Connect

On Windows the app integrates with the WireGuard desktop app. The project creates `.conf` files that you import into WireGuard.

Point‑to‑point addressing used by the project (same‑PC demo):
- Server interface: `10.7.0.1/24`
- Client interface: `10.7.0.2/32`
- Client AllowedIPs: `10.7.0.1/32`

Steps:
1) Start the server process (also starts TCP helper for GUI):
```bash
python main.py --mode server --port 51821 --enable-tcp
```
2) Import and activate server in WireGuard:
   - WireGuard → Add Tunnel → Add from file → select `config/OnamVPN-Server.conf` → Activate
3) In the GUI, select a server (e.g., Mumbai) → Connect. The app logs a client config path like:
   - `config/india-mumbai_client-<timestamp>.conf`
4) Import and activate client in WireGuard:
   - WireGuard → Add Tunnel → Add from file → select that client config → Activate

Notes:
- The GUI “Online” pill is a TCP connectivity check only; real VPN traffic is over UDP via WireGuard.
- If you see “illegal base64”, re‑generate/import without manual edits; keys must be 44‑char base64 with no quotes/extra characters.

## 🎨 Dark Mode

Enable Dark Mode in Settings:
- Open Settings → Theme → choose “Dark” → Save.
- The UI switches immediately and the preference persists in `config/settings.json`.

## ⚙️ Startup Preferences

Settings → Startup controls app behavior:
- Start minimized to system tray: App launches hidden in the tray. Use the tray icon to Show/Quit.
- Auto-connect to last server: On launch, the client attempts to connect to the last server (or the `default_server` in `config/servers.json`).
- Show connection notifications: System notifications on connect/disconnect/errors.

## 📞 Support

For issues and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the logs for error details

---

**⚠️ Disclaimer**: This is a prototype VPN implementation for educational purposes. Use responsibly and in accordance with local laws and regulations.
