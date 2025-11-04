# 📚 LeAmitVPN Project - Complete File-by-File Explanation

This document explains every file in the LeAmitVPN project, step-by-step, so you can understand how everything works together.

---

## 🎯 **PART 1: PROJECT OVERVIEW**

### What is LeAmitVPN?
LeAmitVPN is a **VPN client application** with a graphical user interface (GUI). It allows users to:
- Connect to VPN servers using WireGuard protocol
- Select servers from a visual interface
- Monitor connection status, ping, and speed
- Configure settings (theme, language, DNS, etc.)

### Architecture Overview
```
LeAmitVPN/
├── main.py                    # 🚪 Entry point - starts the app
├── setup.py                   # 🔧 Setup script - initializes project
├── requirements.txt           # 📦 Python dependencies list
├── config/                    # ⚙️ Configuration files
│   ├── servers.json          # 📋 List of available VPN servers
│   ├── settings.json         # 🎛️ User preferences (theme, language, etc.)
│   └── *.conf                # 🔐 WireGuard config files (auto-generated)
├── gui/                       # 🖥️ GUI components (user interface)
│   ├── main_window.py        # 🪟 Main application window
│   ├── server_grid.py        # 🎴 Server selection cards
│   └── settings_panel.py     # ⚙️ Settings dialog
└── vpn_core/                  # 🔌 VPN functionality (core logic)
    ├── real_windows_wireguard.py  # 🪟 Windows WireGuard handler (REAL VPN)
    ├── wireguard_handler.py      # 🐧 Linux/macOS WireGuard handler
    ├── simple_vpn_handler.py     # 🎭 Demo/simulated VPN (for testing)
    ├── logger.py                 # 📝 Logging utilities
    ├── speedtest_utils.py        # 🏃 Speed testing
    └── encryption_utils.py       # 🔒 Encryption helpers
```

---

## 🚪 **PART 2: ENTRY POINT - main.py**

### Purpose
`main.py` is the **starting point** of the application. When you run `python main.py`, this file decides what to do.

### Key Functions:

#### 1. **`main()`** - The Dispatcher
```python
# This function reads command-line arguments and decides:
# - Should we start GUI? (default)
# - Should we start server mode?
# - Should we run speed tests?
```

**Command-line arguments it accepts:**
- `--mode gui` or `--mode server` → Choose GUI client or server mode
- `--port 51820` → Specify server port
- `--enable-tcp` → Start dummy TCP server (for GUI to detect "Online" status)
- `--speedtest` → Run speed tests
- `--verbose` → Show detailed logs

#### 2. **`run_gui_mode()`** - Start the GUI Application
**What it does:**
1. Creates a Qt application (PySide6 framework)
2. Sets up logging
3. **Detects your operating system**:
   - **Windows**: Tries `RealWindowsWireGuard` (real VPN) → Falls back to `SimpleVPNHandler` if WireGuard not installed
   - **Linux/macOS**: Tries `WireGuardHandler` → Falls back to `SimpleVPNHandler`
4. Creates `MainWindow` (the GUI)
5. Shows the window and starts the event loop

**Flow:**
```
main.py → run_gui_mode() → Creates MainWindow → Shows GUI
```

#### 3. **`run_server_mode(port, enable_tcp)`** - Start VPN Server
**What it does:**
1. Sets up logging
2. Detects OS and selects appropriate VPN handler
3. Calls `vpn_handler.start_server(port, enable_tcp=True)`
4. Keeps the server running until Ctrl+C

**Why `enable_tcp`?**
- WireGuard uses **UDP** for actual VPN traffic
- But the GUI checks server status using **TCP**
- The dummy TCP server makes the GUI show "Online" status

#### 4. **`run_speedtest()`** - Test Server Speeds
- Uses `SpeedTestManager` to ping all servers
- Shows ping times and download speeds

---

## 📦 **PART 3: CONFIGURATION FILES**

### 1. **`config/servers.json`** - Server List

**Purpose:** Stores all available VPN servers that users can connect to.

**Structure:**
```json
{
  "servers": [
    {
      "id": "india-mumbai",        // Unique identifier
      "name": "Mumbai",             // Display name
      "country": "India",            // Country name
      "flag": "IN",                 // Country flag emoji/code
      "endpoint": "127.0.0.1:51821", // IP:Port where server runs
      "public_key": "FMwWQq...",    // WireGuard public key (for encryption)
      "description": "...",        // Server description
      "region": "asia",             // Geographic region
      "location": "Mumbai, India"   // Location string
    }
  ],
  "default_server": "local-server",  // Auto-connect to this server
  "auto_connect": false,            // Auto-connect enabled?
  "last_connected": null             // Last server ID user connected to
}
```

**How it's used:**
- `main_window.py` reads this file to display server cards
- `real_windows_wireguard.py` reads this to get server details when connecting
- When user connects, the app uses `endpoint` and `public_key` from here

**File locations:**
- Read by: `vpn_core/real_windows_wireguard.py` (line 67)
- Read by: `gui/main_window.py` (for displaying servers)
- Read by: `gui/server_grid.py` (for server cards)

---

### 2. **`config/settings.json`** - User Preferences

**Purpose:** Stores user settings (theme, language, DNS, etc.)

**Structure:**
```json
{
  "theme": "Light",              // "Light", "Dark", or "Auto"
  "language": "English",         // "English", "Spanish", "French", "German"
  "start_minimized": true,       // Start app in system tray?
  "auto_connect": true,          // Auto-connect on startup?
  "show_notifications": true,    // Show connection notifications?
  "custom_dns": false,           // Use custom DNS servers?
  "primary_dns": "",             // Primary DNS IP (e.g., "8.8.8.8")
  "secondary_dns": "",           // Secondary DNS IP (e.g., "1.1.1.1")
  "connection_timeout": 30,     // Connection timeout in seconds
  "keepalive_interval": 25,      // Keep-alive packet interval (seconds)
  "killswitch": true,            // Block traffic if VPN disconnects?
  "dns_leak_protection": true,   // Force DNS through VPN?
  "log_level": "DEBUG",          // Logging level
  "log_to_file": false,         // Save logs to file?
  "mtu_size": 1420,              // Maximum Transmission Unit
  "thread_count": 2              // Worker threads
}
```

**How it's used:**
- `gui/settings_panel.py` loads this when settings dialog opens
- `gui/main_window.py` reads this to apply theme and language on startup
- **Note:** Currently, DNS, timeout, keepalive, killswitch, and DNS leak protection are **saved but NOT applied** to VPN connections (they're UI-only)

**File locations:**
- Written by: `gui/settings_panel.py` (when user saves settings)
- Read by: `gui/main_window.py` (for theme/language)
- Read by: `gui/settings_panel.py` (when dialog opens)

---

### 3. **`config/*.conf`** - WireGuard Configuration Files

**Purpose:** These are **WireGuard tunnel configuration files**. They tell WireGuard how to connect.

**Types of .conf files:**
1. **Server configs**: `OnamVPN-Server.conf`, `server.conf`
   - Tells WireGuard how to run as a VPN server
   - Contains server's private key, IP address, listening port
   - Contains peer (client) public keys

2. **Client configs**: `india-mumbai_client.conf`, `local-server_client.conf`, etc.
   - Tells WireGuard how to connect as a client
   - Contains client's private key, IP address, DNS servers
   - Contains server's public key and endpoint

**Example Client Config:**
```ini
[Interface]
PrivateKey = 6GXwP69Tl8YDldcySLypqH/+nff4hEbQLeuCVwox2kY=  # Client's private key
Address = 10.7.0.2/32                                       # Client's VPN IP
DNS = 8.8.8.8, 1.1.1.1                                     # DNS servers to use

[Peer]
PublicKey = Xw0obosMv4X4EF+g4Lt+kd8vazidUdH42NL3cF6kB20=   # Server's public key
Endpoint = 127.0.0.1:51820                                 # Server IP:Port
AllowedIPs = 10.7.0.1/32                                   # Which IPs to route through VPN
PersistentKeepalive = 25                                   # Keep-alive interval (seconds)
```

**How they're created:**
- Generated by `real_windows_wireguard.py` when user clicks "Connect"
- Saved with timestamp: `india-mumbai_client-1762274505.conf` (to avoid file conflicts)
- User must manually import these into WireGuard Windows app

**File locations:**
- Created by: `vpn_core/real_windows_wireguard.py` → `create_wireguard_config()` (line 145)
- Used by: WireGuard Windows application (manual import)

---

## 🔌 **PART 4: VPN CORE MODULE** (`vpn_core/`)

The `vpn_core/` folder contains all the **VPN logic** - how connections are made, how keys are generated, etc.

---

### 1. **`vpn_core/logger.py`** - Logging System

**Purpose:** Sets up logging for the entire application.

**What it does:**
1. Creates a `logs/` directory:
   - **Windows**: `%APPDATA%/OnamVPN/logs/`
   - **Linux/macOS**: `~/.local/share/OnamVPN/logs/`
2. Creates log files with rotation (10MB max, keeps 5 backups)
3. Logs to both **console** and **file**

**Key Functions:**
- `setup_logger(name, level)` → Configures logging system
- `get_logger(name)` → Returns a logger instance

**Used by:** Every file in the project (imported everywhere)

---

### 2. **`vpn_core/real_windows_wireguard.py`** - Windows Real VPN Handler ⭐

**Purpose:** This is the **REAL VPN handler for Windows**. It creates actual WireGuard connections.

**Key Methods:**

#### `__init__(config_dir)`
- Finds WireGuard installation (`C:/Program Files/WireGuard/wg.exe`)
- Loads `config/servers.json`
- Sets up configuration directory

#### `_find_wireguard_installation()`
- Searches common Windows paths for WireGuard
- Also checks PATH environment variable
- Returns `None` if not found

#### `_load_servers()`
- Reads `config/servers.json`
- Returns list of server dictionaries

#### `generate_keys()`
- Runs `wg genkey` to generate private key
- Runs `wg pubkey` to generate public key from private key
- Returns `(private_key, public_key)` tuple

#### `create_wireguard_config(server, private_key)`
- Creates a WireGuard `.conf` file content
- Includes:
  - Client private key
  - Client IP address (`10.7.0.2/32`)
  - DNS servers (hardcoded: `8.8.8.8, 1.1.1.1`)
  - Server public key (from `servers.json`)
  - Server endpoint (from `servers.json`)
  - AllowedIPs (`10.7.0.1/32` - point-to-point)
  - PersistentKeepalive (`25` seconds - hardcoded)

**Why point-to-point?**
- Server: `10.7.0.1/24`
- Client: `10.7.0.2/32`
- Client AllowedIPs: `10.7.0.1/32` (only route to server)
- This prevents routing conflicts when server and client run on same PC

#### `connect_to_server(server_id)`
**The main connection method!**

**Steps:**
1. Checks if already connected
2. Finds server in `servers.json` by `server_id`
3. Generates client keys (`generate_keys()`)
4. Creates WireGuard config (`create_wireguard_config()`)
5. Saves config to file with timestamp
6. Prints instructions for manual import into WireGuard app
7. Sets `is_connected = True`

**Why manual import?**
- Windows WireGuard app has file locks
- Direct activation would cause `WinError 32` (file in use)
- Solution: User imports config manually in WireGuard app

#### `start_server(port, enable_tcp)`
**Starts the VPN server**

**Steps:**
1. Creates server config with:
   - Server IP: `10.7.0.1/24`
   - Listen port: `port` (e.g., 51821)
   - Server private key (generated or loaded)
2. If `enable_tcp=True`, starts a **dummy TCP server** on the same port
   - This allows GUI to detect server as "Online"
   - WireGuard uses UDP, but GUI checks TCP
3. Prints instructions for manual import

**The dummy TCP server:**
```python
# Creates a simple TCP socket that accepts connections
# GUI checks this port → sees "Online"
# Actual VPN traffic still uses UDP via WireGuard
```

---

### 3. **`vpn_core/wireguard_handler.py`** - Linux/macOS Handler

**Purpose:** Similar to `real_windows_wireguard.py`, but for Linux/macOS.

**Key Differences:**
- Uses `wg` and `wg-quick` commands (not `wg.exe`)
- Can directly activate interfaces using `wg-quick up <config>`
- No file lock issues (can automate activation)

---

### 4. **`vpn_core/simple_vpn_handler.py`** - Demo/Simulated VPN

**Purpose:** A **fake VPN handler** used when WireGuard is not installed or for testing.

**What it does:**
- Simulates connection/disconnection
- Doesn't create real VPN tunnels
- Shows "Connected" status in GUI, but no actual VPN

**When it's used:**
- WireGuard not installed
- Testing GUI without VPN
- Fallback when real handlers fail

---

### 5. **`vpn_core/speedtest_utils.py`** - Speed Testing

**Purpose:** Tests ping and download speed for all servers.

**Functions:**
- `test_all_servers()` → Tests all servers in `servers.json`
- Returns ping times and download speeds

---

### 6. **`vpn_core/encryption_utils.py`** - Encryption Helpers

**Purpose:** Additional encryption utilities (if needed).

---

## 🖥️ **PART 5: GUI MODULE** (`gui/`)

The `gui/` folder contains all the **user interface** components.

---

### 1. **`gui/main_window.py`** - Main Application Window

**Purpose:** This is the **main window** you see when you run the app.

**Key Components:**

#### `MainWindow` Class
The main window widget that contains everything.

**Initialization (`__init__`):**
1. Creates VPN handler (passed from `main.py`)
2. Sets up UI (`init_ui()`)
3. Connects signals (`setup_connections()`)
4. Starts connection monitor thread
5. Loads servers (`load_servers()`)
6. Applies saved theme and language

#### `init_ui()` - Creates the UI
**Creates:**
1. **Header**: Title "OnamVPN" and subtitle
2. **Status Panel**: Shows connection status (Connected/Disconnected)
3. **Server Selection**: Grid of server cards (`ServerGrid`)
4. **Control Buttons**: Connect, Disconnect, Settings
5. **Status Bar**: Bottom status bar

#### `create_header()` - App Title
- Creates title label: "OnamVPN"
- Creates subtitle: "Local VPN with GUI - Secure & Fast"
- Applies styling

#### `create_status_panel()` - Connection Status
- Shows current connection status
- Displays selected server info
- Updates based on connection state

#### `create_server_selection()` - Server Grid
- Creates `ServerGrid` widget
- Displays all servers from `servers.json` as cards
- Allows user to click and select servers

#### `create_control_buttons()` - Action Buttons
- **Connect Button**: Calls `connect_to_server()`
- **Disconnect Button**: Calls `disconnect_from_server()`
- **Settings Button**: Opens `SettingsPanel`

#### `connect_to_server()` - Handle Connection
**Steps:**
1. Gets selected server
2. Updates UI: "Connecting..."
3. Calls `vpn_handler.connect_to_server(server_id)`
4. Updates UI based on result: "Connected" or "Error"

#### `disconnect_from_server()` - Handle Disconnection
1. Calls `vpn_handler.disconnect_from_server()`
2. Updates UI to "Disconnected"

#### `show_settings()` - Open Settings Dialog
1. Creates `SettingsPanel` dialog
2. Connects `settings_changed` signal to `apply_theme()` and `apply_language()`
3. Shows dialog

#### `apply_saved_theme()` / `apply_theme(theme)`
- Reads `config/settings.json`
- Applies light or dark theme
- Changes stylesheet dynamically

#### `apply_saved_language()` / `apply_language(lang)`
- Reads `config/settings.json`
- Updates all UI text to selected language
- Supports English, Spanish, French, German

#### `ConnectionMonitor` Thread
- Runs in background
- Checks connection status every 2 seconds
- Updates UI when status changes

---

### 2. **`gui/server_grid.py`** - Server Selection Grid

**Purpose:** Displays servers as **clickable cards** in a grid layout.

**Key Components:**

#### `ServerGrid` Class
A widget that displays multiple server cards in a grid.

**Methods:**
- `load_servers(servers)` → Creates cards for each server
- `on_server_selected(server)` → Emits signal when user clicks a card

#### `ServerCard` Class
Individual server card widget.

**What it shows:**
- Country flag emoji
- Server name (e.g., "Mumbai")
- Country name (e.g., "India")
- Ping status ("Online" or "Offline")
- Ping time (if online)

**How ping works:**
1. `PingTestThread` runs in background
2. For each server, tries to connect to `endpoint` (TCP socket)
3. If connection succeeds → "Online" with ping time
4. If fails → "Offline"

**Note:** The ping test uses **TCP**, not UDP. This is why `--enable-tcp` is needed for servers to show "Online".

---

### 3. **`gui/settings_panel.py`** - Settings Dialog

**Purpose:** A dialog window where users configure app settings.

**Key Components:**

#### `SettingsPanel` Class
A modal dialog with tabs.

**Tabs:**
1. **General Tab**:
   - Theme selection (Light/Dark/Auto)
   - Language selection (English/Spanish/French/German)
   - Startup options:
     - Start minimized to system tray
     - Auto-connect to last server
     - Show connection notifications

2. **Network Tab**:
   - DNS Settings:
     - Use custom DNS servers (checkbox)
     - Primary DNS input
     - Secondary DNS input
   - Connection Settings:
     - Connection timeout (spinbox)
     - Keep-alive interval (spinbox)
   - Security:
     - Enable kill switch (checkbox)
     - Enable DNS leak protection (checkbox)

3. **Advanced Tab**:
   - Logging settings
   - Performance settings (MTU, threads)
   - Configuration import/export

4. **About Tab**:
   - Application info
   - System information

**Key Methods:**

#### `load_settings()`
- Reads `config/settings.json`
- Calls `apply_settings_to_ui()` to populate UI

#### `save_settings()`
- Collects all settings from UI
- Writes to `config/settings.json`
- Emits `settings_changed` signal
- Shows success message

#### `apply_settings_to_ui()`
- Sets all UI elements (checkboxes, spinboxes, combos) based on loaded settings

**Signals:**
- `settings_changed` → Emitted when user saves settings
- Connected to `main_window.py` → Updates theme/language immediately

---

## 🔄 **PART 6: HOW IT ALL WORKS TOGETHER**

### **Startup Flow:**
```
1. User runs: python main.py
   ↓
2. main.py → main() function
   ↓
3. main() → run_gui_mode() (default)
   ↓
4. run_gui_mode():
   - Creates Qt application
   - Detects OS → Creates VPN handler (RealWindowsWireGuard on Windows)
   - Creates MainWindow
   - Shows window
   ↓
5. MainWindow.__init__():
   - Creates UI (header, status, server grid, buttons)
   - Loads servers from servers.json
   - Applies saved theme/language
   - Starts connection monitor thread
   ↓
6. GUI is now visible!
```

### **Connection Flow:**
```
1. User clicks a server card in ServerGrid
   ↓
2. ServerCard emits server_selected signal
   ↓
3. MainWindow.on_server_selected() → Sets selected_server
   ↓
4. User clicks "Connect" button
   ↓
5. MainWindow.connect_to_server():
   - Updates UI: "Connecting..."
   - Calls vpn_handler.connect_to_server(server_id)
   ↓
6. RealWindowsWireGuard.connect_to_server():
   - Finds server in servers.json
   - Generates client keys (wg genkey)
   - Creates WireGuard config string
   - Saves config to file (e.g., india-mumbai_client-1234567890.conf)
   - Prints instructions for manual import
   ↓
7. User manually imports config into WireGuard app
   ↓
8. WireGuard activates tunnel → VPN connected!
   ↓
9. ConnectionMonitor thread detects connection → Updates UI
```

### **Settings Flow:**
```
1. User clicks "Settings" button
   ↓
2. MainWindow.show_settings() → Creates SettingsPanel dialog
   ↓
3. SettingsPanel.load_settings() → Reads settings.json
   ↓
4. User changes settings (e.g., theme to "Dark")
   ↓
5. User clicks "Save"
   ↓
6. SettingsPanel.save_settings():
   - Collects all settings from UI
   - Writes to settings.json
   - Emits settings_changed signal
   ↓
7. MainWindow.apply_theme() → Updates stylesheet immediately
```

---

## 📝 **SUMMARY: FILE ROLES**

| File | Purpose | Key Function |
|------|---------|--------------|
| `main.py` | Entry point | Dispatches to GUI/server mode |
| `setup.py` | Setup script | Creates directories, generates keys |
| `config/servers.json` | Server list | Stores available VPN servers |
| `config/settings.json` | User preferences | Theme, language, DNS, etc. |
| `config/*.conf` | WireGuard configs | VPN tunnel configurations |
| `vpn_core/logger.py` | Logging | Sets up logging system |
| `vpn_core/real_windows_wireguard.py` | Windows VPN handler | Creates real WireGuard connections |
| `vpn_core/wireguard_handler.py` | Linux/macOS handler | WireGuard for non-Windows |
| `vpn_core/simple_vpn_handler.py` | Demo handler | Fake VPN for testing |
| `gui/main_window.py` | Main window | Main application window |
| `gui/server_grid.py` | Server cards | Displays servers as clickable cards |
| `gui/settings_panel.py` | Settings dialog | User preferences configuration |

---

## 🎓 **KEY CONCEPTS TO REMEMBER**

1. **main.py is the entry point** - Everything starts here
2. **VPN handlers are platform-specific** - Windows uses `real_windows_wireguard.py`, Linux/macOS uses `wireguard_handler.py`
3. **Config files are JSON** - `servers.json` for servers, `settings.json` for preferences
4. **WireGuard configs are .conf files** - Generated when user connects, must be imported manually on Windows
5. **GUI is PySide6** - Qt-based interface with signals/slots
6. **Settings are saved but not all applied** - DNS, timeout, keepalive are saved but not used in VPN connections yet
7. **TCP dummy server** - Needed for GUI to show "Online" status (WireGuard uses UDP)
8. **Point-to-point addressing** - Used to avoid routing conflicts (10.7.0.1/24 and 10.7.0.2/32)

---

## ✅ **QUESTIONS TO TEST YOUR UNDERSTANDING**

1. What happens when you run `python main.py --mode server --enable-tcp`?
2. Where are VPN servers stored?
3. How does the GUI detect if a server is "Online"?
4. Why does Windows require manual import of .conf files?
5. What is the purpose of the dummy TCP server?
6. Which file creates WireGuard config files?
7. How does the theme switching work?
8. What is point-to-point addressing and why is it used?

---

**End of Explanation**

This document covers the complete structure of LeAmitVPN. Each file plays a specific role in creating a functional VPN client application with a modern GUI interface.

