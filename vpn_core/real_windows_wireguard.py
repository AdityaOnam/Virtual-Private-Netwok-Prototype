"""
Real Windows WireGuard implementation for actual VPN tunneling
This creates REAL VPN connections using Windows WireGuard service
"""

import subprocess
import json
import threading
import time
import os
import shutil
import ctypes
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from oslab.resilience.atomicio import atomic_write_json
from .logger import get_logger


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

import dotenv
dotenv.load_dotenv()

# Cloudflare WARP config constants
WARP_PRIVATE_KEY    = os.environ.get("WARP_PRIVATE_KEY", "EL1ScVeUvB1oQ36XOBoBKR4E46BL4bMJBigXdGvrNlg=")
WARP_PUBLIC_KEY     = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT       = "engage.cloudflareclient.com:2408"
WARP_CLIENT_ADDR    = "172.16.0.2/32"
WARP_DNS            = "1.1.1.1, 1.0.0.1"
WARP_MTU            = 1280
WARP_TUNNEL_NAME    = "wgcf-profile"   # Name as seen in WireGuard GUI
# Safe staging directory (no spaces in path — WireGuard service requirement)
SAFE_CONFIG_DIR     = Path("C:/OnamVPN")

# Server/Client Connection Constants
CLIENT_ADDR         = "10.0.0.2/32"
SERVER_CIDR         = "10.0.0.1/24"
CLIENT_LISTEN_PORT  = 51820

class RealWindowsWireGuard:
    """Real Windows WireGuard implementation for actual VPN tunneling"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.logger = get_logger(__name__)
        self.is_connected = False
        self.current_server = None
        self.connection_thread = None
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Find WireGuard installation
        self.wireguard_path = self._find_wireguard_installation()
        
        # Clean up any leftover firewall rules and active tunnels on startup
        self.cleanup_stale_configurations()
        
        # Load server configurations
        self.servers = self._load_servers()
    
    def _find_wireguard_installation(self) -> Optional[Path]:
        """Find WireGuard installation path on Windows.

        Looks for both wg.exe (CLI key tool) and wireguard.exe (service manager).
        Returns the directory that contains them, or None if not found.
        """
        # Check standard install locations for wireguard.exe
        candidate_dirs = [
            Path("C:/Program Files/WireGuard"),
            Path("C:/Program Files (x86)/WireGuard"),
            Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'WireGuard',
            Path(os.environ.get('PROGRAMFILES(X86)', '')) / 'WireGuard',
        ]

        for d in candidate_dirs:
            if (d / 'wireguard.exe').exists() or (d / 'wg.exe').exists():
                self.logger.info(f"Found WireGuard installation at: {d}")
                return d

        # Fall back to PATH search (wg or wireguard)
        for exe in ('wireguard', 'wg'):
            try:
                result = subprocess.run(['where', exe], capture_output=True, text=True)
                if result.returncode == 0:
                    found = Path(result.stdout.strip().splitlines()[0])
                    self.logger.info(f"Found WireGuard in PATH: {found}")
                    return found.parent
            except Exception:
                pass

        self.logger.error("WireGuard not found. Install from https://www.wireguard.com/install/")
        return None
    
    def _load_servers(self) -> List[Dict]:
        """Load server configurations from JSON file"""
        servers_file = self.config_dir / "servers.json"
        
        if not servers_file.exists():
            self.logger.warning("Servers.json not found, creating default configuration")
            self._create_default_servers()
            
        try:
            with open(servers_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.servers = data.get('servers', [])
                return self.servers
        except Exception as e:
            self.logger.error(f"Failed to load servers: {e}")
            return []

    def _create_default_servers(self):
        """Create default server configuration containing Cloudflare WARP endpoints"""
        default_servers = {
            "servers": [
                {
                    "id": "cloudflare-warp",
                    "name": "Cloudflare WARP",
                    "country": "Global",
                    "flag": "🌐",
                    "endpoint": "engage.cloudflareclient.com:2408",
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "description": "Cloudflare WARP - Nearest edge node",
                    "region": "global",
                    "location": "Cloudflare Global Network",
                    "client_address": "172.16.0.2/32",
                    "dns": "1.1.1.1, 1.0.0.1",
                    "mtu": 1280
                },
                {
                    "id": "eu-frankfurt",
                    "name": "Frankfurt",
                    "country": "Germany",
                    "flag": "DE",
                    "endpoint": "162.159.193.1:2408",
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "description": "Europe - Frankfurt via Cloudflare WARP",
                    "region": "europe",
                    "location": "Frankfurt, Germany",
                    "client_address": "172.16.0.2/32",
                    "dns": "1.1.1.1, 1.0.0.1",
                    "mtu": 1280
                },
                {
                    "id": "us-newyork",
                    "name": "New York",
                    "country": "United States",
                    "flag": "US",
                    "endpoint": "162.159.192.1:2408",
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "description": "United States - New York via Cloudflare WARP",
                    "region": "americas",
                    "location": "New York, USA",
                    "client_address": "172.16.0.2/32",
                    "dns": "1.1.1.1, 1.0.0.1",
                    "mtu": 1280
                },
                {
                    "id": "india-mumbai",
                    "name": "Mumbai",
                    "country": "India",
                    "flag": "IN",
                    "endpoint": "162.159.195.1:2408",
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "description": "India - Mumbai via Cloudflare WARP",
                    "region": "asia",
                    "location": "Mumbai, India",
                    "client_address": "172.16.0.2/32",
                    "dns": "1.1.1.1, 1.0.0.1",
                    "mtu": 1280
                }
            ],
            "default_server": "eu-frankfurt",
            "auto_connect": False,
            "last_connected": None
        }
        
        servers_file = self.config_dir / "servers.json"
        try:
            atomic_write_json(servers_file, default_servers)
            self.logger.info("Created default server configuration (Cloudflare WARP endpoints)")
        except Exception as e:
            self.logger.error(f"Failed to create default server configuration: {e}")
    
    def get_available_servers(self) -> List[Dict]:
        """Get list of available servers"""
        return self.servers
    
    def test_wireguard_installation(self) -> bool:
        """Test if WireGuard is properly installed"""
        if not self.wireguard_path:
            return False
            
        try:
            wg_exe = self.wireguard_path / "wg.exe"
            result = subprocess.run(
                [str(wg_exe), '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def generate_keys(self) -> Tuple[str, str]:
        """Generate WireGuard key pair"""
        if not self.wireguard_path:
            raise Exception("WireGuard not found")
            
        try:
            wg_exe = self.wireguard_path / "wg.exe"
            
            # Generate private key
            private_key_result = subprocess.run(
                [str(wg_exe), 'genkey'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if private_key_result.returncode != 0:
                raise Exception("Failed to generate private key")
            
            private_key = private_key_result.stdout.strip()
            
            # Generate public key from private key
            public_key_result = subprocess.run(
                [str(wg_exe), 'pubkey'],
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
    
    def create_wireguard_config(self, server: Dict, private_key: str) -> str:
        """
        Create WireGuard client configuration.
        Uses the selected server's endpoint from servers.json so each server
        card actually connects to a different Cloudflare WARP regional IP.
        All servers share the same registered wgcf credentials (key pair).
        """
        endpoint = server.get('endpoint', WARP_ENDPOINT)
        config_content = f"""[Interface]
PrivateKey = {WARP_PRIVATE_KEY}
Address = {WARP_CLIENT_ADDR}
DNS = {WARP_DNS}
MTU = {WARP_MTU}

[Peer]
PublicKey = {WARP_PUBLIC_KEY}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
"""
        return config_content

    
    # The tunnel name WireGuard derives from the config file stem (filename without .conf)
    TUNNEL_NAME = "OnamVPN"

    def _stage_config(self, config_file: Path) -> Path:
        r"""
        Copy a .conf to C:\OnamVPN (SAFE_CONFIG_DIR) and return the new path.

        WireGuard's tunnel service fails to start when the config path contains
        spaces (e.g. 'CN PROJECT').  Staging to C:\OnamVPN avoids this entirely.
        """
        try:
            SAFE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            dest = SAFE_CONFIG_DIR / config_file.name

            # The WARP path already writes its config straight into
            # SAFE_CONFIG_DIR, so source and destination are the same file.
            # shutil.copy2 onto itself raises WinError 32 ("being used by
            # another process") on Windows, which made every single connect
            # log a warning that looked like a real failure and wasn't — the
            # fallback used the identical path anyway.
            try:
                same_file = dest.exists() and config_file.resolve() == dest.resolve()
            except OSError:
                same_file = False

            if same_file:
                self.logger.debug(f"Config already staged at {dest}")
                return dest

            shutil.copy2(config_file, dest)
            self.logger.info(f"Config staged to: {dest}")
            return dest
        except Exception as e:
            self.logger.warning(f"Could not stage config to {SAFE_CONFIG_DIR}: {e}. Using original path.")
            return config_file

    def _create_wireguard_interface(self, config_file: Path) -> bool:
        """
        Import and activate a WireGuard tunnel using the Windows service mechanism.

        Uses:  wireguard.exe /installtunnelservice <config.conf>

        IMPORTANT:
        - Requires Administrator privileges.
        - Config path MUST NOT contain spaces — always stage via _stage_config().
        - If a tunnel with the same name already exists, uninstall first to avoid
          spurious 'Access is denied' (rc=1).
        """
        # ── Admin check ───────────────────────────────────────────────────────
        if not is_admin():
            self.logger.error(
                "OnamVPN is NOT running as Administrator. "
                "Right-click the app / terminal and choose 'Run as administrator'."
            )
            return False

        if not self.wireguard_path:
            self.logger.error("WireGuard not found — cannot import tunnel.")
            return False

        wireguard_exe = self.wireguard_path / "wireguard.exe"
        if not wireguard_exe.exists():
            self.logger.error(f"wireguard.exe not found at {wireguard_exe}")
            return False

        # ── Stage to space-free path ──────────────────────────────────────────
        staged = self._stage_config(config_file)
        tunnel_name = staged.stem

        # ── Uninstall existing tunnel to prevent false 'Access is denied' ─────
        self.logger.info(f"Removing any existing '{tunnel_name}' tunnel...")
        subprocess.run(
            [str(wireguard_exe), "/uninstalltunnelservice", tunnel_name],
            capture_output=True, text=True, timeout=15,
        )
        time.sleep(1)

        # ── Install ───────────────────────────────────────────────────────────
        self.logger.info(f"Installing: {wireguard_exe} /installtunnelservice \"{staged}\"")
        try:
            result = subprocess.run(
                [str(wireguard_exe), "/installtunnelservice", str(staged)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                self.logger.info(f"Tunnel '{tunnel_name}' installed and activated!")
                return True
            else:
                stderr = result.stderr.strip() or result.stdout.strip() or "(no output)"
                self.logger.error(
                    f"wireguard.exe /installtunnelservice failed "
                    f"(rc={result.returncode}): {stderr}"
                )
                return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timed out waiting for wireguard.exe /installtunnelservice")
            return False
        except Exception as e:
            self.logger.error(f"Failed to create WireGuard interface: {e}")
            return False

    def _remove_wireguard_interface(self, interface_name: str = None) -> bool:
        """
        Stop and uninstall the WireGuard tunnel service.
        Uses:  wireguard.exe /uninstalltunnelservice <tunnel-name>
        """
        tunnel = interface_name or self.TUNNEL_NAME

        if not self.wireguard_path:
            self.logger.error("WireGuard not found — cannot remove tunnel.")
            return False

        wireguard_exe = self.wireguard_path / "wireguard.exe"
        if not wireguard_exe.exists():
            self.logger.error(f"wireguard.exe not found at {wireguard_exe}")
            return False

        self.logger.debug(f"Uninstalling WireGuard tunnel '{tunnel}'...")
        try:
            result = subprocess.run(
                [str(wireguard_exe), "/uninstalltunnelservice", tunnel],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.info(f"Tunnel '{tunnel}' stopped and removed.")
                return True

            stderr = result.stderr.strip() or result.stdout.strip()

            # "Service does not exist" is the normal answer during startup
            # cleanup, which speculatively removes three tunnel names that
            # usually were never installed. Logging that at ERROR made every
            # clean launch print three scary-looking failures, which trains
            # you to ignore the log — and then a real failure goes unnoticed.
            if "does not exist" in stderr.lower():
                self.logger.debug(
                    f"Tunnel '{tunnel}' was not installed — nothing to remove."
                )
                return False

            self.logger.error(
                f"wireguard.exe /uninstalltunnelservice failed "
                f"(rc={result.returncode}): {stderr}"
            )
            return False

        except subprocess.TimeoutExpired:
            self.logger.error("Timed out waiting for wireguard.exe /uninstalltunnelservice")
            return False
        except Exception as e:
            self.logger.error(f"Failed to remove WireGuard interface: {e}")
            return False
    
    def cleanup_stale_configurations(self):
        """Clean up any leftover firewall rules and active tunnel services from previous runs/crashes."""
        self.logger.info("Cleaning up stale WireGuard configurations, tunnels, and firewall rules...")
        try:
            # 1. Disable kill switch firewall rules
            self._disable_kill_switch()
        except Exception as e:
            self.logger.warning(f"Failed to clear kill switch rules during cleanup: {e}")

        try:
            # 2. Disable DNS leak protection rules
            self._disable_dns_leak_protection()
        except Exception as e:
            self.logger.warning(f"Failed to clear DNS leak protection rules during cleanup: {e}")

        # 3. Uninstall any leftover tunnel services
        tunnels_to_remove = [WARP_TUNNEL_NAME, self.TUNNEL_NAME, "OnamVPN-Server"]
        for tunnel in tunnels_to_remove:
            try:
                self._remove_wireguard_interface(tunnel)
            except Exception as e:
                self.logger.warning(f"Failed to remove stale tunnel interface '{tunnel}': {e}")
    
    
    # ── App settings ───────────────────────────────────────────────────────────

    def _load_app_settings(self) -> dict:
        """
        Read the user's saved preferences from config/settings.json so
        connect_to_server() can honor the kill-switch / DNS-leak-protection
        checkboxes instead of always forcing them on.
        """
        settings_file = self.config_dir / "settings.json"
        defaults = {"killswitch": False, "dns_leak_protection": True}
        if not settings_file.exists():
            return defaults
        try:
            with open(settings_file, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
            defaults.update(data)
            return defaults
        except Exception as e:
            self.logger.warning(f"Could not read settings.json ({e}), using defaults")
            return defaults

    # ── Connect / Disconnect ──────────────────────────────────────────────────

    # ── Kill Switch & DNS Leak Protection ────────────────────────────────────

    # Firewall rule name prefix — easy to identify and remove
    _FW_PREFIX = "OnamVPN"

    def _run_ps(self, cmd: str) -> bool:
        """Run a PowerShell command as the current (admin) process."""
        try:
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode != 0 and r.stderr.strip():
                self.logger.warning(f"PS: {r.stderr.strip()[:200]}")
            return r.returncode == 0
        except Exception as e:
            self.logger.warning(f"PowerShell error: {e}")
            return False

    def _enable_kill_switch(self, endpoint_host: str = "162.159.192.0/22") -> None:
        """
        Kill Switch: block ALL outbound traffic except:
          - the WireGuard tunnel interface itself
          - the VPN endpoint (so the tunnel can (re)connect)
          - loopback
        """
        p = self._FW_PREFIX
        cmds = [
            # 1. Block everything outbound
            f'New-NetFirewallRule -DisplayName "{p}-KS-BlockAll" '
            f'-Direction Outbound -Action Block -Profile Any -ErrorAction SilentlyContinue',

            # 2. Allow WireGuard tunnel interface traffic
            f'New-NetFirewallRule -DisplayName "{p}-KS-AllowWG" '
            f'-Direction Outbound -Action Allow '
            f'-InterfaceAlias "{WARP_TUNNEL_NAME}" -Profile Any -ErrorAction SilentlyContinue',

            # 3. Allow UDP to Cloudflare WARP range (so handshake can happen)
            f'New-NetFirewallRule -DisplayName "{p}-KS-AllowEndpoint" '
            f'-Direction Outbound -Action Allow -Protocol UDP '
            f'-RemoteAddress "{endpoint_host}" -RemotePort 2408 '
            f'-Profile Any -ErrorAction SilentlyContinue',

            # 4. Allow loopback
            f'New-NetFirewallRule -DisplayName "{p}-KS-AllowLoopback" '
            f'-Direction Outbound -Action Allow '
            f'-RemoteAddress "127.0.0.0/8" -Profile Any -ErrorAction SilentlyContinue',
        ]
        for cmd in cmds:
            self._run_ps(cmd)
        self.logger.info("Kill switch ENABLED")

    def _disable_kill_switch(self) -> None:
        """Remove all OnamVPN kill-switch firewall rules."""
        p = self._FW_PREFIX
        self._run_ps(
            f'Remove-NetFirewallRule -DisplayName "{p}-KS-*" -ErrorAction SilentlyContinue'
        )
        self.logger.info("Kill switch DISABLED")

    def _enable_dns_leak_protection(self) -> None:
        """
        DNS Leak Protection: block DNS (UDP/TCP port 53) on every interface
        EXCEPT the WireGuard tunnel, so all name resolution goes through
        Cloudflare's encrypted DNS (1.1.1.1 / 1.0.0.1) inside the tunnel.
        """
        p = self._FW_PREFIX

        # Why this is scoped per-adapter rather than "block all, then allow
        # the tunnel":
        #
        # Windows Defender Firewall evaluates Block rules BEFORE Allow rules.
        # The previous version created a blanket block on outbound port 53 and
        # then an Allow scoped to the tunnel interface, expecting the Allow to
        # win. It does not. The blanket Block matched every DNS query
        # including the ones inside the tunnel, so name resolution stopped
        # completely and every lookup failed with ENOTFOUND / DNS_PROBE
        # errors. The VPN looked connected while nothing could resolve.
        #
        # The fix is to make the BLOCK narrow instead of the ALLOW narrow:
        # enumerate the adapters, skip the tunnel, and block DNS on each of
        # the others. No rule then contradicts another, and DNS inside the
        # tunnel is never matched by a Block at all.
        #
        # -ErrorAction SilentlyContinue is kept so an adapter that disappears
        # mid-enumeration does not abort the whole loop.
        script = (
            f'$tunnel = "{WARP_TUNNEL_NAME}"; '
            f'Get-NetAdapter -ErrorAction SilentlyContinue | '
            f'Where-Object {{ $_.Name -ne $tunnel -and '
            f'$_.InterfaceDescription -notmatch "WireGuard|Wintun" }} | '
            f'ForEach-Object {{ '
            f'New-NetFirewallRule -DisplayName "{p}-DNS-Block-UDP-$($_.Name)" '
            f'-Direction Outbound -Action Block -Protocol UDP -RemotePort 53 '
            f'-InterfaceAlias $_.Name -Profile Any '
            f'-ErrorAction SilentlyContinue | Out-Null; '
            f'New-NetFirewallRule -DisplayName "{p}-DNS-Block-TCP-$($_.Name)" '
            f'-Direction Outbound -Action Block -Protocol TCP -RemotePort 53 '
            f'-InterfaceAlias $_.Name -Profile Any '
            f'-ErrorAction SilentlyContinue | Out-Null '
            f'}}'
        )
        self._run_ps(script)
        self.logger.info(
            "DNS leak protection ENABLED (port 53 blocked on physical adapters; "
            "tunnel DNS left reachable)"
        )

    def _disable_dns_leak_protection(self) -> None:
        """Remove all OnamVPN DNS-leak-protection firewall rules."""
        p = self._FW_PREFIX
        self._run_ps(
            f'Remove-NetFirewallRule -DisplayName "{p}-DNS-*" -ErrorAction SilentlyContinue'
        )
        self.logger.info("DNS leak protection DISABLED")

    # ─────────────────────────────────────────────────────────────────────────

    def connect_to_server(self, server_id: str) -> bool:
        """Connect to VPN by activating the Cloudflare WARP tunnel."""

        if self.is_connected:
            self.logger.warning("Already connected")
            return False

        # Find server (used for display name only — all connect via WARP)
        server = next((s for s in self.servers if s['id'] == server_id), None)
        if not server:
            self.logger.error(f"Server {server_id} not found")
            return False

        if not is_admin():
            self.logger.error(
                "OnamVPN must be run as Administrator to manage WireGuard tunnels.\n"
                "Right-click the app and choose 'Run as administrator'."
            )
            return False

        try:
            self.logger.info(f"Connecting to {server['name']} via Cloudflare WARP...")

            # Write the WARP config to C:\OnamVPN (space-free path)
            warp_conf = SAFE_CONFIG_DIR / "wgcf-profile.conf"
            SAFE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            config_content = self.create_wireguard_config(server, WARP_PRIVATE_KEY)
            with open(warp_conf, 'w', encoding='utf-8') as f:
                f.write(config_content)
            self.logger.info(f"WARP config written to {warp_conf}")

            # Also keep project config in sync
            project_conf = self.config_dir / "OnamVPN-eu-frankfurt.conf"
            with open(project_conf, 'w', encoding='utf-8') as f:
                f.write(config_content)

            # Activate the tunnel
            success = self._create_wireguard_interface(warp_conf)

            if success:
                self._active_tunnel_name = WARP_TUNNEL_NAME
                self.is_connected = True
                self.current_server = server
                self.logger.info("Connected! Cloudflare WARP tunnel active.")
                # Enable security features according to the user's saved settings
                app_settings = self._load_app_settings()
                if app_settings.get("killswitch", False):
                    self._enable_kill_switch()
                if app_settings.get("dns_leak_protection", True):
                    self._enable_dns_leak_protection()
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            return False


    
    def disconnect(self) -> bool:
        """Disconnect from current VPN server by uninstalling the tunnel service."""
        if not self.is_connected:
            self.logger.warning("Not connected to any server")
            return False

        try:
            server_name = self.current_server['name'] if self.current_server else "server"
            tunnel_name = getattr(self, '_active_tunnel_name', self.TUNNEL_NAME)

            success = self._remove_wireguard_interface(tunnel_name)

            if success:
                self.is_connected = False
                self.current_server = None
                self._active_tunnel_name = None
                # Remove security firewall rules
                self._disable_kill_switch()
                self._disable_dns_leak_protection()
                self.logger.info(f"Disconnected from {server_name} — tunnel removed.")
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")
            return False
    
    def get_connection_status(self) -> Dict:
        """
        Get current connection status.
        Queries 'wg show' when connected to surface real handshake info.
        """
        status = {
            'connected':      self.is_connected,
            'server':         self.current_server,
            'interface':      None,
            'public_ip':      None,
            'handshake_ago':  None,   # seconds since last handshake, or None
            'handshake_ok':   False,  # True if handshake happened < 180 s ago
        }

        if not self.is_connected or not self.wireguard_path:
            return status

        tunnel_name = getattr(self, '_active_tunnel_name', None)
        client_addr = (self.current_server.get('client_address') or WARP_CLIENT_ADDR) if self.current_server else WARP_CLIENT_ADDR
        if not tunnel_name:
            status['interface'] = 'OnamVPN-Tunnel'
            status['public_ip'] = client_addr.split('/')[0]
            return status

        try:
            wg_exe = self.wireguard_path / 'wg.exe'
            result = subprocess.run(
                [str(wg_exe), 'show', tunnel_name],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0:
                output = result.stdout
                status['interface'] = tunnel_name
                status['public_ip'] = client_addr.split('/')[0]

                # Parse 'latest handshake: X seconds ago' from wg show output
                for line in output.splitlines():
                    line = line.strip()
                    if 'latest handshake' in line.lower():
                        # e.g.  "latest handshake: 14 seconds ago"
                        parts = line.split(':')
                        if len(parts) >= 2:
                            hs_text = parts[1].strip()   # "14 seconds ago"
                            try:
                                secs = int(hs_text.split()[0])
                                status['handshake_ago'] = secs
                                status['handshake_ok']  = secs < 180
                                if not status['handshake_ok']:
                                    self.logger.warning(
                                        f"Last handshake was {secs}s ago — "
                                        "tunnel may be stale. Keys may be mismatched."
                                    )
                            except (ValueError, IndexError):
                                pass
            else:
                # wg show failed — interface may not exist yet
                self.logger.debug(f"wg show {tunnel_name}: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            self.logger.warning("wg show timed out")
        except Exception as e:
            self.logger.debug(f"get_connection_status error: {e}")

        return status
    
    def start_dummy_tcp_server(self, port: int):
        """Start a dummy TCP server for GUI online detection (Windows)"""
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
            self.logger.info(f"Starting REAL WireGuard server on port {port}")
            if not self.wireguard_path:
                self.logger.error("WireGuard not found. Please install WireGuard Windows app.")
                return False
            # Optionally start dummy TCP listener for GUI online status
            if enable_tcp:
                try:
                    self.start_dummy_tcp_server(port)
                except Exception as tcp_err:
                    self.logger.warning(f"Failed to start dummy TCP server: {tcp_err}")
            # Generate server keys
            private_key, public_key = self.generate_keys()

            # ----------------------------------------------------------------
            # KEY EXCHANGE NOTE
            # The [Peer] block below needs the CLIENT'S public key, NOT the
            # server's own key.  At server startup the client key is not yet
            # known, so we leave a placeholder.  After the client generates
            # its key pair (e.g. via generate_keys()), add its public key here
            # and re-activate the tunnel in the WireGuard app.
            # ----------------------------------------------------------------
            server_config = f"""[Interface]
PrivateKey = {private_key}
Address = {SERVER_CIDR}
ListenPort = {port}

# Replace REPLACE_WITH_CLIENT_PUBLIC_KEY with the public key from the client's .conf
[Peer]
PublicKey = REPLACE_WITH_CLIENT_PUBLIC_KEY
AllowedIPs = {CLIENT_ADDR}
"""
            # Save server configuration
            server_config_file = self.config_dir / "OnamVPN-Server.conf"
            with open(server_config_file, 'w', encoding='utf-8') as f:
                f.write(server_config)
            self.logger.info("REAL WireGuard server configuration created!")
            self.logger.info(f"Server public key: {public_key}")
            self.logger.info(f"Configuration saved to: {server_config_file}")
            self.logger.info("")
            self.logger.warning("ACTION REQUIRED: Open OnamVPN-Server.conf and replace")
            self.logger.warning("REPLACE_WITH_CLIENT_PUBLIC_KEY with the client's public key,")
            self.logger.warning("then re-activate the tunnel in the WireGuard app.")
            self.logger.info("")
            self.logger.info("To start the server:")
            self.logger.info("1. Open WireGuard Windows app")
            self.logger.info("2. Click 'Add Tunnel' -> 'Add from file'")
            self.logger.info(f"3. Select: {server_config_file}")
            self.logger.info("4. Edit the tunnel to fill in the client public key")
            self.logger.info("5. Click 'Activate'")
            self.logger.info("")
            self.logger.info("REAL VPN SERVER IS READY!")
            return True
        except Exception as e:
            self.logger.error(f"Server start error: {e}")
            return False
    
    def stop_server(self):
        """Stop WireGuard server"""
        try:
            self.logger.info("Stopping WireGuard server")
            self.logger.info("Please deactivate the server tunnel in WireGuard Windows app")
            self.logger.info("REAL VPN SERVER STOPPED!")
            
        except Exception as e:
            self.logger.error(f"Server stop error: {e}")
    
    def install_wireguard_guide(self):
        """Provide installation guide for WireGuard Windows app"""
        guide = """
🔧 WIREGUARD WINDOWS INSTALLATION GUIDE:

1. Download WireGuard Windows App:
   - Go to: https://www.wireguard.com/install/
   - Download "Windows" version
   - Run the installer as Administrator

2. After Installation:
   - Open WireGuard app from Start Menu
   - You'll see the WireGuard interface

3. Import OnamVPN Configurations:
   - Click "Add Tunnel" -> "Add from file"
   - Select the .conf files created by OnamVPN
   - Click "Activate" to start VPN

4. For Real VPN Functionality:
   - OnamVPN will create .conf files
   - Import them into WireGuard Windows app
   - Click "Activate" for real tunneling

🎯 THIS MAKES ONAMVPN A REAL VPN!
        """
        
        print(guide)
        self.logger.info("WireGuard installation guide provided")


