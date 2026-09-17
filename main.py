#!/usr/bin/env python3
"""
OnamVPN - Local VPN with GUI
Main entry point for the application

Author: Addy
Based on: OnamVPN architecture
"""

import sys
import argparse
import logging
import platform
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

IS_WINDOWS = platform.system().lower() == 'windows'


def _make_console_unicode_safe() -> None:
    """
    Stop a console that cannot encode an emoji from killing the app.

    Windows consoles default to a legacy code page — cp1252 here — and
    printing any character outside it raises UnicodeEncodeError. Several
    status messages in this file start with an emoji, so launching from such
    a console crashed during startup, before any window appeared:

        UnicodeEncodeError: 'charmap' codec can't encode character
        '\\U0001f52c' in position 0

    Reconfiguring to UTF-8 with errors="replace" keeps the messages intact
    where the console supports them and degrades to a replacement character
    where it does not. Losing a decorative glyph is acceptable; refusing to
    start is not.

    This must run before the first print, which is why it is at import time
    rather than inside main().
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # Not a real console (piped, redirected, or already wrapped).
            # Nothing to fix and nothing to break.
            pass


_make_console_unicode_safe()


def _is_admin() -> bool:
    """Return True if the process has Administrator privileges (Windows only check)."""
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin():
    """Re-launch this script with Administrator privileges via UAC prompt (Windows only)."""
    import ctypes
    # ShellExecuteW with verb='runas' triggers the UAC elevation dialog
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )


# ── Auto-elevation: WireGuard tunnel service management requires admin on Windows ──
# If we're not already elevated, show the UAC dialog and relaunch, then exit.
# Exception: --labs opens the offline concept-demo window and requires no
# privileges — skip elevation so the demo can run on any machine.
#
# This check runs before argparse (the elevation decision has to happen at
# import time), so it must match argparse's own parsing — including prefix
# abbreviation, where "--lab" and "--la" are both accepted as "--labs".
# A plain `"--labs" in sys.argv` would miss those and elevate anyway, then
# run Labs mode with Administrator rights it does not need.
def _labs_requested(argv) -> bool:
    """True if any argument is '--labs' or an unambiguous abbreviation of it."""
    for arg in argv[1:]:
        if arg == "--":            # everything after this is positional
            break
        # argparse splits "--labs=x" on the first '='
        name = arg.split("=", 1)[0]
        if name.startswith("--") and len(name) > 2 and "--labs".startswith(name):
            return True
    return False


_LABS_MODE = _labs_requested(sys.argv)
if IS_WINDOWS and not _is_admin() and not _LABS_MODE:
    print("OnamVPN needs Administrator rights to manage WireGuard tunnels.")
    print("Requesting elevation via UAC...")
    _relaunch_as_admin()
    sys.exit(0)
# ───────────────────────────────────────────────────────────────────────────────


from gui.main_window import MainWindow
from vpn_core.logger import setup_logger
from vpn_core.wireguard_handler import WireGuardHandler
from vpn_core.simple_vpn_handler import SimpleVPNHandler
from vpn_core.real_windows_wireguard import RealWindowsWireGuard


def setup_application():
    """Initialize the Qt application with proper settings"""
    app = QApplication(sys.argv)
    app.setApplicationName("OnamVPN")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("OnamVPN")

    # Fusion renders our QSS + QPalette theming identically across platforms
    # (native styles like "windowsvista" ignore large parts of both).
    app.setStyle("Fusion")

    # Enable high DPI scaling
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    return app


def _load_logging_settings(verbose: bool = False):
    """
    Determine effective log level and file-logging preference from
    config/settings.json (log_level, log_to_file), with --verbose always
    forcing DEBUG regardless of the saved setting.
    """
    level = logging.DEBUG if verbose else logging.INFO
    log_to_file = True
    settings_file = project_root / "config" / "settings.json"
    if settings_file.exists():
        try:
            import json
            with open(settings_file, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
            if not verbose:
                level = getattr(logging, str(data.get('log_level', 'INFO')).upper(), logging.INFO)
            log_to_file = bool(data.get('log_to_file', True))
        except Exception:
            pass
    return level, log_to_file


def run_gui_mode(verbose: bool = False):
    """Run the application in GUI mode"""
    print("🚀 Starting OnamVPN GUI...")

    app = setup_application()

    # Setup logging (honors config/settings.json log_level / log_to_file)
    level, log_to_file = _load_logging_settings(verbose)
    setup_logger(level=level, log_to_file=log_to_file)
    logger = logging.getLogger(__name__)
    logger.info("Starting OnamVPN GUI application")

    try:
        # Initialize VPN handler (Windows-specific with REAL VPN)
        if IS_WINDOWS:
            try:
                real_handler = RealWindowsWireGuard()
                if real_handler.test_wireguard_installation():
                    logger.info("Using REAL Windows WireGuard handler")
                    vpn_handler = real_handler
                else:
                    logger.warning("WireGuard not available, showing installation guide")
                    real_handler.install_wireguard_guide()
                    logger.info("Using simple demo handler until WireGuard is installed")
                    vpn_handler = SimpleVPNHandler()
            except Exception as e:
                logger.warning(f"Real Windows WireGuard handler failed: {e}")
                logger.info("Using simple demo handler")
                vpn_handler = SimpleVPNHandler()
        else:
            # Non-Windows systems
            try:
                wg_handler = WireGuardHandler()
                if wg_handler.test_wireguard_installation():
                    logger.info("Using standard WireGuard handler")
                    vpn_handler = wg_handler
                else:
                    logger.warning("WireGuard not available, using simple demo handler")
                    vpn_handler = SimpleVPNHandler()
            except Exception as e:
                logger.warning(f"WireGuard handler failed, using simple demo handler: {e}")
                vpn_handler = SimpleVPNHandler()
        
        # Create and show main window
        window = MainWindow(vpn_handler)
        window.show()
        
        logger.info("GUI application started successfully")
        return app.exec()
        
    except Exception as e:
        logger.error(f"Failed to start GUI: {e}")
        print(f"❌ Error starting GUI: {e}")
        return 1


def run_server_mode(port=51820, enable_tcp=False, verbose: bool = False):
    """Run the application in server mode"""
    print(f"🌐 Starting OnamVPN Server on port {port}...")

    # Setup logging (honors config/settings.json log_level / log_to_file)
    level, log_to_file = _load_logging_settings(verbose)
    setup_logger(level=level, log_to_file=log_to_file)
    logger = logging.getLogger(__name__)
    logger.info(f"Starting OnamVPN server on port {port}")

    try:
        # Initialize VPN handler (Windows-specific with REAL VPN)
        if IS_WINDOWS:
            try:
                real_handler = RealWindowsWireGuard()
                if real_handler.test_wireguard_installation():
                    logger.info("Using REAL Windows WireGuard handler for server")
                    vpn_handler = real_handler
                else:
                    logger.warning("WireGuard not available, showing installation guide")
                    real_handler.install_wireguard_guide()
                    logger.info("Using simple demo handler until WireGuard is installed")
                    vpn_handler = SimpleVPNHandler()
            except Exception as e:
                logger.warning(f"Real Windows WireGuard handler failed: {e}")
                logger.info("Using simple demo handler")
                vpn_handler = SimpleVPNHandler()
        else:
            # Non-Windows systems
            try:
                wg_handler = WireGuardHandler()
                if wg_handler.test_wireguard_installation():
                    logger.info("Using standard WireGuard handler for server")
                    vpn_handler = wg_handler
                else:
                    logger.warning("WireGuard not available, using simple demo handler")
                    vpn_handler = SimpleVPNHandler()
            except Exception as e:
                logger.warning(f"WireGuard handler failed, using simple demo handler: {e}")
                vpn_handler = SimpleVPNHandler()
        
        # Start server
        success = vpn_handler.start_server(port, enable_tcp=enable_tcp)
        if success:
            logger.info("VPN server started successfully")
            print("✅ VPN Server is running!")
            print("Press Ctrl+C to stop the server")
            
            # Keep server running
            import time
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping server...")
                vpn_handler.stop_server()
                logger.info("VPN server stopped")
                print("✅ Server stopped successfully")
        else:
            logger.error("Failed to start VPN server")
            print("❌ Failed to start VPN server")
            return 1
            
    except Exception as e:
        logger.error(f"Server error: {e}")
        print(f"❌ Server error: {e}")
        return 1
    
    return 0


def run_speedtest(verbose: bool = False):
    """Run speed test for available servers"""
    print("🏃 Running speed tests...")

    from vpn_core.speedtest_utils import SpeedTestManager

    level, log_to_file = _load_logging_settings(verbose)
    setup_logger(level=level, log_to_file=log_to_file)
    logger = logging.getLogger(__name__)
    
    try:
        speedtest_manager = SpeedTestManager()
        results = speedtest_manager.test_all_servers()
        
        print("\n📊 Speed Test Results:")
        print("-" * 50)
        for server, result in results.items():
            print(f"{server}: {result['ping']}ms ping, {result['download']:.2f} Mbps")
        
        logger.info("Speed test completed")
        
    except Exception as e:
        logger.error(f"Speed test error: {e}")
        print(f"❌ Speed test error: {e}")
        return 1
    
    return 0


def run_labs_mode(verbose: bool = False):
    """Open the CN+OS Concept Labs window (no admin rights required)."""
    print("🔬 Starting OnamVPN Concept Labs...")

    app = setup_application()

    level, log_to_file = _load_logging_settings(verbose)
    setup_logger(level=level, log_to_file=log_to_file)
    logger = logging.getLogger(__name__)
    logger.info("Starting OnamVPN Concept Labs window")

    try:
        from gui.labs_window import LabsWindow
        window = LabsWindow()
        window.show()
        logger.info("Labs window opened successfully")
        return app.exec()
    except Exception as e:
        logger.error(f"Failed to open Labs window: {e}")
        print(f"❌ Error opening Labs window: {e}")
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="OnamVPN - Local VPN with GUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start GUI client
  python main.py --mode server      # Start VPN server
  python main.py --mode server --port 51821  # Start server on custom port
  python main.py --speedtest        # Run speed tests
        """
    )
    
    parser.add_argument(
        '--mode', 
        choices=['gui', 'server'], 
        default='gui',
        help='Application mode (default: gui)'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=51820,
        help='Server port (default: 51820)'
    )
    
    parser.add_argument(
        '--server', 
        type=str,
        help='Connect to specific server (for GUI mode)'
    )
    
    parser.add_argument(
        '--speedtest', 
        action='store_true',
        help='Run speed tests for all servers'
    )
    
    parser.add_argument(
        '--enable-tcp',
        action='store_true',
        help='Enable dummy TCP server for GUI online detection'
    )

    parser.add_argument(
        '--labs',
        action='store_true',
        help=(
            'Open the CN+OS Concept Labs window instead of the main VPN GUI. '
            'Does not require Administrator rights — safe for offline demo.'
        )
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Handle different modes
    if args.speedtest:
        return run_speedtest(verbose=args.verbose)
    elif args.labs:
        return run_labs_mode(verbose=args.verbose)
    elif args.mode == 'server':
        return run_server_mode(args.port, enable_tcp=args.enable_tcp, verbose=args.verbose)
    else:  # GUI mode (default)
        return run_gui_mode(verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
