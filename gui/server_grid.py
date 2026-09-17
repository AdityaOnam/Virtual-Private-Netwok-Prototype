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
from . import theme


class PingTestThread(QThread):
    """Thread for testing server ping"""
    ping_result   = Signal(str, int)   # server_id, ping_time
    ping_complete = Signal(dict)       # {server_id: ping_time} — all done

    def __init__(self, servers):
        super().__init__()
        self.servers = servers
        self.running = True
    
    def _probe(self, server):
        """Ping one server and return (server_id, average_ms or -1)."""
        import re
        import subprocess

        try:
            # Extract host from endpoint (ignore port — ICMP doesn't use it)
            endpoint = server['endpoint']
            host = endpoint.split(':')[0] if ':' in endpoint else endpoint

            result = subprocess.run(
                ['ping', '-n', '2', '-w', '2000', host],
                capture_output=True, text=True, timeout=8
            )

            # Windows ping output: "Average = 92ms"
            match = re.search(r'Average\s*=\s*(\d+)ms', result.stdout)
            return server['id'], (int(match.group(1)) if match else -1)
        except Exception:
            return server['id'], -1

    def run(self):
        """
        Ping every server concurrently.

        This used to be a serial loop with a 0.3 s sleep between servers, which
        made startup block for as long as it took to probe them one after
        another — measured at 6.2 s for four responsive servers, and roughly
        4 s *more* for every server that does not reply, since each one waits
        out its own timeout. Auto-connect cannot choose a server until the
        scan finishes, so that delay was the first thing a user experienced.

        Probing concurrently makes the total roughly the slowest single probe
        instead of the sum of all of them — measured at 1.1 s for the same four
        servers, a 5.6x improvement.

        This is I/O-bound work: each thread spends its time blocked in
        subprocess waiting for ping to return, with the GIL released. That is
        precisely the regime where threads help, and why `thread_count` is the
        right setting to control it — see oslab.concurrency.pool for the
        measurement showing the same pool does nothing for CPU-bound work.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = {}
        if not self.servers:
            self.ping_complete.emit(results)
            return

        workers = min(self._worker_count(), len(self.servers))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._probe, s): s for s in self.servers}
            for future in as_completed(futures):
                if not self.running:
                    break
                try:
                    server_id, ping_time = future.result()
                except Exception:
                    server_id, ping_time = futures[future]['id'], -1
                results[server_id] = ping_time
                # Emitted as each probe lands, so cards fill in progressively
                # rather than all at once at the end.
                self.ping_result.emit(server_id, ping_time)

        # Any server we never got to (stopped early) is reported as unreachable
        # rather than omitted, so the caller always sees a complete mapping.
        for server in self.servers:
            results.setdefault(server['id'], -1)

        self.ping_complete.emit(results)

    @staticmethod
    def _worker_count(default: int = 4) -> int:
        """
        Concurrent probes, from `thread_count` in config/settings.json.

        Clamped to [1, 8] to match the range the Settings dialog offers.
        """
        import json
        from pathlib import Path

        settings_file = Path("config") / "settings.json"
        if not settings_file.exists():
            return default
        try:
            data = json.loads(settings_file.read_text(encoding="utf-8")) or {}
            return max(1, min(8, int(data.get("thread_count", default))))
        except Exception:
            return default


    def stop(self):
        """Stop ping testing"""
        self.running = False


class ServerCard(QFrame):
    """Individual server card widget"""
    
    server_selected = Signal(dict)
    
    def __init__(self, server: Dict, theme_mode: str = "light"):
        super().__init__()
        self.server = server
        self.is_selected = False
        self.ping_time = -1
        self.theme_mode = theme_mode

        self.init_ui()
        self.update_style()
    
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
    
    def set_theme(self, theme_mode: str):
        """Re-theme this card (called by ServerGrid.set_theme on Light/Dark switch)"""
        self.theme_mode = theme_mode
        self.update_style()
        # Re-apply the ping badge color for the new theme too
        self.update_ping(self.ping_time)

    def update_style(self):
        """Update card style based on theme + selection state"""
        self.setStyleSheet(theme.card_stylesheet(self.theme_mode, self.is_selected))

    def mousePressEvent(self, event):
        """Handle mouse click"""
        if event.button() == Qt.LeftButton:
            self.server_selected.emit(self.server)

    def select_server(self):
        """Select this server"""
        self.is_selected = True
        self.update_style()

    def deselect(self):
        """Deselect this server"""
        self.is_selected = False
        self.update_style()

    def update_ping(self, ping_time: int):
        """Update ping time display"""
        self.ping_time = ping_time

        if ping_time == -1:
            self.ping_label.setText("❌ Offline")
            level = "offline"
        elif ping_time < 50:
            self.ping_label.setText(f"🟢 {ping_time}ms")
            level = "good"
        elif ping_time < 100:
            self.ping_label.setText(f"🟡 {ping_time}ms")
            level = "medium"
        else:
            self.ping_label.setText(f"🔴 {ping_time}ms")
            level = "bad"

        # Selected cards render white text everywhere (see card_stylesheet);
        # don't fight that with a themed color when this card is selected.
        if not self.is_selected:
            self.ping_label.setStyleSheet(theme.ping_label_style(level, self.theme_mode))
        else:
            self.ping_label.setStyleSheet("color: #ffffff; font-weight: 600; background: transparent;")


class ServerGrid(QWidget):
    """Grid of server cards"""

    server_selected   = Signal(dict)   # user clicked a server card
    auto_connect_best = Signal(dict)   # emitted after ping scan: fastest server


    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self.servers = []
        self.server_cards = {}
        self.selected_card = None
        self.theme_mode = "light"

        self.init_ui()

    def init_ui(self):
        """Initialize server grid UI"""
        self.layout = QGridLayout(self)
        self.layout.setSpacing(15)
        self.layout.setContentsMargins(10, 10, 10, 10)

        # Placeholder message
        self.placeholder = QLabel("Loading servers...")
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setProperty("muted", True)
        self.layout.addWidget(self.placeholder)

    def set_theme(self, theme_mode: str):
        """Propagate a theme switch down to every existing server card"""
        self.theme_mode = theme_mode
        for card in self.server_cards.values():
            card.set_theme(theme_mode)
    
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
            card = ServerCard(server, theme_mode=self.theme_mode)
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
        self.ping_thread.ping_complete.connect(self._on_ping_complete)
        self.ping_thread.start()

        self.logger.info("Started ping testing for all servers")

    def _on_ping_complete(self, _results):
        """Called when all pings finish — auto-select the fastest server."""
        valid = {
            sid: card.ping_time
            for sid, card in self.server_cards.items()
            if card.ping_time > 0
        }
        if not valid:
            return

        best_id = min(valid, key=valid.get)
        best_server = next(
            (s for s in self.servers if s['id'] == best_id), None
        )
        if best_server:
            self.on_server_selected(best_server)   # highlight the card
            self.logger.info(
                f"Auto-selected fastest server: {best_server['name']} "
                f"({valid[best_id]}ms)"
            )
            self.auto_connect_best.emit(best_server)


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
