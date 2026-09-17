"""
Centralized theme system for OnamVPN.

Every widget in the app pulls its colors from here instead of hardcoding
hex values, so switching Light/Dark actually reaches every widget
(including dialogs and server cards) instead of just the main window.
"""

from PySide6.QtGui import QPalette, QColor

PALETTES = {
    "light": {
        "bg":          "#f5f6fa",
        "surface":     "#ffffff",
        "surface_alt": "#eef0f5",
        "border":      "#dde1e8",
        "text":        "#1f2430",
        "text_muted":  "#6b7280",
        "accent":      "#4f46e5",
        "accent_hover":"#4338ca",
        "success":     "#16a34a",
        "success_hover":"#15803d",
        "danger":      "#dc2626",
        "danger_hover":"#b91c1c",
        "warning":     "#d97706",
        "info":        "#2563eb",
        "info_hover":  "#1d4ed8",
        "disabled":    "#c2c7d0",
        "disabled_text":"#8a8f99",
    },
    "dark": {
        "bg":          "#15161c",
        "surface":     "#1d1f28",
        "surface_alt": "#262834",
        "border":      "#33364a",
        "text":        "#e7e9f2",
        "text_muted":  "#9aa0b2",
        "accent":      "#818cf8",
        "accent_hover":"#a5b4fc",
        "success":     "#22c55e",
        "success_hover":"#4ade80",
        "danger":      "#f87171",
        "danger_hover":"#fca5a5",
        "warning":     "#fbbf24",
        "info":        "#60a5fa",
        "info_hover":  "#93c5fd",
        "disabled":    "#3a3d4d",
        "disabled_text":"#6b6f80",
    },
}

PING_COLORS = {
    "good":    {"light": "#16a34a", "dark": "#4ade80"},
    "medium":  {"light": "#d97706", "dark": "#fbbf24"},
    "bad":     {"light": "#dc2626", "dark": "#f87171"},
    "offline": {"light": "#9ca3af", "dark": "#6b7280"},
}


def normalize(mode: str) -> str:
    mode = (mode or "light").lower()
    return "dark" if mode == "dark" else "light"


def palette(mode: str) -> dict:
    return PALETTES[normalize(mode)]


def apply_qpalette(app, mode: str):
    """Set the QApplication QPalette so native dialogs (QMessageBox, QFileDialog,
    QColorDialog...) also follow the theme, not just our own QSS-styled widgets."""
    p = palette(mode)
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(p["bg"]))
    pal.setColor(QPalette.WindowText, QColor(p["text"]))
    pal.setColor(QPalette.Base, QColor(p["surface"]))
    pal.setColor(QPalette.AlternateBase, QColor(p["surface_alt"]))
    pal.setColor(QPalette.ToolTipBase, QColor(p["surface"]))
    pal.setColor(QPalette.ToolTipText, QColor(p["text"]))
    pal.setColor(QPalette.Text, QColor(p["text"]))
    pal.setColor(QPalette.Button, QColor(p["surface"]))
    pal.setColor(QPalette.ButtonText, QColor(p["text"]))
    pal.setColor(QPalette.Highlight, QColor(p["accent"]))
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.PlaceholderText, QColor(p["text_muted"]))
    pal.setColor(QPalette.Disabled, QPalette.WindowText, QColor(p["disabled_text"]))
    pal.setColor(QPalette.Disabled, QPalette.Text, QColor(p["disabled_text"]))
    pal.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(p["disabled_text"]))
    app.setPalette(pal)


def app_stylesheet(mode: str) -> str:
    """
    One QSS blob applied at the QApplication level, so it reaches every
    top-level window (MainWindow, SettingsPanel dialog, message boxes, etc.)
    without each of them needing to re-implement theming.
    """
    p = palette(mode)
    return f"""
    QMainWindow, QDialog {{
        background-color: {p['bg']};
    }}

    QWidget {{
        color: {p['text']};
        font-family: "Segoe UI", "Inter", sans-serif;
    }}

    QLabel {{
        color: {p['text']};
        background: transparent;
    }}

    QLabel#titleLabel {{
        color: {p['accent']};
        margin: 4px;
    }}

    QLabel#subtitleLabel, QLabel[muted="true"] {{
        color: {p['text_muted']};
    }}

    QGroupBox {{
        background-color: {p['surface']};
        border: 1px solid {p['border']};
        border-radius: 10px;
        font-weight: 600;
        margin-top: 14px;
        padding-top: 14px;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 6px;
        color: {p['text']};
    }}

    QScrollArea {{
        background: transparent;
        border: none;
    }}
    QScrollArea > QWidget > QWidget {{
        background: transparent;
    }}

    QStatusBar {{
        background: transparent;
        color: {p['text_muted']};
    }}

    QPushButton {{
        background-color: {p['surface_alt']};
        color: {p['text']};
        border: 1px solid {p['border']};
        border-radius: 8px;
        padding: 8px 16px;
        font-weight: 600;
    }}
    QPushButton:hover {{ border-color: {p['accent']}; }}
    QPushButton:disabled {{
        background-color: {p['disabled']};
        color: {p['disabled_text']};
        border-color: {p['disabled']};
    }}

    QPushButton[variant="primary"] {{
        background-color: {p['success']};
        color: #ffffff;
        border: none;
    }}
    QPushButton[variant="primary"]:hover {{ background-color: {p['success_hover']}; }}

    QPushButton[variant="danger"] {{
        background-color: {p['danger']};
        color: #ffffff;
        border: none;
    }}
    QPushButton[variant="danger"]:hover {{ background-color: {p['danger_hover']}; }}

    QPushButton[variant="info"] {{
        background-color: {p['info']};
        color: #ffffff;
        border: none;
    }}
    QPushButton[variant="info"]:hover {{ background-color: {p['info_hover']}; }}

    QPushButton[variant="ghost"] {{
        background-color: transparent;
        color: {p['text_muted']};
        border: 1px solid {p['border']};
    }}
    QPushButton[variant="ghost"]:hover {{ color: {p['text']}; border-color: {p['accent']}; }}

    QLineEdit, QComboBox, QSpinBox, QTextEdit {{
        background-color: {p['surface_alt']};
        color: {p['text']};
        border: 1px solid {p['border']};
        border-radius: 6px;
        padding: 5px 8px;
        selection-background-color: {p['accent']};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
        border-color: {p['accent']};
    }}
    QComboBox::drop-down {{ border: none; }}
    QComboBox QAbstractItemView {{
        background-color: {p['surface']};
        color: {p['text']};
        selection-background-color: {p['accent']};
        selection-color: #ffffff;
        border: 1px solid {p['border']};
    }}

    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{
        width: 16px; height: 16px;
        border: 1px solid {p['border']};
        border-radius: 4px;
        background: {p['surface_alt']};
    }}
    QCheckBox::indicator:checked {{
        background: {p['accent']};
        border-color: {p['accent']};
    }}

    QTabWidget::pane {{
        border: 1px solid {p['border']};
        border-radius: 8px;
        background: {p['surface']};
        top: -1px;
    }}
    QTabBar::tab {{
        background: transparent;
        color: {p['text_muted']};
        padding: 8px 16px;
        border: none;
        font-weight: 600;
    }}
    QTabBar::tab:selected {{
        color: {p['accent']};
        border-bottom: 2px solid {p['accent']};
    }}
    QTabBar::tab:hover {{ color: {p['text']}; }}

    QProgressBar {{
        background-color: {p['surface_alt']};
        border: none;
        border-radius: 4px;
        height: 8px;
    }}
    QProgressBar::chunk {{
        background-color: {p['accent']};
        border-radius: 4px;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {p['border']};
        border-radius: 5px;
        min-height: 24px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {p['accent']}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    """


def card_stylesheet(mode: str, selected: bool) -> str:
    """Stylesheet for an individual ServerCard — theme + selection aware."""
    p = palette(mode)
    if selected:
        return f"""
            QFrame {{
                background-color: {p['accent']};
                border: 2px solid {p['accent_hover']};
                border-radius: 10px;
            }}
            QLabel {{ color: #ffffff; background: transparent; }}
        """
    return f"""
        QFrame {{
            background-color: {p['surface']};
            border: 1px solid {p['border']};
            border-radius: 10px;
        }}
        QFrame:hover {{
            border: 1px solid {p['accent']};
            background-color: {p['surface_alt']};
        }}
        QLabel {{ color: {p['text']}; background: transparent; }}
    """


def ping_label_style(level: str, mode: str) -> str:
    color = PING_COLORS.get(level, PING_COLORS["offline"])[normalize(mode)]
    return f"color: {color}; font-weight: 600; background: transparent;"


def set_variant(button, variant: str):
    """Tag a QPushButton with a semantic variant and force Qt to re-evaluate
    the [variant=...] QSS selector immediately."""
    button.setProperty("variant", variant)
    button.style().unpolish(button)
    button.style().polish(button)
