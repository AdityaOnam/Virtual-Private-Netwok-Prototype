"""
Logging utilities for OnamVPN
"""

import logging
import logging.handlers
import os
from pathlib import Path
from datetime import datetime


def setup_logger(name="OnamVPN", level=logging.INFO, log_to_file=True):
    """
    Setup logging configuration for the application

    Args:
        name (str): Logger name
        level (int): Logging level
        log_to_file (bool): Whether to also write rotating log files to disk
    """

    # Configure the ROOT logger, not a logger named `name`.
    #
    # Every module in this project obtains its logger with
    # get_logger(__name__), producing names like
    # "vpn_core.real_windows_wireguard" and "gui.main_window". Those are not
    # descendants of "OnamVPN", so records logged through them propagate to
    # the root logger and never reach a handler attached to "OnamVPN".
    #
    # The effect was that file logging silently did nothing: every file in
    # %APPDATA%\OnamVPN\logs was 0 bytes, going back months, while the console
    # output looked fine because the root logger had a default handler. That
    # left no diagnostics at all for the one failure mode that most needs them
    # — a connection that goes wrong on a user's machine.
    #
    # Attaching to root means every module's records are captured, whatever
    # they call their logger.
    logger = logging.getLogger()
    logger.setLevel(level)

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_to_file:
        # Create logs directory
        if os.name == 'nt':  # Windows
            log_dir = Path(os.environ.get('APPDATA', '')) / 'OnamVPN' / 'logs'
        else:  # macOS/Linux
            log_dir = Path.home() / '.local' / 'share' / 'OnamVPN' / 'logs'

        log_dir.mkdir(parents=True, exist_ok=True)

        # File handler with rotation
        log_file = log_dir / f"onamvpn_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name="OnamVPN"):
    """Get a logger instance"""
    return logging.getLogger(name)
