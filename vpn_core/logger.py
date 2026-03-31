"""
Logging utilities for OnamVPN
"""

import logging
import logging.handlers
import os
from pathlib import Path
from datetime import datetime


def setup_logger(name="OnamVPN", level=logging.INFO):
    """
    Setup logging configuration for the application
    
    Args:
        name (str): Logger name
        level (int): Logging level
    """
    
    # Create logs directory
    if os.name == 'nt':  # Windows
        log_dir = Path(os.environ.get('APPDATA', '')) / 'OnamVPN' / 'logs'
    else:  # macOS/Linux
        log_dir = Path.home() / '.local' / 'share' / 'OnamVPN' / 'logs'
    
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
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
