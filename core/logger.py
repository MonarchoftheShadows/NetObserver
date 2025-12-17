"""
Logging configuration for NetGUI application.
Provides structured logging with file and console output.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


def setup_logger(log_level: int = logging.INFO) -> logging.Logger:
    """
    Setup application-wide logger with file and console handlers.
    
    Args:
        log_level: Logging level (default: INFO)
    
    Returns:
        Configured root logger
    """
    # Create logs directory
    log_dir = Path.home() / ".netgui" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create log filename with timestamp
    log_file = log_dir / f"netgui_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # Log everything to file
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    logger.info(f"Logging initialized - Log file: {log_file}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)