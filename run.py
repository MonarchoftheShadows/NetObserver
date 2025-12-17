#!/usr/bin/env python3
"""
NetObserver - Defensive Network Visibility & Incident Response Tool
Entry point for the application.
"""

import sys
import os
from PyQt6.QtWidgets import QApplication

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.logger import setup_logger
from core.orchestrator import Orchestrator
from ui.main_window import MainWindow


def main():
    """Main application entry point."""
    # Setup logging
    logger = setup_logger()
    logger.info("Starting NetObserver - Defensive Network Visibility Tool")
    
    # Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("NetObserver")
    app.setOrganizationName("DefensiveSec")
    
    # Create orchestrator (central coordinator)
    orchestrator = Orchestrator()
    
    # Create and show main window
    window = MainWindow(orchestrator)
    window.show()
    
    logger.info("Application window displayed")
    
    # Start event loop
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
