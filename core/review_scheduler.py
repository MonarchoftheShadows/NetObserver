"""
Whitelist review scheduler with in-app reminders.
"""

from datetime import datetime
from typing import Optional
from PyQt6.QtCore import QTimer, QObject, pyqtSignal

from core.logger import get_logger

logger = get_logger(__name__)


class ReviewScheduler(QObject):
    """
    Manages whitelist review reminders.
    """
    
    review_due = pyqtSignal()  # Emitted when review is due
    
    def __init__(self, whitelist_manager):
        """
        Initialize review scheduler.
        
        Args:
            whitelist_manager: WhitelistManager instance
        """
        super().__init__()
        self.whitelist_manager = whitelist_manager
        
        # Check for due review on startup
        self.check_timer = QTimer()
        self.check_timer.timeout.connect(self._check_review)
        self.check_timer.start(3600000)  # Check every hour
        
        # Check immediately on startup
        QTimer.singleShot(5000, self._check_review)  # 5 seconds after startup
        
        logger.info("Review scheduler initialized")
    
    def _check_review(self) -> None:
        """Check if review is due and emit signal."""
        if self.whitelist_manager.check_review_due():
            logger.info("Whitelist review is due")
            self.review_due.emit()