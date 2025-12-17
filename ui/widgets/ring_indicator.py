"""
Ring indicator widget - circular progress indicator with threat level.
Shows 100% when safe, decreases as threat increases.
"""

from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QFont

from core.logger import get_logger

logger = get_logger(__name__)


class RingIndicator(QWidget):
    """
    Circular ring indicator showing threat level percentage.
    100% = Safe (Green), decreases to 0% = Critical (Red)
    """
    
    threshold_crossed = pyqtSignal(str)  # Emits severity level
    
    def __init__(self, parent=None):
        """Initialize ring indicator."""
        super().__init__(parent)
        self.setMinimumSize(250, 250)
        
        self.value = 100  # Start at 100% (safe)
        self.ring_color = QColor(0, 255, 0)  # Green
        
        # Severity thresholds (inverted - higher value = safer)
        self.thresholds = {
            'safe': (85, 100, QColor(0, 255, 0)),        # Green 85-100%
            'caution': (70, 85, QColor(255, 255, 0)),    # Yellow 70-85%
            'elevated': (50, 70, QColor(255, 170, 0)),   # Orange 50-70%
            'high_risk': (25, 50, QColor(255, 100, 0)),  # Dark Orange 25-50%
            'critical': (0, 25, QColor(255, 0, 0))       # Red 0-25%
        }
        
        self.current_severity = 'safe'
        
        logger.debug("Ring indicator initialized")
    
    def set_value(self, threat_score: int) -> None:
        """
        Set threat level value (inverted to show safety percentage).
        
        Args:
            threat_score: Threat score from 0 (safe) to 100 (critical)
        """
        # Invert: high threat = low percentage shown
        self.value = max(0, min(100, 100 - threat_score))
        
        # Update color based on value
        old_severity = self.current_severity
        
        for severity, (min_val, max_val, color) in self.thresholds.items():
            if min_val <= self.value < max_val:
                self.ring_color = color
                self.current_severity = severity
                break
        
        # Handle exactly 100%
        if self.value == 100:
            self.ring_color = QColor(0, 255, 0)
            self.current_severity = 'safe'
        
        # Emit signal if severity changed
        if old_severity != self.current_severity:
            self.threshold_crossed.emit(self.current_severity)
            logger.info(f"Threat level changed: {self.current_severity} ({self.value}%)")
        
        self.update()
    
    def paintEvent(self, event):
        """Custom paint event to draw the ring."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Calculate dimensions
        width = self.width()
        height = self.height()
        size = min(width, height)
        
        # Center the ring
        x = (width - size) // 2
        y = (height - size) // 2
        
        # Draw background circle
        painter.setPen(QPen(QColor(50, 50, 50), 15))
        painter.drawEllipse(x + 10, y + 10, size - 20, size - 20)
        
        # Draw value ring
        painter.setPen(QPen(self.ring_color, 15))
        span_angle = int(self.value * 360 / 100) * 16  # Qt uses 1/16th degree units
        painter.drawArc(x + 10, y + 10, size - 20, size - 20, 90 * 16, -span_angle)
        
        # Draw center circle with value
        center_size = size - 80
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255))
        painter.drawEllipse(x + 40, y + 40, center_size, center_size)
        
        # Draw text
        painter.setPen(QColor(0, 0, 0))
        font = QFont("Arial", max(12, size // 10), QFont.Weight.Bold)
        painter.setFont(font)
        
        text_rect = painter.boundingRect(x + 40, y + 40, center_size, center_size,
                                        Qt.AlignmentFlag.AlignCenter, f"{self.value}%")
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, f"{self.value}%")
        
        # Draw severity label
        severity_font = QFont("Arial", max(8, size // 20))
        painter.setFont(severity_font)
        severity_text = self.current_severity.replace('_', ' ').upper()
        severity_rect = painter.boundingRect(x + 40, y + 40 + center_size // 2, 
                                            center_size, center_size // 2,
                                            Qt.AlignmentFlag.AlignCenter, 
                                            severity_text)
        painter.drawText(severity_rect, Qt.AlignmentFlag.AlignCenter, severity_text)