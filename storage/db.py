"""
Database storage for events and alerts.
Uses SQLite for persistent storage.
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from core.logger import get_logger

logger = get_logger(__name__)


class Database:
    """SQLite database manager for NetGUI."""
    
    def __init__(self):
        """Initialize database connection and schema."""
        self.db_path = Path.home() / ".netgui" / "netgui.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = None
        self._connect()
        self._create_schema()
        
        logger.info(f"Database initialized at {self.db_path}")
    
    def _connect(self) -> None:
        """Establish database connection."""
        try:
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            logger.debug("Database connection established")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def _create_schema(self) -> None:
        """Create database schema if it doesn't exist."""
        try:
            cursor = self.conn.cursor()
            
            # Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    term TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    explanation TEXT,
                    metadata TEXT,
                    timestamp REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            
            self.conn.commit()
            logger.info("Database schema created/verified")
            
        except Exception as e:
            logger.error(f"Failed to create database schema: {e}")
            raise
    
    def insert_event(self, event: Dict[str, Any]) -> int:
        """
        Insert network event into database.
        
        Args:
            event: Event dictionary
        
        Returns:
            ID of inserted event
        """
        try:
            cursor = self.conn.cursor()
            
            # Extract key fields
            timestamp = event.get('timestamp', 0)
            protocol = event.get('protocol', 'UNKNOWN')
            src_ip = event.get('src_ip', '')
            dst_ip = event.get('dst_ip', '')
            src_port = event.get('src_port', 0)
            dst_port = event.get('dst_port', 0)
            
            # Store remaining fields as JSON
            metadata = json.dumps({k: v for k, v in event.items() 
                                  if k not in ['timestamp', 'protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port']})
            
            cursor.execute("""
                INSERT INTO events (timestamp, protocol, src_ip, dst_ip, src_port, dst_port, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, protocol, src_ip, dst_ip, src_port, dst_port, metadata))
            
            self.conn.commit()
            return cursor.lastrowid
            
        except Exception as e:
            logger.error(f"Failed to insert event: {e}")
            return -1
    
    def insert_alert(self, alert: Dict[str, Any]) -> int:
        """
        Insert alert into database.
        
        Args:
            alert: Alert dictionary
        
        Returns:
            ID of inserted alert
        """
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (term, count, severity, explanation, metadata, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alert.get('term', ''),
                alert.get('count', 0),
                alert.get('severity', 'low'),
                alert.get('explanation', ''),
                json.dumps(alert.get('metadata', {})),
                alert.get('timestamp', 0)
            ))
            
            self.conn.commit()
            return cursor.lastrowid
            
        except Exception as e:
            logger.error(f"Failed to insert alert: {e}")
            return -1
    
    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieve recent alerts from database.
        
        Args:
            limit: Maximum number of alerts to retrieve
        
        Returns:
            List of alert dictionaries
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            alerts = []
            
            for row in rows:
                alert = dict(row)
                alert['metadata'] = json.loads(alert['metadata'])
                alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to retrieve alerts: {e}")
            return []
    
    def get_event_count(self) -> int:
        """Get total number of events."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to get event count: {e}")
            return 0
    
    def get_alert_count(self) -> int:
        """Get total number of alerts."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to get alert count: {e}")
            return 0
    
    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")