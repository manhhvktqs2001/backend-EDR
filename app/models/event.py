# app/models/event.py - FIXED VERSION (loại bỏ OUTPUT clause)
"""
Event Model - Events table mapping
Represents security events from endpoint agents (Fixed for trigger compatibility)
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from sqlalchemy import Column, String, DateTime, Boolean, Integer, BigInteger, Text
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.sql import func
import json

from ..database import Base

class Event(Base):
    """Event model representing security events from agents"""
    
    __tablename__ = 'Events'
    
    # Primary Key - matches BIGINT IDENTITY(1,1) PRIMARY KEY exactly
    EventID = Column(BigInteger, primary_key=True)
    AgentID = Column(UNIQUEIDENTIFIER, nullable=False)
    
    # Event Classification - matches schema column names exactly
    EventType = Column(String(50), nullable=False)
    EventAction = Column(String(50), nullable=False)
    EventTimestamp = Column(DateTime, nullable=False)
    Severity = Column(String(20), default='Info')
    
    # Process Events - matches database schema column names exactly
    ProcessID = Column(Integer)
    ProcessName = Column(String(255))
    ProcessPath = Column(String(500))
    CommandLine = Column(Text)
    ParentPID = Column(Integer)
    ParentProcessName = Column(String(255))
    ProcessUser = Column(String(100))
    ProcessHash = Column(String(128))
    
    # File Events - matches database schema column names exactly
    FilePath = Column(String(500))
    FileName = Column(String(255))
    FileSize = Column(BigInteger)
    FileHash = Column(String(128))
    FileExtension = Column(String(10))
    FileOperation = Column(String(20))
    
    # Network Events - matches database schema column names exactly
    SourceIP = Column(String(45))
    DestinationIP = Column(String(45))
    SourcePort = Column(Integer)
    DestinationPort = Column(Integer)
    Protocol = Column(String(10))
    Direction = Column(String(10))
    
    # Registry Events - matches database schema column names exactly
    RegistryKey = Column(String(500))
    RegistryValueName = Column(String(255))
    RegistryValueData = Column(Text)
    RegistryOperation = Column(String(20))
    
    # Authentication Events - matches database schema column names exactly
    LoginUser = Column(String(100))
    LoginType = Column(String(50))
    LoginResult = Column(String(20))
    
    # Detection Status - matches database schema exactly
    ThreatLevel = Column(String(20), default='None')
    RiskScore = Column(Integer, default=0)
    Analyzed = Column(Boolean, default=False)
    AnalyzedAt = Column(DateTime)
    
    # Raw Data - matches database schema
    RawEventData = Column(Text)
    
    # Metadata - matches DEFAULT GETDATE() - REMOVED OUTPUT CLAUSE
    CreatedAt = Column(DateTime, default=func.getdate())
    
    def __repr__(self):
        return f"<Event(id={self.EventID}, type='{self.EventType}', action='{self.EventAction}', agent={self.AgentID})>"
    
    def to_dict(self, include_raw_data: bool = False) -> Dict:
        """Convert event to dictionary for JSON serialization"""
        data = {
            'event_id': self.EventID,
            'agent_id': str(self.AgentID),
            'event_type': self.EventType,
            'event_action': self.EventAction,
            'event_timestamp': self.EventTimestamp.isoformat() if self.EventTimestamp else None,
            'severity': self.Severity,
            'threat_level': self.ThreatLevel,
            'risk_score': self.RiskScore,
            'analyzed': self.Analyzed,
            'analyzed_at': self.AnalyzedAt.isoformat() if self.AnalyzedAt else None,
            'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None
        }
        
        # Add event-specific fields based on type
        if self.EventType == 'Process':
            data.update({
                'process_id': self.ProcessID,
                'process_name': self.ProcessName,
                'process_path': self.ProcessPath,
                'command_line': self.CommandLine,
                'parent_pid': self.ParentPID,
                'parent_process_name': self.ParentProcessName,
                'process_user': self.ProcessUser,
                'process_hash': self.ProcessHash
            })
        
        elif self.EventType == 'File':
            data.update({
                'file_path': self.FilePath,
                'file_name': self.FileName,
                'file_size': self.FileSize,
                'file_hash': self.FileHash,
                'file_extension': self.FileExtension,
                'file_operation': self.FileOperation
            })
        
        elif self.EventType == 'Network':
            data.update({
                'source_ip': self.SourceIP,
                'destination_ip': self.DestinationIP,
                'source_port': self.SourcePort,
                'destination_port': self.DestinationPort,
                'protocol': self.Protocol,
                'direction': self.Direction
            })
        
        elif self.EventType == 'Registry':
            data.update({
                'registry_key': self.RegistryKey,
                'registry_value_name': self.RegistryValueName,
                'registry_value_data': self.RegistryValueData,
                'registry_operation': self.RegistryOperation
            })
        
        elif self.EventType == 'Authentication':
            data.update({
                'login_user': self.LoginUser,
                'login_type': self.LoginType,
                'login_result': self.LoginResult
            })
        
        # Include raw data if requested
        if include_raw_data and self.RawEventData:
            try:
                data['raw_event_data'] = json.loads(self.RawEventData)
            except (json.JSONDecodeError, TypeError):
                data['raw_event_data'] = self.RawEventData
        
        return data
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists and dashboards"""
        return {
            'event_id': self.EventID,
            'agent_id': str(self.AgentID),
            'event_type': self.EventType,
            'event_action': self.EventAction,
            'event_timestamp': self.EventTimestamp.isoformat() if self.EventTimestamp else None,
            'severity': self.Severity,
            'threat_level': self.ThreatLevel,
            'risk_score': self.RiskScore,
            'primary_indicator': self.get_primary_indicator()
        }
    
    def get_primary_indicator(self) -> Optional[str]:
        """Get the primary indicator for this event type"""
        if self.EventType == 'Process':
            return self.ProcessName or self.ProcessPath
        elif self.EventType == 'File':
            return self.FileName or self.FilePath
        elif self.EventType == 'Network':
            return f"{self.DestinationIP}:{self.DestinationPort}" if self.DestinationIP else None
        elif self.EventType == 'Registry':
            return self.RegistryKey
        elif self.EventType == 'Authentication':
            return self.LoginUser
        return None
    
    def is_suspicious(self) -> bool:
        """Check if event is potentially suspicious"""
        return self.ThreatLevel in ['Suspicious', 'Malicious'] or self.RiskScore >= 50
    
    def is_high_risk(self) -> bool:
        """Check if event is high risk"""
        return self.ThreatLevel == 'Malicious' or self.RiskScore >= 80
    
    def get_event_category(self) -> str:
        """Get event category for classification"""
        categories = {
            'Process': 'Execution',
            'File': 'File System',
            'Network': 'Network Activity',
            'Registry': 'System Configuration',
            'Authentication': 'Access Control'
        }
        return categories.get(self.EventType, 'Unknown')
    
    def update_analysis(self, threat_level: str, risk_score: int, analyzed_by: str = 'System'):
        """Update event analysis results"""
        valid_threat_levels = ['None', 'Suspicious', 'Malicious']
        if threat_level not in valid_threat_levels:
            raise ValueError(f"Invalid threat level: {threat_level}. Must be one of {valid_threat_levels}")
        
        if not (0 <= risk_score <= 100):
            raise ValueError("Risk score must be between 0 and 100")
        
        self.ThreatLevel = threat_level
        self.RiskScore = risk_score
        self.Analyzed = True
        self.AnalyzedAt = datetime.now()  # Changed from func.getdate() to avoid trigger issues
    
    def set_raw_data(self, raw_data: Dict):
        """Set raw event data as JSON"""
        try:
            self.RawEventData = json.dumps(raw_data)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid raw data format: {e}")
    
    def get_raw_data(self) -> Optional[Dict]:
        """Get raw event data as dictionary"""
        if not self.RawEventData:
            return None
        try:
            return json.loads(self.RawEventData)
        except (json.JSONDecodeError, TypeError):
            return None
    
    @classmethod
    def create_event(cls, agent_id: str, event_type: str, event_action: str, 
                    event_timestamp: datetime, **kwargs):
        """Create new event instance with validation - FIXED for trigger compatibility"""
        # Validate required fields
        if not agent_id:
            raise ValueError("Agent ID is required")
        if not event_type:
            raise ValueError("Event type is required")
        if not event_action:
            raise ValueError("Event action is required")
        if not event_timestamp:
            raise ValueError("Event timestamp is required")
        
        # Validate event type
        valid_types = ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
        if event_type not in valid_types:
            raise ValueError(f"Invalid event type: {event_type}. Must be one of {valid_types}")
        
        # Create event without OUTPUT clause dependencies
        event = cls(
            AgentID=agent_id,
            EventType=event_type,
            EventAction=event_action,
            EventTimestamp=event_timestamp,
            **kwargs
        )
        return event
    
    @classmethod
    def get_by_agent(cls, session, agent_id: str, limit: int = 100):
        """Get events for specific agent"""
        return session.query(cls).filter(
            cls.AgentID == agent_id
        ).order_by(cls.EventTimestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_recent_events(cls, session, hours: int = 24, limit: int = 1000):
        """Get recent events within specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return session.query(cls).filter(
            cls.EventTimestamp >= cutoff_time
        ).order_by(cls.EventTimestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_suspicious_events(cls, session, hours: int = 24):
        """Get suspicious events within specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return session.query(cls).filter(
            cls.EventTimestamp >= cutoff_time,
            cls.ThreatLevel.in_(['Suspicious', 'Malicious'])
        ).order_by(cls.RiskScore.desc()).all()
    
    @classmethod
    def get_events_by_type(cls, session, event_type: str, hours: int = 24):
        """Get events by type within specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return session.query(cls).filter(
            cls.EventType == event_type,
            cls.EventTimestamp >= cutoff_time
        ).order_by(cls.EventTimestamp.desc()).all()
    
    @classmethod
    def get_unanalyzed_events(cls, session, limit: int = 1000):
        """Get events that haven't been analyzed yet"""
        return session.query(cls).filter(
            cls.Analyzed == False
        ).order_by(cls.CreatedAt.asc()).limit(limit).all()
    
    @classmethod
    def get_events_summary(cls, session, hours: int = 24) -> Dict:
        """Get summary statistics for events"""
        from sqlalchemy import func as sql_func
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Total events
        total = session.query(sql_func.count(cls.EventID)).filter(
            cls.EventTimestamp >= cutoff_time
        ).scalar() or 0
        
        # Events by type
        type_breakdown = session.query(
            cls.EventType,
            sql_func.count(cls.EventID).label('count')
        ).filter(
            cls.EventTimestamp >= cutoff_time
        ).group_by(cls.EventType).all()
        
        # Events by severity
        severity_breakdown = session.query(
            cls.Severity,
            sql_func.count(cls.EventID).label('count')
        ).filter(
            cls.EventTimestamp >= cutoff_time
        ).group_by(cls.Severity).all()
        
        # Threat level breakdown
        threat_breakdown = session.query(
            cls.ThreatLevel,
            sql_func.count(cls.EventID).label('count')
        ).filter(
            cls.EventTimestamp >= cutoff_time
        ).group_by(cls.ThreatLevel).all()
        
        return {
            'total_events': total,
            'time_range_hours': hours,
            'type_breakdown': {event_type: count for event_type, count in type_breakdown},
            'severity_breakdown': {severity: count for severity, count in severity_breakdown},
            'threat_breakdown': {threat: count for threat, count in threat_breakdown},
            'analyzed_count': session.query(sql_func.count(cls.EventID)).filter(
                cls.EventTimestamp >= cutoff_time,
                cls.Analyzed == True
            ).scalar() or 0
        }