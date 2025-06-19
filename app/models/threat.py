# app/models/threat.py - Complete Threat Model (Database Schema Compliant)
"""
Threat Model - Threats table mapping
Represents threat intelligence indicators
"""

from datetime import datetime
from typing import Optional, Dict, List
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text, Numeric
from sqlalchemy.sql import func

from ..database import Base

class Threat(Base):
    """Threat model representing threat intelligence indicators"""
    
    __tablename__ = 'Threats'
    
    # Primary Key - matches INT IDENTITY(1,1) PRIMARY KEY exactly
    ThreatID = Column(Integer, primary_key=True)
    
    # Basic Information - matches database schema column names exactly
    ThreatName = Column(String(255), nullable=False)
    ThreatType = Column(String(50), nullable=False)
    ThreatValue = Column(Text, nullable=False)
    ThreatCategory = Column(String(50))
    Severity = Column(String(20), nullable=False, default='Medium')
    Description = Column(Text)
    
    # MITRE ATT&CK Framework - matches database schema exactly
    MitreTactic = Column(String(100))
    MitreTechnique = Column(String(100))
    
    # Source Information - matches database schema exactly
    Platform = Column(String(50), default='All')
    ThreatSource = Column(String(100))
    Confidence = Column(Numeric(3, 2), default=0.5)
    
    # Status - matches BIT DEFAULT 1
    IsActive = Column(Boolean, default=True)
    
    # Metadata - matches DEFAULT GETDATE()
    CreatedAt = Column(DateTime, default=func.getdate())
    UpdatedAt = Column(DateTime, default=func.getdate(), onupdate=func.getdate())
    
    def __repr__(self):
        return f"<Threat(id={self.ThreatID}, name='{self.ThreatName}', type='{self.ThreatType}', severity='{self.Severity}')>"
    
    def to_dict(self) -> Dict:
        """Convert threat to dictionary for JSON serialization"""
        return {
            'threat_id': self.ThreatID,
            'threat_name': self.ThreatName,
            'threat_type': self.ThreatType,
            'threat_value': self.ThreatValue,
            'threat_category': self.ThreatCategory,
            'severity': self.Severity,
            'description': self.Description,
            'mitre_tactic': self.MitreTactic,
            'mitre_technique': self.MitreTechnique,
            'platform': self.Platform,
            'threat_source': self.ThreatSource,
            'confidence': float(self.Confidence) if self.Confidence else 0.5,
            'is_active': self.IsActive,
            'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None,
            'updated_at': self.UpdatedAt.isoformat() if self.UpdatedAt else None
        }
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists"""
        return {
            'threat_id': self.ThreatID,
            'threat_name': self.ThreatName,
            'threat_type': self.ThreatType,
            'threat_category': self.ThreatCategory,
            'severity': self.Severity,
            'confidence': float(self.Confidence) if self.Confidence else 0.5,
            'is_active': self.IsActive
        }
    
    def is_high_confidence(self) -> bool:
        """Check if threat has high confidence"""
        return self.Confidence and self.Confidence >= 0.8
    
    def is_critical(self) -> bool:
        """Check if threat is critical severity"""
        return self.Severity in ['High', 'Critical']
    
    @classmethod
    def get_by_type(cls, session, threat_type: str):
        """Get threats by type"""
        return session.query(cls).filter(
            cls.ThreatType == threat_type,
            cls.IsActive == True
        ).all()
    
    @classmethod
    def get_by_value(cls, session, threat_value: str):
        """Get threat by value (exact match)"""
        return session.query(cls).filter(
            cls.ThreatValue == threat_value,
            cls.IsActive == True
        ).first()
    
    @classmethod
    def check_hash(cls, session, file_hash: str):
        """Check if hash is in threat database"""
        return session.query(cls).filter(
            cls.ThreatType == 'Hash',
            cls.ThreatValue == file_hash,
            cls.IsActive == True
        ).first()
    
    @classmethod
    def check_ip(cls, session, ip_address: str):
        """Check if IP is in threat database"""
        return session.query(cls).filter(
            cls.ThreatType == 'IP',
            cls.ThreatValue == ip_address,
            cls.IsActive == True
        ).first()
    
    @classmethod
    def check_domain(cls, session, domain: str):
        """Check if domain is in threat database"""
        return session.query(cls).filter(
            cls.ThreatType == 'Domain',
            cls.ThreatValue == domain,
            cls.IsActive == True
        ).first()
    
    @classmethod
    def get_active_threats(cls, session):
        """Get all active threats"""
        return session.query(cls).filter(cls.IsActive == True).all()
    
    @classmethod
    def get_threats_summary(cls, session) -> Dict:
        """Get threat summary statistics"""
        from sqlalchemy import func as sql_func
        
        total = session.query(sql_func.count(cls.ThreatID)).scalar() or 0
        active = session.query(sql_func.count(cls.ThreatID)).filter(cls.IsActive == True).scalar() or 0
        
        # Type breakdown
        type_breakdown = session.query(
            cls.ThreatType,
            sql_func.count(cls.ThreatID).label('count')
        ).filter(cls.IsActive == True).group_by(cls.ThreatType).all()
        
        # Severity breakdown
        severity_breakdown = session.query(
            cls.Severity,
            sql_func.count(cls.ThreatID).label('count')
        ).filter(cls.IsActive == True).group_by(cls.Severity).all()
        
        return {
            'total_threats': total,
            'active_threats': active,
            'type_breakdown': {threat_type: count for threat_type, count in type_breakdown},
            'severity_breakdown': {severity: count for severity, count in severity_breakdown}
        }