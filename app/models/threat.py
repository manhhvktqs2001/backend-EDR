# app/models/threat.py - FIXED VERSION (Database Schema Compliant)
"""
Threat Model - Threats table mapping
Represents threat intelligence indicators (FIXED for 512 char limit)
"""

from datetime import datetime
from typing import Optional, Dict, List
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text, Numeric
from sqlalchemy.sql import func
import logging

from ..database import Base

logger = logging.getLogger(__name__)

class Threat(Base):
    """Threat model representing threat intelligence indicators - FIXED"""
    
    __tablename__ = 'Threats'
    
    # Primary Key - matches INT IDENTITY(1,1) PRIMARY KEY exactly
    ThreatID = Column(Integer, primary_key=True)
    
    # Basic Information - FIXED: matches database schema column names exactly
    ThreatName = Column(String(255), nullable=False)
    ThreatType = Column(String(50), nullable=False)
    # CRITICAL FIX: Changed from Text to String(512) to match DB schema
    ThreatValue = Column(String(512), nullable=False)  # FIXED: NVARCHAR(512) limit
    ThreatCategory = Column(String(50))
    Severity = Column(String(20), nullable=False, default='Medium')
    Description = Column(Text)
    
    # MITRE ATT&CK Framework - matches database schema exactly
    MitreTactic = Column(String(100))
    MitreTechnique = Column(String(100))
    
    # Source Information - FIXED: matches database schema exactly
    Platform = Column(String(50), nullable=False, default='All')
    ThreatSource = Column(String(100))
    # FIXED: DECIMAL(3,2) precision matching DB schema
    Confidence = Column(Numeric(3, 2), nullable=False, default=0.5)
    
    # Status - FIXED: matches BIT DEFAULT 1 exactly
    IsActive = Column(Boolean, nullable=False, default=True)
    
    # Metadata - matches DEFAULT GETDATE() exactly
    CreatedAt = Column(DateTime, nullable=False, default=func.getdate())
    UpdatedAt = Column(DateTime, nullable=False, default=func.getdate())
    
    def __repr__(self):
        return f"<Threat(id={self.ThreatID}, name='{self.ThreatName}', type='{self.ThreatType}', severity='{self.Severity}')>"
    
    def to_dict(self) -> Dict:
        """Convert threat to dictionary for JSON serialization - FIXED"""
        try:
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
                # FIXED: Proper DECIMAL handling
                'confidence': float(self.Confidence) if self.Confidence is not None else 0.5,
                'is_active': bool(self.IsActive),
                'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None,
                'updated_at': self.UpdatedAt.isoformat() if self.UpdatedAt else None
            }
        except Exception as e:
            logger.error(f"Error converting threat to dict: {e}")
            return {'error': 'Conversion failed'}
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists - FIXED"""
        try:
            return {
                'threat_id': self.ThreatID,
                'threat_name': self.ThreatName,
                'threat_type': self.ThreatType,
                'threat_category': self.ThreatCategory,
                'severity': self.Severity,
                'confidence': float(self.Confidence) if self.Confidence is not None else 0.5,
                'is_active': bool(self.IsActive)
            }
        except Exception as e:
            logger.error(f"Error creating threat summary: {e}")
            return {'error': 'Summary creation failed'}
    
    def is_high_confidence(self) -> bool:
        """Check if threat has high confidence"""
        try:
            return self.Confidence is not None and float(self.Confidence) >= 0.8
        except Exception:
            return False
    
    def is_critical(self) -> bool:
        """Check if threat is critical severity"""
        return self.Severity in ['High', 'Critical']
    
    def validate_threat_value(self, value: str) -> str:
        """Validate and truncate threat value to 512 chars - CRITICAL FIX"""
        if not value:
            raise ValueError("Threat value cannot be empty")
        
        # CRITICAL: Enforce 512 character limit to match DB schema
        if len(value) > 512:
            logger.warning(f"Threat value truncated from {len(value)} to 512 characters")
            return value[:512]
        
        return value
    
    def set_threat_value(self, value: str) -> None:
        """Set threat value with validation - FIXED"""
        self.ThreatValue = self.validate_threat_value(value)
    
    @classmethod
    def create_threat(cls, threat_name: str, threat_type: str, threat_value: str, **kwargs):
        """Create new threat with validation - FIXED"""
        try:
            # Validate required fields
            if not threat_name or not threat_type or not threat_value:
                raise ValueError("threat_name, threat_type, and threat_value are required")
            
            # Validate threat_type
            valid_types = ['Hash', 'IP', 'Domain', 'URL', 'YARA', 'Behavioral']
            if threat_type not in valid_types:
                raise ValueError(f"Invalid threat_type. Must be one of: {valid_types}")
            
            # Validate severity if provided
            severity = kwargs.get('Severity', 'Medium')
            valid_severities = ['Low', 'Medium', 'High', 'Critical']
            if severity not in valid_severities:
                raise ValueError(f"Invalid severity. Must be one of: {valid_severities}")
            
            # Create threat instance
            threat = cls(
                ThreatName=threat_name[:255],  # Truncate to max length
                ThreatType=threat_type[:50],   # Truncate to max length
                ThreatValue=threat_value[:512],  # CRITICAL: Truncate to 512 chars
                **kwargs
            )
            
            # Validate confidence if provided
            if 'Confidence' in kwargs:
                conf_val = float(kwargs['Confidence'])
                if not (0.0 <= conf_val <= 1.0):
                    raise ValueError("Confidence must be between 0.0 and 1.0")
                threat.Confidence = conf_val
            
            return threat
            
        except Exception as e:
            logger.error(f"Error creating threat: {e}")
            raise ValueError(f"Failed to create threat: {e}")
    
    @classmethod
    def get_by_type(cls, session, threat_type: str):
        """Get threats by type - FIXED"""
        try:
            return session.query(cls).filter(
                cls.ThreatType == threat_type,
                cls.IsActive == True
            ).all()
        except Exception as e:
            logger.error(f"Error getting threats by type: {e}")
            return []
    
    @classmethod
    def get_by_value(cls, session, threat_value: str):
        """Get threat by value (exact match) - FIXED"""
        try:
            # Truncate search value to match DB limit
            search_value = threat_value[:512]
            return session.query(cls).filter(
                cls.ThreatValue == search_value,
                cls.IsActive == True
            ).first()
        except Exception as e:
            logger.error(f"Error getting threat by value: {e}")
            return None
    
    @classmethod
    def check_hash(cls, session, file_hash: str):
        """Check if hash is in threat database - FIXED"""
        try:
            if not file_hash:
                return None
            
            # Normalize hash (lowercase, strip whitespace)
            normalized_hash = file_hash.lower().strip()
            
            # Truncate to 512 chars if needed
            if len(normalized_hash) > 512:
                logger.warning(f"Hash truncated from {len(normalized_hash)} to 512 characters")
                normalized_hash = normalized_hash[:512]
            
            return session.query(cls).filter(
                cls.ThreatType == 'Hash',
                cls.ThreatValue == normalized_hash,
                cls.IsActive == True
            ).first()
        except Exception as e:
            logger.error(f"Error checking hash: {e}")
            return None
    
    @classmethod
    def check_ip(cls, session, ip_address: str):
        """Check if IP is in threat database - FIXED"""
        try:
            if not ip_address:
                return None
            
            # Validate IP format
            import ipaddress
            try:
                # This will raise ValueError if invalid
                ipaddress.ip_address(ip_address)
            except ValueError:
                logger.warning(f"Invalid IP address format: {ip_address}")
                return None
            
            return session.query(cls).filter(
                cls.ThreatType == 'IP',
                cls.ThreatValue == ip_address,
                cls.IsActive == True
            ).first()
        except Exception as e:
            logger.error(f"Error checking IP: {e}")
            return None
    
    @classmethod
    def check_domain(cls, session, domain: str):
        """Check if domain is in threat database - FIXED"""
        try:
            if not domain:
                return None
            
            # Normalize domain (lowercase, strip)
            normalized_domain = domain.lower().strip()
            
            # Truncate to 512 chars if needed
            if len(normalized_domain) > 512:
                logger.warning(f"Domain truncated from {len(normalized_domain)} to 512 characters")
                normalized_domain = normalized_domain[:512]
            
            return session.query(cls).filter(
                cls.ThreatType == 'Domain',
                cls.ThreatValue == normalized_domain,
                cls.IsActive == True
            ).first()
        except Exception as e:
            logger.error(f"Error checking domain: {e}")
            return None
    
    @classmethod
    def get_active_threats(cls, session):
        """Get all active threats - FIXED"""
        try:
            return session.query(cls).filter(cls.IsActive == True).all()
        except Exception as e:
            logger.error(f"Error getting active threats: {e}")
            return []
    
    @classmethod
    def get_threats_summary(cls, session) -> Dict:
        """Get threat summary statistics - FIXED"""
        try:
            from sqlalchemy import func as sql_func
            
            total = session.query(sql_func.count(cls.ThreatID)).scalar() or 0
            active = session.query(sql_func.count(cls.ThreatID)).filter(cls.IsActive == True).scalar() or 0
            
            # Type breakdown - FIXED with error handling
            try:
                type_breakdown = session.query(
                    cls.ThreatType,
                    sql_func.count(cls.ThreatID).label('count')
                ).filter(cls.IsActive == True).group_by(cls.ThreatType).all()
                type_dict = {threat_type: count for threat_type, count in type_breakdown}
            except Exception:
                type_dict = {}
            
            # Severity breakdown - FIXED with error handling
            try:
                severity_breakdown = session.query(
                    cls.Severity,
                    sql_func.count(cls.ThreatID).label('count')
                ).filter(cls.IsActive == True).group_by(cls.Severity).all()
                severity_dict = {severity: count for severity, count in severity_breakdown}
            except Exception:
                severity_dict = {}
            
            return {
                'total_threats': total,
                'active_threats': active,
                'type_breakdown': type_dict,
                'severity_breakdown': severity_dict
            }
            
        except Exception as e:
            logger.error(f"Error getting threats summary: {e}")
            return {
                'total_threats': 0,
                'active_threats': 0,
                'type_breakdown': {},
                'severity_breakdown': {}
            }
    
    @classmethod
    def bulk_import_threats(cls, session, threats_data: List[Dict], validate: bool = True) -> Dict:
        """Bulk import threats with validation - NEW"""
        try:
            imported = 0
            updated = 0
            skipped = 0
            errors = []
            
            for threat_data in threats_data:
                try:
                    # Validate required fields
                    if not all(k in threat_data for k in ['threat_name', 'threat_type', 'threat_value']):
                        errors.append(f"Missing required fields in threat data")
                        skipped += 1
                        continue
                    
                    # Check if threat already exists
                    existing = cls.get_by_value(session, threat_data['threat_value'])
                    
                    if existing:
                        # Update existing
                        if threat_data.get('threat_name'):
                            existing.ThreatName = threat_data['threat_name'][:255]
                        if threat_data.get('severity'):
                            existing.Severity = threat_data['severity']
                        if threat_data.get('description'):
                            existing.Description = threat_data['description']
                        updated += 1
                    else:
                        # Create new threat
                        new_threat = cls.create_threat(**threat_data)
                        session.add(new_threat)
                        imported += 1
                    
                except Exception as e:
                    errors.append(f"Error processing threat: {str(e)}")
                    skipped += 1
            
            session.commit()
            
            return {
                'imported': imported,
                'updated': updated,
                'skipped': skipped,
                'errors': errors,
                'total_processed': len(threats_data)
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Bulk import failed: {e}")
            return {
                'imported': 0,
                'updated': 0,
                'skipped': len(threats_data),
                'errors': [f"Bulk import failed: {str(e)}"],
                'total_processed': len(threats_data)
            }
    
    @classmethod
    def cleanup_old_threats(cls, session, days: int = 365) -> int:
        """Clean up old inactive threats - NEW"""
        try:
            from datetime import timedelta
            
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Delete old inactive threats
            deleted_count = session.query(cls).filter(
                cls.IsActive == False,
                cls.UpdatedAt < cutoff_date
            ).delete()
            
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old inactive threats")
            
            return deleted_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"Threat cleanup failed: {e}")
            return 0