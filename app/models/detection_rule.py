# app/models/detection_rule.py - Complete Detection Rule Model (Database Schema Compliant)
"""
Detection Rule Model - DetectionRules table mapping
Represents detection rules for the EDR engine
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text
from sqlalchemy.sql import func
import json

from ..database import Base

class DetectionRule(Base):
    """Detection rule model for EDR detection engine"""
    
    __tablename__ = 'DetectionRules'
    
    # Primary Key - matches INT IDENTITY(1,1) PRIMARY KEY exactly
    RuleID = Column(Integer, primary_key=True)
    
    # Rule Identification - matches database schema exactly
    RuleName = Column(String(100), nullable=False, unique=True)
    RuleType = Column(String(50), nullable=False)
    RuleCategory = Column(String(50))
    
    # Rule Logic (JSON Format) - matches NVARCHAR(MAX) NOT NULL
    RuleCondition = Column(Text, nullable=False)
    
    # Alert Configuration - matches database schema exactly
    AlertTitle = Column(String(255), nullable=False)
    AlertDescription = Column(Text)
    AlertSeverity = Column(String(20), nullable=False)
    AlertType = Column(String(100), nullable=False)
    
    # MITRE ATT&CK Mapping - matches database schema exactly
    MitreTactic = Column(String(100))
    MitreTechnique = Column(String(100))
    
    # Rule Metadata - matches database schema exactly
    Platform = Column(String(50), default='All')
    Priority = Column(Integer, default=50)
    IsActive = Column(Boolean, default=True)
    TestMode = Column(Boolean, default=False)
    
    # Metadata - matches DEFAULT GETDATE()
    CreatedAt = Column(DateTime, default=func.getdate())
    UpdatedAt = Column(DateTime, default=func.getdate(), onupdate=func.getdate())
    
    def __repr__(self):
        return f"<DetectionRule(id={self.RuleID}, name='{self.RuleName}', type='{self.RuleType}', active={self.IsActive})>"
    
    def to_dict(self) -> Dict:
        """Convert rule to dictionary for JSON serialization"""
        return {
            'rule_id': self.RuleID,
            'rule_name': self.RuleName,
            'rule_type': self.RuleType,
            'rule_category': self.RuleCategory,
            'rule_condition': self.get_rule_condition(),
            'alert_title': self.AlertTitle,
            'alert_description': self.AlertDescription,
            'alert_severity': self.AlertSeverity,
            'alert_type': self.AlertType,
            'mitre_tactic': self.MitreTactic,
            'mitre_technique': self.MitreTechnique,
            'platform': self.Platform,
            'priority': self.Priority,
            'is_active': self.IsActive,
            'test_mode': self.TestMode,
            'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None,
            'updated_at': self.UpdatedAt.isoformat() if self.UpdatedAt else None
        }
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists"""
        return {
            'rule_id': self.RuleID,
            'rule_name': self.RuleName,
            'rule_type': self.RuleType,
            'rule_category': self.RuleCategory,
            'alert_severity': self.AlertSeverity,
            'platform': self.Platform,
            'priority': self.Priority,
            'is_active': self.IsActive,
            'test_mode': self.TestMode
        }
    
    def get_rule_condition(self) -> Optional[Dict]:
        """Get rule condition as dictionary"""
        if not self.RuleCondition:
            return None
        try:
            return json.loads(self.RuleCondition)
        except (json.JSONDecodeError, TypeError):
            return None
    
    def set_rule_condition(self, condition: Dict):
        """Set rule condition from dictionary"""
        try:
            self.RuleCondition = json.dumps(condition)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid rule condition format: {e}")
    
    def is_applicable_to_platform(self, platform: str) -> bool:
        """Check if rule applies to given platform"""
        if self.Platform == 'All':
            return True
        return self.Platform.lower() == platform.lower()
    
    def enable(self):
        """Enable the rule"""
        self.IsActive = True
        self.UpdatedAt = func.getdate()
    
    def disable(self):
        """Disable the rule"""
        self.IsActive = False
        self.UpdatedAt = func.getdate()
    
    def set_test_mode(self, test_mode: bool):
        """Set test mode for the rule"""
        self.TestMode = test_mode
        self.UpdatedAt = func.getdate()
    
    @classmethod
    def create_rule(cls, rule_name: str, rule_type: str, rule_condition: Dict, 
                   alert_title: str, alert_severity: str, alert_type: str, **kwargs):
        """Create new detection rule"""
        rule = cls(
            RuleName=rule_name,
            RuleType=rule_type,
            AlertTitle=alert_title,
            AlertSeverity=alert_severity,
            AlertType=alert_type,
            **kwargs
        )
        rule.set_rule_condition(rule_condition)
        return rule
    
    @classmethod
    def get_active_rules(cls, session, platform: Optional[str] = None):
        """Get active detection rules"""
        query = session.query(cls).filter(cls.IsActive == True)
        if platform:
            query = query.filter(
                (cls.Platform == 'All') | (cls.Platform == platform)
            )
        return query.order_by(cls.Priority.desc()).all()
    
    @classmethod
    def get_rules_by_type(cls, session, rule_type: str):
        """Get rules by type"""
        return session.query(cls).filter(
            cls.RuleType == rule_type,
            cls.IsActive == True
        ).all()
    
    @classmethod
    def get_rules_by_category(cls, session, category: str):
        """Get rules by category"""
        return session.query(cls).filter(
            cls.RuleCategory == category,
            cls.IsActive == True
        ).all()
    
    @classmethod
    def get_rules_summary(cls, session) -> Dict:
        """Get detection rules summary"""
        from sqlalchemy import func as sql_func
        
        total = session.query(sql_func.count(cls.RuleID)).scalar() or 0
        active = session.query(sql_func.count(cls.RuleID)).filter(cls.IsActive == True).scalar() or 0
        
        # Type breakdown
        type_breakdown = session.query(
            cls.RuleType,
            sql_func.count(cls.RuleID).label('count')
        ).filter(cls.IsActive == True).group_by(cls.RuleType).all()
        
        # Category breakdown
        category_breakdown = session.query(
            cls.RuleCategory,
            sql_func.count(cls.RuleID).label('count')
        ).filter(cls.IsActive == True).group_by(cls.RuleCategory).all()
        
        return {
            'total_rules': total,
            'active_rules': active,
            'inactive_rules': total - active,
            'type_breakdown': {rule_type: count for rule_type, count in type_breakdown},
            'category_breakdown': {category: count for category, count in category_breakdown if category}
        }