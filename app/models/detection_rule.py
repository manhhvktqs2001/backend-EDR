# app/models/detection_rule.py - FIXED VERSION for Rule Condition Parsing
"""
Detection Rule Model - FIXED
Đảm bảo rule conditions được parse đúng cho notepad.exe detection
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text
from sqlalchemy.sql import func
import json
import logging

from ..database import Base

logger = logging.getLogger(__name__)

class DetectionRule(Base):
    """Detection rule model for EDR detection engine - FIXED"""
    
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
        """FIXED: Get rule condition as dictionary với better error handling"""
        if not self.RuleCondition:
            logger.debug(f"Rule {self.RuleID} has no condition")
            return None
        
        try:
            # Try to parse as JSON first
            condition = json.loads(self.RuleCondition)
            
            # Validate và normalize condition format
            if isinstance(condition, dict):
                # Log the parsed condition for debugging
                logger.debug(f"Rule {self.RuleID} condition parsed: {condition}")
                return condition
            else:
                logger.warning(f"Rule {self.RuleID} condition is not a dict: {type(condition)}")
                return None
                
        except json.JSONDecodeError as e:
            logger.error(f"Rule {self.RuleID} JSON decode error: {e}")
            logger.error(f"Rule condition content: {self.RuleCondition}")
            
            # Try to handle simple string conditions
            try:
                # If it's a simple string, try to create a basic condition
                if isinstance(self.RuleCondition, str) and '=' in self.RuleCondition:
                    # Simple key=value format
                    parts = self.RuleCondition.split('=', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip().strip('"\'')
                        return {key: value, "logic": "AND"}
            except Exception as fallback_error:
                logger.error(f"Fallback parsing failed: {fallback_error}")
            
            return None
        except Exception as e:
            logger.error(f"Rule {self.RuleID} condition parsing failed: {e}")
            return None
    
    def set_rule_condition(self, condition: Dict):
        """FIXED: Set rule condition from dictionary với validation"""
        try:
            if not isinstance(condition, dict):
                raise ValueError(f"Rule condition must be a dictionary, got {type(condition)}")
            
            # Validate required fields for notepad.exe type rules
            if 'process_name' in condition:
                # This is a process-based rule like notepad.exe
                logger.info(f"Setting process-based rule condition: {condition}")
            
            # Convert to JSON string
            self.RuleCondition = json.dumps(condition, ensure_ascii=False, separators=(',', ':'))
            
            logger.debug(f"Rule {self.RuleID} condition set: {self.RuleCondition}")
            
        except (TypeError, ValueError) as e:
            logger.error(f"Invalid rule condition format for rule {self.RuleID}: {e}")
            raise ValueError(f"Invalid rule condition format: {e}")
    
    def is_applicable_to_platform(self, platform: str) -> bool:
        """Check if rule applies to given platform"""
        if not self.Platform or self.Platform == 'All':
            return True
        return self.Platform.lower() == platform.lower()
    
    def is_applicable_to_event_type(self, event_type: str) -> bool:
        """FIXED: Check if rule applies to given event type"""
        try:
            condition = self.get_rule_condition()
            if not condition:
                return True  # If no condition, apply to all events
            
            # Check if rule specifies event type
            rule_event_type = condition.get('event_type')
            if rule_event_type:
                return rule_event_type.lower() == event_type.lower()
            
            # Check based on condition fields để determine applicable event types
            if any(field in condition for field in ['process_name', 'process_path', 'command_line']):
                return event_type.lower() == 'process'
            elif any(field in condition for field in ['file_name', 'file_path', 'file_hash']):
                return event_type.lower() == 'file'
            elif any(field in condition for field in ['source_ip', 'destination_ip', 'protocol']):
                return event_type.lower() == 'network'
            elif any(field in condition for field in ['registry_key', 'registry_value']):
                return event_type.lower() == 'registry'
            else:
                # If no specific fields, assume it applies to all event types
                return True
                
        except Exception as e:
            logger.error(f"Error checking event type applicability for rule {self.RuleID}: {e}")
            return True  # Default to applicable if check fails
    
    def enable(self):
        """Enable the rule"""
        self.IsActive = True
        self.UpdatedAt = func.getdate()
        logger.info(f"Rule {self.RuleID} ({self.RuleName}) enabled")
    
    def disable(self):
        """Disable the rule"""
        self.IsActive = False
        self.UpdatedAt = func.getdate()
        logger.info(f"Rule {self.RuleID} ({self.RuleName}) disabled")
    
    def set_test_mode(self, test_mode: bool):
        """Set test mode for the rule"""
        self.TestMode = test_mode
        self.UpdatedAt = func.getdate()
        logger.info(f"Rule {self.RuleID} test mode: {test_mode}")
    
    def validate_condition_format(self) -> bool:
        """FIXED: Validate rule condition format"""
        try:
            condition = self.get_rule_condition()
            if not condition:
                return False
            
            if not isinstance(condition, dict):
                return False
            
            # Check for at least one meaningful condition
            meaningful_fields = [
                'process_name', 'process_path', 'command_line',
                'file_name', 'file_path', 'file_hash',
                'source_ip', 'destination_ip', 'protocol',
                'registry_key', 'registry_value',
                'conditions'  # New format
            ]
            
            has_meaningful_condition = any(field in condition for field in meaningful_fields)
            
            if not has_meaningful_condition:
                logger.warning(f"Rule {self.RuleID} has no meaningful conditions")
                return False
            
            # Validate logic operator
            logic = condition.get('logic', 'AND')
            if logic not in ['AND', 'OR']:
                logger.warning(f"Rule {self.RuleID} has invalid logic operator: {logic}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Rule {self.RuleID} condition validation failed: {e}")
            return False
    
    def get_condition_summary(self) -> str:
        """FIXED: Get human-readable summary of rule condition"""
        try:
            condition = self.get_rule_condition()
            if not condition:
                return "No condition defined"
            
            summary_parts = []
            
            # Handle simple conditions
            if 'process_name' in condition:
                summary_parts.append(f"Process: {condition['process_name']}")
            
            if 'file_name' in condition:
                summary_parts.append(f"File: {condition['file_name']}")
            
            if 'source_ip' in condition:
                summary_parts.append(f"Source IP: {condition['source_ip']}")
            
            if 'destination_ip' in condition:
                summary_parts.append(f"Destination IP: {condition['destination_ip']}")
            
            # Handle new conditions array format
            if 'conditions' in condition and isinstance(condition['conditions'], list):
                for cond in condition['conditions']:
                    if isinstance(cond, dict):
                        field = cond.get('field', 'unknown')
                        operator = cond.get('operator', 'equals')
                        value = cond.get('value', 'unknown')
                        summary_parts.append(f"{field} {operator} {value}")
            
            if summary_parts:
                logic = condition.get('logic', 'AND')
                return f" {logic} ".join(summary_parts)
            else:
                return f"Complex condition: {len(condition)} fields"
                
        except Exception as e:
            logger.error(f"Failed to generate condition summary for rule {self.RuleID}: {e}")
            return "Error reading condition"
    
    @classmethod
    def create_rule(cls, rule_name: str, rule_type: str, rule_condition: Dict, 
                   alert_title: str, alert_severity: str, alert_type: str, **kwargs):
        """FIXED: Create new detection rule với validation"""
        try:
            # Validate inputs
            if not rule_name or not rule_type or not alert_title or not alert_severity:
                raise ValueError("Missing required fields")
            
            if not isinstance(rule_condition, dict):
                raise ValueError("Rule condition must be a dictionary")
            
            # Validate severity
            valid_severities = ['Low', 'Medium', 'High', 'Critical']
            if alert_severity not in valid_severities:
                raise ValueError(f"Invalid severity. Must be one of: {valid_severities}")
            
            # Create rule instance
            rule = cls(
                RuleName=rule_name,
                RuleType=rule_type,
                AlertTitle=alert_title,
                AlertSeverity=alert_severity,
                AlertType=alert_type,
                **kwargs
            )
            
            # Set rule condition với validation
            rule.set_rule_condition(rule_condition)
            
            # Validate the complete rule
            if not rule.validate_condition_format():
                raise ValueError("Invalid rule condition format")
            
            logger.info(f"Created detection rule: {rule_name}")
            logger.info(f"  Condition: {rule.get_condition_summary()}")
            
            return rule
            
        except Exception as e:
            logger.error(f"Failed to create detection rule: {e}")
            raise
    
    @classmethod
    def get_active_rules(cls, session, platform: Optional[str] = None):
        """Get active detection rules - FIXED với platform filtering"""
        try:
            query = session.query(cls).filter(cls.IsActive == True)
            
            if platform and platform.lower() != 'all':
                query = query.filter(
                    (cls.Platform == platform) | 
                    (cls.Platform == 'All') |
                    (cls.Platform.is_(None))
                )
            
            rules = query.order_by(cls.Priority.desc()).all()
            
            logger.debug(f"Retrieved {len(rules)} active rules for platform: {platform}")
            
            # Log rules for debugging
            for rule in rules:
                logger.debug(f"  Rule: {rule.RuleName} (ID: {rule.RuleID}, Priority: {rule.Priority})")
            
            return rules
            
        except Exception as e:
            logger.error(f"Failed to get active rules: {e}")
            return []
    
    @classmethod
    def get_rules_by_type(cls, session, rule_type: str):
        """Get rules by type"""
        try:
            return session.query(cls).filter(
                cls.RuleType == rule_type,
                cls.IsActive == True
            ).all()
        except Exception as e:
            logger.error(f"Failed to get rules by type: {e}")
            return []
    
    @classmethod
    def get_rules_by_category(cls, session, category: str):
        """Get rules by category"""
        try:
            return session.query(cls).filter(
                cls.RuleCategory == category,
                cls.IsActive == True
            ).all()
        except Exception as e:
            logger.error(f"Failed to get rules by category: {e}")
            return []
    
    @classmethod
    def get_rules_summary(cls, session) -> Dict:
        """Get detection rules summary statistics"""
        try:
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
            
            # Platform breakdown
            platform_breakdown = session.query(
                cls.Platform,
                sql_func.count(cls.RuleID).label('count')
            ).filter(cls.IsActive == True).group_by(cls.Platform).all()
            
            return {
                'total_rules': total,
                'active_rules': active,
                'inactive_rules': total - active,
                'type_breakdown': {rule_type: count for rule_type, count in type_breakdown},
                'category_breakdown': {category: count for category, count in category_breakdown if category},
                'platform_breakdown': {platform: count for platform, count in platform_breakdown if platform}
            }
            
        except Exception as e:
            logger.error(f"Failed to get rules summary: {e}")
            return {
                'total_rules': 0,
                'active_rules': 0,
                'inactive_rules': 0,
                'type_breakdown': {},
                'category_breakdown': {},
                'platform_breakdown': {}
            }
    
    @classmethod
    def find_rules_for_process(cls, session, process_name: str) -> List['DetectionRule']:
        """FIXED: Find rules that would match a specific process name (useful for testing)"""
        try:
            active_rules = cls.get_active_rules(session)
            matching_rules = []
            
            for rule in active_rules:
                try:
                    condition = rule.get_rule_condition()
                    if not condition:
                        continue
                    
                    # Check if rule targets processes
                    if 'process_name' in condition:
                        rule_process = condition['process_name'].lower()
                        if rule_process == process_name.lower():
                            matching_rules.append(rule)
                            logger.debug(f"Rule {rule.RuleName} matches process {process_name}")
                    
                    # Check conditions array format
                    elif 'conditions' in condition:
                        for cond in condition.get('conditions', []):
                            if (cond.get('field') == 'process_name' and 
                                cond.get('value', '').lower() == process_name.lower()):
                                matching_rules.append(rule)
                                logger.debug(f"Rule {rule.RuleName} matches process {process_name} (conditions format)")
                                break
                
                except Exception as e:
                    logger.error(f"Error checking rule {rule.RuleID} for process {process_name}: {e}")
                    continue
            
            logger.info(f"Found {len(matching_rules)} rules matching process: {process_name}")
            return matching_rules
            
        except Exception as e:
            logger.error(f"Failed to find rules for process {process_name}: {e}")
            return []
    
    def test_against_sample_data(self, sample_data: Dict) -> bool:
        """FIXED: Test rule against sample data (useful for rule testing)"""
        try:
            condition = self.get_rule_condition()
            if not condition:
                return False
            
            logger.debug(f"Testing rule {self.RuleName} against sample data")
            logger.debug(f"  Rule condition: {condition}")
            logger.debug(f"  Sample data: {sample_data}")
            
            # Simple field matching
            for field, expected_value in condition.items():
                if field == 'logic':
                    continue
                
                # Map rule field to sample data field
                sample_value = sample_data.get(field)
                if sample_value is None:
                    logger.debug(f"  Field {field} not in sample data")
                    continue
                
                # Case-insensitive comparison
                if str(sample_value).lower() == str(expected_value).lower():
                    logger.debug(f"  Match: {field} = {expected_value}")
                    return True
                else:
                    logger.debug(f"  No match: {field} ({sample_value} != {expected_value})")
            
            return False
            
        except Exception as e:
            logger.error(f"Rule testing failed for {self.RuleID}: {e}")
            return False
    
    @classmethod
    def create_notepad_test_rule(cls, session) -> 'DetectionRule':
        """FIXED: Create a test rule for notepad.exe detection"""
        try:
            # Check if rule already exists
            existing = session.query(cls).filter(cls.RuleName == 'Notepad Execution Test').first()
            if existing:
                logger.info("Notepad test rule already exists")
                return existing
            
            # Create notepad.exe detection rule
            rule_condition = {
                "process_name": "notepad.exe",
                "logic": "AND"
            }
            
            rule = cls.create_rule(
                rule_name="Notepad Execution Test",
                rule_type="Behavioral",
                rule_condition=rule_condition,
                alert_title="Notepad Application Detected",
                alert_severity="Medium",
                alert_type="Execution",
                RuleCategory="Process",
                AlertDescription="Notepad.exe process was executed - Test rule",
                MitreTactic="Execution",
                MitreTechnique="T1059",
                Platform="Windows",
                Priority=75,
                TestMode=True
            )
            
            session.add(rule)
            session.commit()
            
            logger.info(f"Created notepad test rule: {rule.RuleID}")
            return rule
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create notepad test rule: {e}")
            raise