# app/models/system_config.py
"""
System Configuration Model - SystemConfig table mapping
Represents system-wide configuration settings
"""

from datetime import datetime
from typing import Optional, Dict, Any, Union
from sqlalchemy import Column, String, DateTime, Integer, Text
from sqlalchemy.sql import func
import json

from ..database import Base

class SystemConfig(Base):
    """System configuration model for EDR system settings"""
    
    __tablename__ = 'SystemConfig'
    
    # Primary Key
    ConfigID = Column(Integer, primary_key=True)
    
    # Configuration Key-Value
    ConfigKey = Column(String(100), nullable=False, unique=True)
    ConfigValue = Column(Text, nullable=False)
    ConfigType = Column(String(50), nullable=False, default='String')
    
    # Metadata
    Description = Column(String(500))
    Category = Column(String(100))
    
    # Validation
    ValidationRegex = Column(String(500))
    DefaultValue = Column(Text)
    
    # Timestamps
    CreatedAt = Column(DateTime, default=func.getdate())
    UpdatedAt = Column(DateTime, default=func.getdate(), onupdate=func.getdate())
    
    def __repr__(self):
        return f"<SystemConfig(key='{self.ConfigKey}', type='{self.ConfigType}', value='{self.ConfigValue[:50]}...')>"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'config_id': self.ConfigID,
            'config_key': self.ConfigKey,
            'config_value': self.get_typed_value(),
            'config_type': self.ConfigType,
            'description': self.Description,
            'category': self.Category,
            'validation_regex': self.ValidationRegex,
            'default_value': self.DefaultValue,
            'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None,
            'updated_at': self.UpdatedAt.isoformat() if self.UpdatedAt else None
        }
    
    def get_typed_value(self) -> Union[str, int, bool, Dict, None]:
        """Get config value converted to appropriate type"""
        if not self.ConfigValue:
            return None
        
        try:
            if self.ConfigType == 'Integer':
                return int(self.ConfigValue)
            elif self.ConfigType == 'Boolean':
                return self.ConfigValue.lower() in ('true', '1', 'yes', 'on')
            elif self.ConfigType == 'JSON':
                return json.loads(self.ConfigValue)
            else:  # String or default
                return self.ConfigValue
        except (ValueError, json.JSONDecodeError):
            return self.ConfigValue  # Return as string if conversion fails
    
    def set_typed_value(self, value: Any) -> None:
        """Set config value with automatic type conversion"""
        if self.ConfigType == 'Integer':
            self.ConfigValue = str(int(value))
        elif self.ConfigType == 'Boolean':
            self.ConfigValue = 'true' if bool(value) else 'false'
        elif self.ConfigType == 'JSON':
            self.ConfigValue = json.dumps(value)
        else:  # String
            self.ConfigValue = str(value)
        
        self.UpdatedAt = func.getdate()
    
    def validate_value(self, value: str) -> bool:
        """Validate config value against regex if defined"""
        if not self.ValidationRegex:
            return True
        
        import re
        try:
            return bool(re.match(self.ValidationRegex, value))
        except re.error:
            return False
    
    @classmethod
    def get_config(cls, session, key: str) -> Optional['SystemConfig']:
        """Get configuration by key"""
        return session.query(cls).filter(cls.ConfigKey == key).first()
    
    @classmethod
    def get_config_value(cls, session, key: str, default: Any = None) -> Any:
        """Get configuration value by key with default"""
        config = cls.get_config(session, key)
        if config:
            return config.get_typed_value()
        return default
    
    @classmethod
    def set_config(cls, session, key: str, value: Any, config_type: str = 'String', 
                   description: str = None, category: str = None) -> 'SystemConfig':
        """Set or update configuration"""
        config = cls.get_config(session, key)
        
        if config:
            # Update existing
            config.set_typed_value(value)
            if description:
                config.Description = description
            if category:
                config.Category = category
        else:
            # Create new
            config = cls(
                ConfigKey=key,
                ConfigType=config_type,
                Description=description,
                Category=category
            )
            config.set_typed_value(value)
            session.add(config)
        
        return config
    
    @classmethod
    def get_by_category(cls, session, category: str):
        """Get all configurations by category"""
        return session.query(cls).filter(cls.Category == category).all()
    
    @classmethod
    def get_all_configs(cls, session) -> Dict[str, Any]:
        """Get all configurations as dictionary"""
        configs = session.query(cls).all()
        result = {}
        for config in configs:
            result[config.ConfigKey] = config.get_typed_value()
        return result
    
    @classmethod
    def initialize_defaults(cls, session):
        """Initialize default system configurations"""
        defaults = [
            # System Info
            ('system.name', 'EDR Security Platform', 'String', 'General', 'System display name'),
            ('system.version', '2.0.0', 'String', 'General', 'Current system version'),
            
            # Agent Settings
            ('agent.heartbeat_interval', '30', 'Integer', 'Agent', 'Agent heartbeat interval in seconds'),
            ('agent.max_agents', '1000', 'Integer', 'Agent', 'Maximum number of agents'),
            ('agent.auto_approve', 'true', 'Boolean', 'Agent', 'Auto-approve agent registration'),
            
            # Detection Settings
            ('detection.rules_enabled', 'true', 'Boolean', 'Detection', 'Enable detection rules'),
            ('detection.threat_intel_enabled', 'true', 'Boolean', 'Detection', 'Enable threat intelligence'),
            ('detection.risk_threshold', '70', 'Integer', 'Detection', 'Risk score threshold for alerts'),
            
            # Alert Settings
            ('alerts.retention_days', '90', 'Integer', 'Alerts', 'Alert retention period in days'),
            ('alerts.auto_resolve_days', '30', 'Integer', 'Alerts', 'Auto-resolve alerts after X days'),
            ('alerts.max_per_hour', '100', 'Integer', 'Alerts', 'Maximum alerts per hour per agent'),
            
            # Performance Settings
            ('performance.cache_ttl', '300', 'Integer', 'Performance', 'Cache TTL in seconds'),
            ('performance.db_pool_size', '10', 'Integer', 'Performance', 'Database connection pool size'),
            
            # Maintenance
            ('maintenance.cleanup_enabled', 'true', 'Boolean', 'Maintenance', 'Enable automatic cleanup'),
            ('maintenance.event_retention_days', '365', 'Integer', 'Maintenance', 'Event retention period'),
            ('maintenance.last_cleanup', '', 'String', 'Maintenance', 'Last cleanup timestamp'),
        ]
        
        for key, value, config_type, category, description in defaults:
            existing = cls.get_config(session, key)
            if not existing:
                config = cls(
                    ConfigKey=key,
                    ConfigType=config_type,
                    Category=category,
                    Description=description
                )
                config.set_typed_value(value)
                session.add(config)
        
        session.commit()
    
    @classmethod
    def get_system_info(cls, session) -> Dict:
        """Get system information configuration"""
        system_configs = cls.get_by_category(session, 'General')
        info = {}
        for config in system_configs:
            info[config.ConfigKey.replace('system.', '')] = config.get_typed_value()
        return info
    
    @classmethod
    def get_agent_config(cls, session) -> Dict:
        """Get agent-related configuration"""
        agent_configs = cls.get_by_category(session, 'Agent')
        config = {}
        for cfg in agent_configs:
            config[cfg.ConfigKey.replace('agent.', '')] = cfg.get_typed_value()
        return config
    
    @classmethod
    def get_detection_config(cls, session) -> Dict:
        """Get detection engine configuration"""
        detection_configs = cls.get_by_category(session, 'Detection')
        config = {}
        for cfg in detection_configs:
            config[cfg.ConfigKey.replace('detection.', '')] = cfg.get_typed_value()
        return config