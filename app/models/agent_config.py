# app/models/agent_config.py
"""
Agent Configuration Model - AgentConfigs table mapping
Represents agent-specific configuration settings
"""

from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Column, String, DateTime, Boolean, BigInteger, Text
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.sql import func
import json

from ..database import Base

class AgentConfig(Base):
    """Agent configuration model for agent-specific settings"""
    
    __tablename__ = 'AgentConfigs'
    
    # Primary Key
    ConfigID = Column(BigInteger, primary_key=True)
    
    # Foreign Key
    AgentID = Column(UNIQUEIDENTIFIER, nullable=False)
    
    # Configuration Data (JSON format)
    ConfigData = Column(Text, nullable=False)
    ConfigVersion = Column(String(50), nullable=False)
    
    # Status
    IsActive = Column(Boolean, default=True)
    AppliedAt = Column(DateTime)
    
    # Metadata
    CreatedAt = Column(DateTime, default=func.getdate())
    
    def __repr__(self):
        return f"<AgentConfig(id={self.ConfigID}, agent={self.AgentID}, version='{self.ConfigVersion}', active={self.IsActive})>"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'config_id': self.ConfigID,
            'agent_id': str(self.AgentID),
            'config_data': self.get_config_data(),
            'config_version': self.ConfigVersion,
            'is_active': self.IsActive,
            'applied_at': self.AppliedAt.isoformat() if self.AppliedAt else None,
            'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None
        }
    
    def get_config_data(self) -> Optional[Dict]:
        """Get configuration data as dictionary"""
        if not self.ConfigData:
            return None
        try:
            return json.loads(self.ConfigData)
        except (json.JSONDecodeError, TypeError):
            return None
    
    def set_config_data(self, config_data: Dict):
        """Set configuration data from dictionary"""
        try:
            self.ConfigData = json.dumps(config_data, indent=2)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid configuration data: {e}")
    
    def mark_applied(self):
        """Mark configuration as applied"""
        self.AppliedAt = func.getdate()
    
    def activate(self):
        """Activate this configuration"""
        self.IsActive = True
    
    def deactivate(self):
        """Deactivate this configuration"""
        self.IsActive = False
    
    @classmethod
    def get_active_config(cls, session, agent_id: str) -> Optional['AgentConfig']:
        """Get active configuration for agent"""
        return session.query(cls).filter(
            cls.AgentID == agent_id,
            cls.IsActive == True
        ).order_by(cls.CreatedAt.desc()).first()
    
    @classmethod
    def get_latest_config(cls, session, agent_id: str) -> Optional['AgentConfig']:
        """Get latest configuration for agent (active or not)"""
        return session.query(cls).filter(
            cls.AgentID == agent_id
        ).order_by(cls.CreatedAt.desc()).first()
    
    @classmethod
    def create_config(cls, session, agent_id: str, config_data: Dict, 
                     config_version: str, auto_activate: bool = True) -> 'AgentConfig':
        """Create new agent configuration"""
        
        # Deactivate existing configs if auto_activate
        if auto_activate:
            existing_configs = session.query(cls).filter(
                cls.AgentID == agent_id,
                cls.IsActive == True
            ).all()
            for config in existing_configs:
                config.deactivate()
        
        # Create new config
        new_config = cls(
            AgentID=agent_id,
            ConfigVersion=config_version,
            IsActive=auto_activate
        )
        new_config.set_config_data(config_data)
        
        session.add(new_config)
        return new_config
    
    @classmethod
    def get_default_config(cls, platform: str = 'Windows') -> Dict:
        """Get default configuration for platform"""
        base_config = {
            'version': '2.0',
            'heartbeat_interval': 30,
            'event_batch_size': 100,
            'monitoring_enabled': True,
            'collection_settings': {
                'collect_processes': True,
                'collect_files': True,
                'collect_network': True,
                'collect_registry': platform.lower() == 'windows',
                'collect_authentication': True,
                'collect_system_events': True
            },
            'detection_settings': {
                'realtime_detection': True,
                'threat_intel_lookup': True,
                'behavior_analysis': True,
                'risk_threshold': 70
            },
            'performance_settings': {
                'max_events_per_minute': 1000,
                'max_memory_usage_mb': 512,
                'max_cpu_usage_percent': 20,
                'cache_size_mb': 64
            },
            'network_settings': {
                'server_timeout': 30,
                'retry_attempts': 3,
                'retry_delay': 5,
                'compression_enabled': True
            }
        }
        
        # Platform-specific settings
        if platform.lower() == 'windows':
            base_config['collection_settings'].update({
                'registry_monitoring': True,
                'wmi_monitoring': False,
                'etw_monitoring': False
            })
        elif platform.lower() == 'linux':
            base_config['collection_settings'].update({
                'auditd_monitoring': True,
                'syslog_monitoring': True,
                'container_monitoring': False
            })
        
        return base_config
    
    @classmethod
    def get_configs_by_version(cls, session, config_version: str):
        """Get all configurations by version"""
        return session.query(cls).filter(
            cls.ConfigVersion == config_version,
            cls.IsActive == True
        ).all()
    
    @classmethod
    def get_agent_config_history(cls, session, agent_id: str, limit: int = 10):
        """Get configuration history for agent"""
        return session.query(cls).filter(
            cls.AgentID == agent_id
        ).order_by(cls.CreatedAt.desc()).limit(limit).all()
    
    def get_setting(self, setting_path: str, default: Any = None) -> Any:
        """Get specific setting using dot notation (e.g., 'collection_settings.collect_processes')"""
        config_data = self.get_config_data()
        if not config_data:
            return default
        
        try:
            keys = setting_path.split('.')
            value = config_data
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_setting(self, setting_path: str, value: Any):
        """Set specific setting using dot notation"""
        config_data = self.get_config_data() or {}
        
        keys = setting_path.split('.')
        current = config_data
        
        # Navigate to parent of target key
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set the value
        current[keys[-1]] = value
        
        # Update config data
        self.set_config_data(config_data)
    
    @classmethod
    def bulk_update_configs(cls, session, agent_ids: list, config_updates: Dict, 
                           config_version: str = None):
        """Bulk update configurations for multiple agents"""
        updated_configs = []
        
        for agent_id in agent_ids:
            # Get current active config
            current_config = cls.get_active_config(session, agent_id)
            
            if current_config:
                # Update existing config
                current_data = current_config.get_config_data() or {}
                current_data.update(config_updates)
                
                # Create new config version
                new_version = config_version or f"bulk_update_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                new_config = cls.create_config(
                    session, agent_id, current_data, new_version, auto_activate=True
                )
                updated_configs.append(new_config)
        
        return updated_configs
    
    @classmethod
    def cleanup_old_configs(cls, session, retention_days: int = 30):
        """Clean up old configuration versions"""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # Keep only latest 5 configs per agent and active configs
        old_configs = session.query(cls).filter(
            cls.CreatedAt < cutoff_date,
            cls.IsActive == False
        )
        
        # Group by agent and keep only newest configs
        agent_configs = {}
        for config in old_configs:
            agent_id = str(config.AgentID)
            if agent_id not in agent_configs:
                agent_configs[agent_id] = []
            agent_configs[agent_id].append(config)
        
        deleted_count = 0
        for agent_id, configs in agent_configs.items():
            # Sort by creation date and keep only 5 newest
            configs.sort(key=lambda x: x.CreatedAt, reverse=True)
            configs_to_delete = configs[5:]  # Keep 5, delete rest
            
            for config in configs_to_delete:
                session.delete(config)
                deleted_count += 1
        
        return deleted_count