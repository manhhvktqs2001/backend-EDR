"""
Agent Model - Agents table mapping
Represents endpoint agents in the EDR system
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from sqlalchemy import Column, String, DateTime, Boolean, Numeric, Integer
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from uuid import uuid4

from ..database import Base

class Agent(Base):
    """Agent model representing endpoint systems"""
    
    __tablename__ = 'Agents'
    
    # Primary Key
    AgentID = Column(UNIQUEIDENTIFIER, primary_key=True, default=uuid4)
    
    # Basic Information
    HostName = Column(String(255), nullable=False, unique=True)
    IPAddress = Column(String(45), nullable=False)
    MACAddress = Column(String(17))
    
    # System Information
    OperatingSystem = Column(String(100), nullable=False)
    OSVersion = Column(String(100))
    Architecture = Column(String(20))
    Domain = Column(String(100))
    
    # Agent Information
    AgentVersion = Column(String(20), default='1.0.0')
    InstallPath = Column(String(500))
    
    # Status & Health
    Status = Column(String(20), default='Active')
    LastHeartbeat = Column(DateTime, default=func.getdate())
    FirstSeen = Column(DateTime, default=func.getdate())
    
    # Performance Metrics
    CPUUsage = Column(Numeric(5, 2), default=0.0)
    MemoryUsage = Column(Numeric(5, 2), default=0.0)
    DiskUsage = Column(Numeric(5, 2), default=0.0)
    NetworkLatency = Column(Integer, default=0)
    
    # Configuration
    MonitoringEnabled = Column(Boolean, default=True)
    
    # Metadata
    CreatedAt = Column(DateTime, default=func.getdate())
    UpdatedAt = Column(DateTime, default=func.getdate(), onupdate=func.getdate())
    
    def __repr__(self):
        return f"<Agent(id={self.AgentID}, hostname='{self.HostName}', ip='{self.IPAddress}', status='{self.Status}')>"
    
    def to_dict(self, include_sensitive: bool = False) -> Dict:
        """Convert agent to dictionary for JSON serialization"""
        data = {
            'agent_id': str(self.AgentID),
            'hostname': self.HostName,
            'ip_address': self.IPAddress,
            'operating_system': self.OperatingSystem,
            'os_version': self.OSVersion,
            'architecture': self.Architecture,
            'agent_version': self.AgentVersion,
            'status': self.Status,
            'last_heartbeat': self.LastHeartbeat.isoformat() if self.LastHeartbeat else None,
            'first_seen': self.FirstSeen.isoformat() if self.FirstSeen else None,
            'cpu_usage': float(self.CPUUsage) if self.CPUUsage else 0.0,
            'memory_usage': float(self.MemoryUsage) if self.MemoryUsage else 0.0,
            'disk_usage': float(self.DiskUsage) if self.DiskUsage else 0.0,
            'network_latency': self.NetworkLatency or 0,
            'monitoring_enabled': self.MonitoringEnabled,
            'created_at': self.CreatedAt.isoformat() if self.CreatedAt else None,
            'updated_at': self.UpdatedAt.isoformat() if self.UpdatedAt else None,
            
            # Computed fields
            'connection_status': self.get_connection_status(),
            'is_online': self.is_online(),
            'minutes_since_heartbeat': self.get_minutes_since_heartbeat(),
            'health_status': self.get_health_status()
        }
        
        # Include sensitive information if requested
        if include_sensitive:
            data.update({
                'mac_address': self.MACAddress,
                'domain': self.Domain,
                'install_path': self.InstallPath
            })
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists and dashboards"""
        return {
            'agent_id': str(self.AgentID),
            'hostname': self.HostName,
            'ip_address': self.IPAddress,
            'operating_system': self.OperatingSystem,
            'status': self.Status,
            'connection_status': self.get_connection_status(),
            'last_heartbeat': self.LastHeartbeat.isoformat() if self.LastHeartbeat else None,
            'cpu_usage': float(self.CPUUsage) if self.CPUUsage else 0.0,
            'memory_usage': float(self.MemoryUsage) if self.MemoryUsage else 0.0
        }
    
    def get_connection_status(self) -> str:
        """Get connection status based on last heartbeat"""
        if not self.LastHeartbeat:
            return 'Unknown'
        
        now = datetime.now()
        time_diff = now - self.LastHeartbeat
        minutes = time_diff.total_seconds() / 60
        
        if minutes <= 2:
            return 'Online'
        elif minutes <= 5:
            return 'Warning'
        elif minutes <= 30:
            return 'Degraded'
        else:
            return 'Offline'
    
    def is_online(self) -> bool:
        """Check if agent is currently online"""
        return self.get_connection_status() in ['Online', 'Warning']
    
    def is_healthy(self) -> bool:
        """Check if agent is healthy (online + good performance)"""
        if not self.is_online():
            return False
        
        # Check performance thresholds
        cpu_threshold = 90.0
        memory_threshold = 95.0
        disk_threshold = 90.0
        
        if self.CPUUsage and self.CPUUsage > cpu_threshold:
            return False
        if self.MemoryUsage and self.MemoryUsage > memory_threshold:
            return False
        if self.DiskUsage and self.DiskUsage > disk_threshold:
            return False
        
        return True
    
    def get_minutes_since_heartbeat(self) -> int:
        """Get minutes since last heartbeat"""
        if not self.LastHeartbeat:
            return float('inf')
        
        now = datetime.now()
        time_diff = now - self.LastHeartbeat
        return int(time_diff.total_seconds() / 60)
    
    def get_health_status(self) -> Dict:
        """Get detailed health status"""
        status = {
            'overall': 'Healthy',
            'connection': self.get_connection_status(),
            'performance': 'Good',
            'issues': []
        }
        
        # Check connection
        if not self.is_online():
            status['overall'] = 'Unhealthy'
            status['issues'].append('Agent is offline or not responding')
        
        # Check performance metrics
        if self.CPUUsage and self.CPUUsage > 80:
            status['performance'] = 'Poor' if self.CPUUsage > 90 else 'Degraded'
            status['issues'].append(f'High CPU usage: {self.CPUUsage:.1f}%')
        
        if self.MemoryUsage and self.MemoryUsage > 85:
            status['performance'] = 'Poor' if self.MemoryUsage > 95 else 'Degraded'
            status['issues'].append(f'High memory usage: {self.MemoryUsage:.1f}%')
        
        if self.DiskUsage and self.DiskUsage > 80:
            status['performance'] = 'Poor' if self.DiskUsage > 90 else 'Degraded'
            status['issues'].append(f'High disk usage: {self.DiskUsage:.1f}%')
        
        if self.NetworkLatency and self.NetworkLatency > 1000:
            status['performance'] = 'Degraded'
            status['issues'].append(f'High network latency: {self.NetworkLatency}ms')
        
        # Determine overall status
        if status['issues']:
            if status['performance'] == 'Poor' or not self.is_online():
                status['overall'] = 'Critical'
            else:
                status['overall'] = 'Warning'
        
        return status
    
    def update_heartbeat(self, performance_data: Optional[Dict] = None):
        """Update heartbeat and performance metrics"""
        self.LastHeartbeat = func.getdate()
        self.UpdatedAt = func.getdate()
        
        if performance_data:
            self.CPUUsage = performance_data.get('cpu_usage', self.CPUUsage)
            self.MemoryUsage = performance_data.get('memory_usage', self.MemoryUsage)
            self.DiskUsage = performance_data.get('disk_usage', self.DiskUsage)
            self.NetworkLatency = performance_data.get('network_latency', self.NetworkLatency)
    
    def update_system_info(self, system_info: Dict):
        """Update system information"""
        self.OSVersion = system_info.get('os_version', self.OSVersion)
        self.Architecture = system_info.get('architecture', self.Architecture)
        self.Domain = system_info.get('domain', self.Domain)
        self.UpdatedAt = func.getdate()
    
    def set_status(self, status: str, reason: Optional[str] = None):
        """Set agent status with validation"""
        valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
        if status not in valid_statuses:
            raise ValueError(f"Invalid status: {status}. Must be one of {valid_statuses}")
        
        self.Status = status
        self.UpdatedAt = func.getdate()
    
    def enable_monitoring(self):
        """Enable monitoring for this agent"""
        self.MonitoringEnabled = True
        self.UpdatedAt = func.getdate()
    
    def disable_monitoring(self):
        """Disable monitoring for this agent"""
        self.MonitoringEnabled = False
        self.UpdatedAt = func.getdate()
    
    @classmethod
    def create_agent(cls, hostname: str, ip_address: str, operating_system: str, **kwargs):
        """Create new agent instance with validation"""
        # Validate required fields
        if not hostname or not hostname.strip():
            raise ValueError("Hostname is required")
        if not ip_address or not ip_address.strip():
            raise ValueError("IP address is required")
        if not operating_system or not operating_system.strip():
            raise ValueError("Operating system is required")
        
        agent = cls(
            HostName=hostname.strip(),
            IPAddress=ip_address.strip(),
            OperatingSystem=operating_system.strip(),
            **kwargs
        )
        return agent
    
    @classmethod
    def get_by_hostname(cls, session, hostname: str):
        """Get agent by hostname"""
        return session.query(cls).filter(cls.HostName == hostname).first()
    
    @classmethod
    def get_by_ip(cls, session, ip_address: str):
        """Get agent by IP address"""
        return session.query(cls).filter(cls.IPAddress == ip_address).first()
    
    @classmethod
    def get_by_id(cls, session, agent_id: str):
        """Get agent by ID"""
        return session.query(cls).filter(cls.AgentID == agent_id).first()
    
    @classmethod
    def get_active_agents(cls, session):
        """Get all active agents"""
        return session.query(cls).filter(cls.Status == 'Active').all()
    
    @classmethod
    def get_online_agents(cls, session, timeout_minutes: int = 5):
        """Get agents that are currently online"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        return session.query(cls).filter(
            cls.LastHeartbeat >= cutoff_time,
            cls.Status == 'Active'
        ).all()
    
    @classmethod
    def get_offline_agents(cls, session, timeout_minutes: int = 30):
        """Get agents that are offline"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        return session.query(cls).filter(
            cls.LastHeartbeat < cutoff_time
        ).all()
    
    @classmethod
    def get_agents_by_os(cls, session, operating_system: str):
        """Get agents by operating system"""
        return session.query(cls).filter(
            cls.OperatingSystem.ilike(f'%{operating_system}%')
        ).all()
    
    @classmethod
    def get_agents_summary(cls, session) -> Dict:
        """Get summary statistics for all agents"""
        from sqlalchemy import func as sql_func
        
        # Total counts
        total = session.query(sql_func.count(cls.AgentID)).scalar() or 0
        active = session.query(sql_func.count(cls.AgentID)).filter(cls.Status == 'Active').scalar() or 0
        
        # Online agents (last 5 minutes)
        cutoff_time = datetime.now() - timedelta(minutes=5)
        online = session.query(sql_func.count(cls.AgentID)).filter(
            cls.LastHeartbeat >= cutoff_time,
            cls.Status == 'Active'
        ).scalar() or 0
        
        # OS breakdown
        os_breakdown = session.query(
            cls.OperatingSystem,
            sql_func.count(cls.AgentID).label('count')
        ).group_by(cls.OperatingSystem).all()
        
        return {
            'total_agents': total,
            'active_agents': active,
            'online_agents': online,
            'offline_agents': active - online,
            'inactive_agents': total - active,
            'os_breakdown': {os: count for os, count in os_breakdown}
        }