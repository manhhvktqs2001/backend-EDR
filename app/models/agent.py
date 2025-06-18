# app/models/agent.py - Complete Agent Model
"""
Agent Model - Agents table mapping
Represents endpoint agents in the EDR system (Updated for simplified schema)
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from sqlalchemy import Column, String, DateTime, Boolean, Numeric, Integer, or_
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from uuid import uuid4

from ..database import Base

class Agent(Base):
    """Agent model representing endpoint systems in EDR network"""
    
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
            'health_status': self.get_health_status(),
            'platform_type': self.get_platform_type()
        }
        
        # Include sensitive information if requested
        if include_sensitive:
            data.update({
                'mac_address': self.MACAddress,
                'domain': self.Domain,
                'install_path': self.InstallPath
            })
        
        return data
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists and dashboards"""
        return {
            'agent_id': str(self.AgentID),
            'hostname': self.HostName,
            'ip_address': self.IPAddress,
            'operating_system': self.OperatingSystem,
            'platform_type': self.get_platform_type(),
            'status': self.Status,
            'connection_status': self.get_connection_status(),
            'last_heartbeat': self.LastHeartbeat.isoformat() if self.LastHeartbeat else None,
            'cpu_usage': float(self.CPUUsage) if self.CPUUsage else 0.0,
            'memory_usage': float(self.MemoryUsage) if self.MemoryUsage else 0.0,
            'is_healthy': self.is_healthy(),
            'monitoring_enabled': self.MonitoringEnabled
        }
    
    def get_platform_type(self) -> str:
        """Get simplified platform type"""
        if 'windows' in self.OperatingSystem.lower():
            return 'Windows'
        elif 'linux' in self.OperatingSystem.lower():
            return 'Linux'
        elif 'mac' in self.OperatingSystem.lower() or 'darwin' in self.OperatingSystem.lower():
            return 'macOS'
        else:
            return 'Other'
    
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
        elif minutes <= 15:
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
        """Get detailed health status with recommendations"""
        status = {
            'overall': 'Healthy',
            'connection': self.get_connection_status(),
            'performance': 'Good',
            'issues': [],
            'recommendations': []
        }
        
        # Check connection
        if not self.is_online():
            status['overall'] = 'Unhealthy'
            status['issues'].append('Agent is offline or not responding')
            status['recommendations'].append('Check agent service and network connectivity')
        
        # Check performance metrics
        if self.CPUUsage and self.CPUUsage > 80:
            status['performance'] = 'Poor' if self.CPUUsage > 90 else 'Degraded'
            status['issues'].append(f'High CPU usage: {self.CPUUsage:.1f}%')
            if self.CPUUsage > 90:
                status['recommendations'].append('Investigate high CPU usage processes')
        
        if self.MemoryUsage and self.MemoryUsage > 85:
            status['performance'] = 'Poor' if self.MemoryUsage > 95 else 'Degraded'
            status['issues'].append(f'High memory usage: {self.MemoryUsage:.1f}%')
            if self.MemoryUsage > 95:
                status['recommendations'].append('Check for memory leaks or high memory processes')
        
        if self.DiskUsage and self.DiskUsage > 80:
            status['performance'] = 'Poor' if self.DiskUsage > 90 else 'Degraded'
            status['issues'].append(f'High disk usage: {self.DiskUsage:.1f}%')
            if self.DiskUsage > 90:
                status['recommendations'].append('Clean up disk space or investigate disk usage')
        
        if self.NetworkLatency and self.NetworkLatency > 200:
            status['performance'] = 'Poor' if self.NetworkLatency > 500 else 'Degraded'
            status['issues'].append(f'High network latency: {self.NetworkLatency}ms')
            if self.NetworkLatency > 500:
                status['recommendations'].append('Check network connectivity and bandwidth')
        
        # Update overall status based on issues
        if status['issues']:
            if status['performance'] == 'Poor':
                status['overall'] = 'Critical'
            elif status['performance'] == 'Degraded':
                status['overall'] = 'Warning'
        
        return status
    
    def update_heartbeat(self, performance_data: Dict = None) -> None:
        """Update heartbeat with optional performance data"""
        self.LastHeartbeat = datetime.now()
        self.UpdatedAt = datetime.now()
        
        if performance_data:
            if 'cpu_usage' in performance_data:
                self.CPUUsage = performance_data['cpu_usage']
            if 'memory_usage' in performance_data:
                self.MemoryUsage = performance_data['memory_usage']
            if 'disk_usage' in performance_data:
                self.DiskUsage = performance_data['disk_usage']
            if 'network_latency' in performance_data:
                self.NetworkLatency = performance_data['network_latency']
    
    def update_performance_metrics(self, cpu: float = None, memory: float = None, 
                                 disk: float = None, latency: int = None) -> None:
        """Update performance metrics"""
        if cpu is not None:
            self.CPUUsage = cpu
        if memory is not None:
            self.MemoryUsage = memory
        if disk is not None:
            self.DiskUsage = disk
        if latency is not None:
            self.NetworkLatency = latency
        
        self.UpdatedAt = datetime.now()
    
    def set_status(self, status: str) -> None:
        """Set agent status"""
        valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
        if status in valid_statuses:
            self.Status = status
            self.UpdatedAt = datetime.now()
        else:
            raise ValueError(f"Invalid status: {status}. Valid statuses: {valid_statuses}")
    
    def enable_monitoring(self) -> None:
        """Enable monitoring for agent"""
        self.MonitoringEnabled = True
        self.UpdatedAt = datetime.now()
    
    def disable_monitoring(self) -> None:
        """Disable monitoring for agent"""
        self.MonitoringEnabled = False
        self.UpdatedAt = datetime.now()
    
    def get_uptime_percentage(self, days: int = 30) -> float:
        """Calculate uptime percentage over specified days"""
        if not self.FirstSeen:
            return 0.0
        
        start_date = datetime.now() - timedelta(days=days)
        if self.FirstSeen > start_date:
            start_date = self.FirstSeen
        
        total_time = (datetime.now() - start_date).total_seconds()
        if total_time <= 0:
            return 0.0
        
        # Simplified calculation - in real implementation, you'd track offline periods
        if self.is_online():
            return 99.5  # Assume good uptime if currently online
        else:
            return 85.0  # Assume lower uptime if currently offline
    
    def get_agent_info(self) -> Dict:
        """Get comprehensive agent information"""
        return {
            'basic_info': {
                'agent_id': str(self.AgentID),
                'hostname': self.HostName,
                'ip_address': self.IPAddress,
                'mac_address': self.MACAddress,
                'domain': self.Domain
            },
            'system_info': {
                'operating_system': self.OperatingSystem,
                'os_version': self.OSVersion,
                'architecture': self.Architecture,
                'platform_type': self.get_platform_type()
            },
            'agent_info': {
                'version': self.AgentVersion,
                'install_path': self.InstallPath,
                'status': self.Status,
                'monitoring_enabled': self.MonitoringEnabled
            },
            'connection_info': {
                'connection_status': self.get_connection_status(),
                'last_heartbeat': self.LastHeartbeat.isoformat() if self.LastHeartbeat else None,
                'first_seen': self.FirstSeen.isoformat() if self.FirstSeen else None,
                'minutes_since_heartbeat': self.get_minutes_since_heartbeat(),
                'uptime_percentage': self.get_uptime_percentage()
            },
            'performance_metrics': {
                'cpu_usage': float(self.CPUUsage) if self.CPUUsage else 0.0,
                'memory_usage': float(self.MemoryUsage) if self.MemoryUsage else 0.0,
                'disk_usage': float(self.DiskUsage) if self.DiskUsage else 0.0,
                'network_latency': self.NetworkLatency or 0
            },
            'health_status': self.get_health_status()
        }
    
    @classmethod
    def get_by_hostname(cls, session, hostname: str) -> Optional['Agent']:
        """Get agent by hostname"""
        return session.query(cls).filter(cls.HostName == hostname).first()
    
    @classmethod
    def get_by_id(cls, session, agent_id: str) -> Optional['Agent']:
        """Get agent by ID"""
        return session.query(cls).filter(cls.AgentID == agent_id).first()
    
    @classmethod
    def get_by_ip(cls, session, ip_address: str) -> Optional['Agent']:
        """Get agent by IP address"""
        return session.query(cls).filter(cls.IPAddress == ip_address).first()
    
    @classmethod
    def create_agent(cls, hostname: str, ip_address: str, operating_system: str, **kwargs) -> 'Agent':
        """Create new agent instance"""
        agent = cls(
            HostName=hostname,
            IPAddress=ip_address,
            OperatingSystem=operating_system,
            **kwargs
        )
        return agent
    
    @classmethod
    def get_online_agents_count(cls, session) -> int:
        """Get count of online agents"""
        from sqlalchemy import and_
        cutoff_time = datetime.now() - timedelta(minutes=5)
        return session.query(cls).filter(
            and_(
                cls.LastHeartbeat >= cutoff_time,
                cls.Status == 'Active'
            )
        ).count()
    
    @classmethod
    def get_offline_agents_count(cls, session) -> int:
        """Get count of offline agents"""
        cutoff_time = datetime.now() - timedelta(minutes=15)
        return session.query(cls).filter(
            or_(
                cls.LastHeartbeat < cutoff_time,
                cls.Status != 'Active'
            )
        ).count()
    
    @classmethod
    def get_online_agents(cls, session, timeout_minutes: int = 5):
        """Get currently online agents"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        return session.query(cls).filter(
            cls.Status == 'Active',
            cls.LastHeartbeat >= cutoff_time
        ).all()
    
    @classmethod
    def get_offline_agents(cls, session, timeout_minutes: int = 15):
        """Get offline agents"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        return session.query(cls).filter(
            or_(
                cls.LastHeartbeat < cutoff_time,
                cls.Status != 'Active'
            )
        ).all()
    
    @classmethod
    def get_agents_by_platform(cls, session) -> Dict:
        """Get agent count by platform"""
        results = session.query(
            cls.OperatingSystem,
            func.count(cls.AgentID).label('count')
        ).group_by(cls.OperatingSystem).all()
        
        platform_counts = {'Windows': 0, 'Linux': 0, 'macOS': 0, 'Other': 0}
        
        for os_name, count in results:
            if 'windows' in os_name.lower():
                platform_counts['Windows'] += count
            elif 'linux' in os_name.lower():
                platform_counts['Linux'] += count
            elif 'mac' in os_name.lower() or 'darwin' in os_name.lower():
                platform_counts['macOS'] += count
            else:
                platform_counts['Other'] += count
        
        return platform_counts
    
    @classmethod
    def get_unhealthy_agents(cls, session) -> List['Agent']:
        """Get list of unhealthy agents"""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        
        return session.query(cls).filter(
            or_(
                cls.LastHeartbeat < cutoff_time,
                cls.CPUUsage > 90,
                cls.MemoryUsage > 95,
                cls.DiskUsage > 90,
                cls.Status != 'Active'
            )
        ).all()
    
    @classmethod
    def get_agents_summary(cls, session) -> Dict:
        """Get agents summary statistics"""
        total_agents = session.query(cls).count()
        active_agents = session.query(cls).filter(cls.Status == 'Active').count()
        
        # Online agents (last 5 minutes)
        online_cutoff = datetime.now() - timedelta(minutes=5)
        online_agents = session.query(cls).filter(
            cls.Status == 'Active',
            cls.LastHeartbeat >= online_cutoff
        ).count()
        
        # OS breakdown
        os_breakdown = session.query(
            cls.OperatingSystem,
            func.count(cls.AgentID).label('count')
        ).group_by(cls.OperatingSystem).all()
        
        return {
            'total_agents': total_agents,
            'active_agents': active_agents,
            'online_agents': online_agents,
            'offline_agents': total_agents - online_agents,
            'inactive_agents': total_agents - active_agents,
            'os_breakdown': {os: count for os, count in os_breakdown}
        }