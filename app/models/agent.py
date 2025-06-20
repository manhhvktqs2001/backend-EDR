# app/models/agent.py - FIXED VERSION (Database Schema Compliant)
"""
Agent Model - Agents table mapping
Represents endpoint agents in the EDR system (FIXED for database compatibility)
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from sqlalchemy import Column, String, DateTime, Boolean, Numeric, Integer, or_, text
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.sql import func
from uuid import uuid4
import logging

from ..database import Base

logger = logging.getLogger(__name__)

class Agent(Base):
    """Agent model representing endpoint systems in EDR network - FIXED"""
    
    __tablename__ = 'Agents'
    
    # Primary Key - FIXED: Proper UNIQUEIDENTIFIER handling
    AgentID = Column(UNIQUEIDENTIFIER, primary_key=True, default=lambda: str(uuid4()))
    
    # Basic Information - matches NOT NULL constraints EXACTLY
    HostName = Column(String(255), nullable=False, unique=True)
    IPAddress = Column(String(45), nullable=False)
    MACAddress = Column(String(17))
    
    # System Information - matches DB schema EXACTLY
    OperatingSystem = Column(String(100), nullable=False)
    OSVersion = Column(String(100))
    Architecture = Column(String(20))
    Domain = Column(String(100))
    
    # Agent Information - matches DB defaults EXACTLY
    AgentVersion = Column(String(20), nullable=False, default='1.0.0')
    InstallPath = Column(String(500))
    
    # Status & Health - FIXED: matches DEFAULT values exactly
    Status = Column(String(20), nullable=False, default='Active')
    LastHeartbeat = Column(DateTime, nullable=False, default=func.getdate())
    FirstSeen = Column(DateTime, nullable=False, default=func.getdate())
    
    # Performance Metrics - FIXED: matches DECIMAL(5,2) DEFAULT 0.0 EXACTLY
    CPUUsage = Column(Numeric(5, 2), nullable=False, default=0.0)
    MemoryUsage = Column(Numeric(5, 2), nullable=False, default=0.0)
    DiskUsage = Column(Numeric(5, 2), nullable=False, default=0.0)
    NetworkLatency = Column(Integer, nullable=False, default=0)
    
    # Configuration - FIXED: matches BIT DEFAULT 1 EXACTLY
    MonitoringEnabled = Column(Boolean, nullable=False, default=True)
    
    # Metadata - FIXED: matches DEFAULT GETDATE() EXACTLY  
    CreatedAt = Column(DateTime, nullable=False, default=func.getdate())
    UpdatedAt = Column(DateTime, nullable=False, default=func.getdate())
    
    def __repr__(self):
        return f"<Agent(id={self.AgentID}, hostname='{self.HostName}', ip='{self.IPAddress}', status='{self.Status}')>"
    
    def to_dict(self, include_sensitive: bool = False) -> Dict:
        """Convert agent to dictionary for JSON serialization - FIXED"""
        try:
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
                # FIXED: Proper DECIMAL handling
                'cpu_usage': float(self.CPUUsage) if self.CPUUsage is not None else 0.0,
                'memory_usage': float(self.MemoryUsage) if self.MemoryUsage is not None else 0.0,
                'disk_usage': float(self.DiskUsage) if self.DiskUsage is not None else 0.0,
                'network_latency': self.NetworkLatency or 0,
                'monitoring_enabled': bool(self.MonitoringEnabled),
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
            
        except Exception as e:
            logger.error(f"Error converting agent to dict: {e}")
            return {'error': 'Conversion failed'}
    
    def to_summary(self) -> Dict:
        """Convert to summary format for lists and dashboards - FIXED"""
        try:
            return {
                'agent_id': str(self.AgentID),
                'hostname': self.HostName,
                'ip_address': self.IPAddress,
                'operating_system': self.OperatingSystem,
                'platform_type': self.get_platform_type(),
                'status': self.Status,
                'connection_status': self.get_connection_status(),
                'last_heartbeat': self.LastHeartbeat.isoformat() if self.LastHeartbeat else None,
                'cpu_usage': float(self.CPUUsage) if self.CPUUsage is not None else 0.0,
                'memory_usage': float(self.MemoryUsage) if self.MemoryUsage is not None else 0.0,
                'is_healthy': self.is_healthy(),
                'monitoring_enabled': bool(self.MonitoringEnabled)
            }
        except Exception as e:
            logger.error(f"Error creating agent summary: {e}")
            return {'error': 'Summary creation failed'}
    
    def get_platform_type(self) -> str:
        """Get simplified platform type"""
        if not self.OperatingSystem:
            return 'Unknown'
        os_lower = self.OperatingSystem.lower()
        if 'windows' in os_lower:
            return 'Windows'
        elif 'linux' in os_lower:
            return 'Linux'
        elif 'mac' in os_lower or 'darwin' in os_lower:
            return 'macOS'
        else:
            return 'Other'
    
    def get_connection_status(self) -> str:
        """Get connection status based on last heartbeat"""
        if not self.LastHeartbeat:
            return 'Unknown'
        
        try:
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
        except Exception:
            return 'Unknown'
    
    def is_online(self) -> bool:
        """Check if agent is currently online"""
        return self.get_connection_status() in ['Online', 'Warning']
    
    def is_healthy(self) -> bool:
        """Check if agent is healthy (online + good performance)"""
        if not self.is_online():
            return False
        
        try:
            # Check performance thresholds with proper None handling
            cpu_threshold = 90.0
            memory_threshold = 95.0
            disk_threshold = 90.0
            
            if self.CPUUsage is not None and float(self.CPUUsage) > cpu_threshold:
                return False
            if self.MemoryUsage is not None and float(self.MemoryUsage) > memory_threshold:
                return False
            if self.DiskUsage is not None and float(self.DiskUsage) > disk_threshold:
                return False
            
            return True
        except Exception:
            return False
    
    def get_minutes_since_heartbeat(self) -> int:
        """Get minutes since last heartbeat"""
        if not self.LastHeartbeat:
            return 999999  # Large number for never seen
        
        try:
            now = datetime.now()
            time_diff = now - self.LastHeartbeat
            return int(time_diff.total_seconds() / 60)
        except Exception:
            return 999999
    
    def get_health_status(self) -> Dict:
        """Get detailed health status with recommendations"""
        status = {
            'overall': 'Healthy',
            'connection': self.get_connection_status(),
            'performance': 'Good',
            'issues': [],
            'recommendations': []
        }
        
        try:
            # Check connection
            if not self.is_online():
                status['overall'] = 'Unhealthy'
                status['issues'].append('Agent is offline or not responding')
                status['recommendations'].append('Check agent service and network connectivity')
            
            # Check performance metrics with proper None handling
            if self.CPUUsage is not None:
                cpu_val = float(self.CPUUsage)
                if cpu_val > 80:
                    status['performance'] = 'Poor' if cpu_val > 90 else 'Degraded'
                    status['issues'].append(f'High CPU usage: {cpu_val:.1f}%')
                    if cpu_val > 90:
                        status['recommendations'].append('Investigate high CPU usage processes')
            
            if self.MemoryUsage is not None:
                mem_val = float(self.MemoryUsage)
                if mem_val > 85:
                    status['performance'] = 'Poor' if mem_val > 95 else 'Degraded'
                    status['issues'].append(f'High memory usage: {mem_val:.1f}%')
                    if mem_val > 95:
                        status['recommendations'].append('Check for memory leaks or high memory processes')
            
            if self.DiskUsage is not None:
                disk_val = float(self.DiskUsage)
                if disk_val > 80:
                    status['performance'] = 'Poor' if disk_val > 90 else 'Degraded'
                    status['issues'].append(f'High disk usage: {disk_val:.1f}%')
                    if disk_val > 90:
                        status['recommendations'].append('Clean up disk space or investigate disk usage')
            
            if self.NetworkLatency is not None and self.NetworkLatency > 200:
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
            
        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            status['overall'] = 'Error'
            status['issues'].append('Health check failed')
        
        return status
    
    def update_heartbeat(self, performance_data: Dict = None) -> None:
        """Update heartbeat with optional performance data - FIXED"""
        try:
            self.LastHeartbeat = datetime.now()
            
            if performance_data:
                # FIXED: Proper DECIMAL handling with validation
                if 'cpu_usage' in performance_data:
                    cpu_val = float(performance_data['cpu_usage'])
                    self.CPUUsage = max(0.0, min(100.0, cpu_val))  # Clamp 0-100
                    
                if 'memory_usage' in performance_data:
                    mem_val = float(performance_data['memory_usage'])
                    self.MemoryUsage = max(0.0, min(100.0, mem_val))  # Clamp 0-100
                    
                if 'disk_usage' in performance_data:
                    disk_val = float(performance_data['disk_usage'])
                    self.DiskUsage = max(0.0, min(100.0, disk_val))  # Clamp 0-100
                    
                if 'network_latency' in performance_data:
                    latency_val = int(performance_data['network_latency'])
                    self.NetworkLatency = max(0, latency_val)  # Non-negative
            
            # REMOVED: UpdatedAt auto-update to avoid trigger conflicts
            
        except Exception as e:
            logger.error(f"Error updating heartbeat: {e}")
            # Still update heartbeat time even if performance data fails
            self.LastHeartbeat = datetime.now()
    
    def set_status(self, status: str) -> None:
        """Set agent status - FIXED with validation"""
        valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
        if status not in valid_statuses:
            raise ValueError(f"Invalid status: {status}. Valid statuses: {valid_statuses}")
        
        self.Status = status
        # REMOVED: UpdatedAt to avoid trigger conflicts
    
    def enable_monitoring(self) -> None:
        """Enable monitoring for agent"""
        self.MonitoringEnabled = True
    
    def disable_monitoring(self) -> None:
        """Disable monitoring for agent"""
        self.MonitoringEnabled = False
    
    @classmethod
    def get_by_hostname(cls, session, hostname: str) -> Optional['Agent']:
        """Get agent by hostname - FIXED"""
        try:
            return session.query(cls).filter(cls.HostName == hostname).first()
        except Exception as e:
            logger.error(f"Error getting agent by hostname: {e}")
            return None
    
    @classmethod
    def get_by_id(cls, session, agent_id: str) -> Optional['Agent']:
        """Get agent by ID - FIXED with proper UUID handling"""
        try:
            # Handle both string and UUID formats
            if isinstance(agent_id, str):
                from uuid import UUID
                try:
                    UUID(agent_id)
                except Exception:
                    logger.error(f"Invalid agent_id format: {agent_id}")
                    return None
            return session.query(cls).filter(cls.AgentID == agent_id).first()
        except Exception as e:
            logger.error(f"Error getting agent by ID: {e}")
            return None
    
    @classmethod
    def get_by_ip(cls, session, ip_address: str) -> Optional['Agent']:
        """Get agent by IP address"""
        try:
            return session.query(cls).filter(cls.IPAddress == ip_address).first()
        except Exception as e:
            logger.error(f"Error getting agent by IP: {e}")
            return None
    
    @classmethod
    def create_agent(cls, hostname: str, ip_address: str, operating_system: str, **kwargs) -> 'Agent':
        """Create new agent instance - FIXED"""
        try:
            # Validate required fields
            if not hostname or not ip_address or not operating_system:
                raise ValueError("hostname, ip_address, and operating_system are required")
            
            # FIXED: Proper field mapping to match DB schema exactly
            agent = cls(
                AgentID=str(uuid4()),  # Generate UUID as string
                HostName=hostname[:255],  # Truncate to max length
                IPAddress=ip_address[:45],  # Truncate to max length
                OperatingSystem=operating_system[:100],  # Truncate to max length
                **{k: v for k, v in kwargs.items() if hasattr(cls, k)}  # Only valid attributes
            )
            return agent
            
        except Exception as e:
            logger.error(f"Error creating agent: {e}")
            raise ValueError(f"Failed to create agent: {e}")
    
    @classmethod
    def get_agents_summary(cls, session) -> Dict:
        """Get agents summary statistics - FIXED"""
        try:
            total_agents = session.query(cls).count()
            active_agents = session.query(cls).filter(cls.Status == 'Active').count()
            
            # Online agents (last 5 minutes) - FIXED timezone handling
            online_cutoff = datetime.now() - timedelta(minutes=5)
            online_agents = session.query(cls).filter(
                cls.Status == 'Active',
                cls.LastHeartbeat >= online_cutoff
            ).count()
            
            # OS breakdown - FIXED with error handling
            try:
                os_breakdown = session.query(
                    cls.OperatingSystem,
                    func.count(cls.AgentID).label('count')
                ).group_by(cls.OperatingSystem).all()
                os_dict = {os: count for os, count in os_breakdown}
            except Exception:
                os_dict = {}
            
            return {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'online_agents': online_agents,
                'offline_agents': total_agents - online_agents,
                'inactive_agents': total_agents - active_agents,
                'os_breakdown': os_dict
            }
            
        except Exception as e:
            logger.error(f"Error getting agents summary: {e}")
            return {
                'total_agents': 0,
                'active_agents': 0,
                'online_agents': 0,
                'offline_agents': 0,
                'inactive_agents': 0,
                'os_breakdown': {}
            }