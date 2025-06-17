# app/schemas/agent.py - Fixed field_validator usage
"""
Agent API Schemas
Pydantic models for agent-related API requests and responses
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict
from datetime import datetime
import ipaddress

# Agent Registration Schemas
class AgentRegisterRequest(BaseModel):
    """Schema for agent registration request"""
    hostname: str = Field(..., min_length=1, max_length=255, description="Agent hostname")
    ip_address: str = Field(..., description="Agent IP address")
    operating_system: str = Field(..., description="Operating system name")
    os_version: Optional[str] = Field(None, description="OS version")
    architecture: Optional[str] = Field(None, description="System architecture")
    agent_version: str = Field(default="1.0.0", description="Agent version")
    mac_address: Optional[str] = Field(None, description="MAC address")
    domain: Optional[str] = Field(None, description="Domain name")
    install_path: Optional[str] = Field(None, description="Agent installation path")
    
    @field_validator('hostname')
    @classmethod
    def validate_hostname(cls, v):
        if not v or v.isspace():
            raise ValueError('Hostname cannot be empty')
        return v.strip()
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip_address(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')
    
    @field_validator('mac_address')
    @classmethod
    def validate_mac_address(cls, v):
        if v is None:
            return v
        # Basic MAC address validation
        if len(v) == 17 and v.count(':') == 5:
            return v.upper()
        elif len(v) == 17 and v.count('-') == 5:
            return v.replace('-', ':').upper()
        else:
            raise ValueError('Invalid MAC address format')

class AgentRegisterResponse(BaseModel):
    """Schema for agent registration response"""
    success: bool
    agent_id: str
    message: str
    config_version: str = "1.0"
    heartbeat_interval: int = 30
    monitoring_enabled: bool = True

# Agent Heartbeat Schemas
class AgentHeartbeatRequest(BaseModel):
    """Schema for agent heartbeat request"""
    hostname: str = Field(..., description="Agent hostname")
    status: Optional[str] = Field(None, description="Agent status")
    cpu_usage: float = Field(default=0.0, ge=0.0, le=100.0, description="CPU usage percentage")
    memory_usage: float = Field(default=0.0, ge=0.0, le=100.0, description="Memory usage percentage")
    disk_usage: float = Field(default=0.0, ge=0.0, le=100.0, description="Disk usage percentage")
    network_latency: int = Field(default=0, ge=0, description="Network latency in milliseconds")
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        if v is not None:
            valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
            if v not in valid_statuses:
                raise ValueError(f'Status must be one of {valid_statuses}')
        return v

class AgentHeartbeatResponse(BaseModel):
    """Schema for agent heartbeat response"""
    success: bool
    message: str
    config_version: str = "1.0"
    monitoring_enabled: bool = True
    next_heartbeat: int = 30  # seconds

# Agent Configuration Schemas
class AgentConfigResponse(BaseModel):
    """Schema for agent configuration response"""
    agent_id: str
    hostname: str
    config_version: str
    monitoring_enabled: bool
    heartbeat_interval: int
    event_batch_size: int
    collection_settings: Dict
    detection_settings: Dict

class AgentStatusUpdate(BaseModel):
    """Schema for updating agent status"""
    status: str
    monitoring_enabled: Optional[bool] = None
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
        if v not in valid_statuses:
            raise ValueError(f'Status must be one of {valid_statuses}')
        return v

# Agent Response Schemas
class AgentResponse(BaseModel):
    """Schema for single agent response"""
    agent_id: str
    hostname: str
    ip_address: str
    mac_address: Optional[str]
    operating_system: str
    os_version: Optional[str]
    architecture: Optional[str]
    domain: Optional[str]
    agent_version: str
    install_path: Optional[str]
    status: str
    last_heartbeat: Optional[datetime]
    first_seen: Optional[datetime]
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_latency: int
    monitoring_enabled: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    connection_status: str
    is_online: bool
    minutes_since_heartbeat: int
    health_status: Dict

class AgentSummary(BaseModel):
    """Schema for agent summary"""
    agent_id: str
    hostname: str
    ip_address: str
    operating_system: str
    status: str
    connection_status: str
    last_heartbeat: Optional[datetime]
    cpu_usage: float
    memory_usage: float

class AgentListResponse(BaseModel):
    """Schema for agent list response"""
    agents: List[AgentSummary]
    total_count: int
    online_count: int
    offline_count: int
    summary: Dict

class AgentStatsResponse(BaseModel):
    """Schema for agent statistics response"""
    total_agents: int
    active_agents: int
    online_agents: int
    offline_agents: int
    inactive_agents: int
    os_breakdown: Dict[str, int]
    connection_status_breakdown: Dict[str, int]
    performance_summary: Dict