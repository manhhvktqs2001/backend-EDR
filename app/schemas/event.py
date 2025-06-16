"""
Event API Schemas
Pydantic models for event-related API requests and responses
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Event Type Enums
class EventType(str, Enum):
    PROCESS = "Process"
    FILE = "File"
    NETWORK = "Network"
    REGISTRY = "Registry"
    AUTHENTICATION = "Authentication"
    SYSTEM = "System"

class EventSeverity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ThreatLevel(str, Enum):
    NONE = "None"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"

# Base Event Schema
class EventBase(BaseModel):
    """Base event schema with common fields"""
    agent_id: str = Field(..., description="Agent ID that generated the event")
    event_type: EventType = Field(..., description="Type of event")
    event_action: str = Field(..., description="Action that occurred")
    event_timestamp: datetime = Field(..., description="When the event occurred")
    severity: EventSeverity = Field(default=EventSeverity.INFO, description="Event severity")

# Process Event Schema
class ProcessEventRequest(EventBase):
    """Schema for process event submission"""
    event_type: EventType = Field(default=EventType.PROCESS, description="Must be Process")
    process_id: Optional[int] = Field(None, description="Process ID")
    process_name: Optional[str] = Field(None, description="Process name")
    process_path: Optional[str] = Field(None, description="Process executable path")
    command_line: Optional[str] = Field(None, description="Command line arguments")
    parent_pid: Optional[int] = Field(None, description="Parent process ID")
    parent_process_name: Optional[str] = Field(None, description="Parent process name")
    process_user: Optional[str] = Field(None, description="User context")
    process_hash: Optional[str] = Field(None, description="Process file hash")

# File Event Schema
class FileEventRequest(EventBase):
    """Schema for file event submission"""
    event_type: EventType = Field(default=EventType.FILE, description="Must be File")
    file_path: Optional[str] = Field(None, description="Full file path")
    file_name: Optional[str] = Field(None, description="File name")
    file_size: Optional[int] = Field(None, description="File size in bytes")
    file_hash: Optional[str] = Field(None, description="File hash (SHA-256)")
    file_extension: Optional[str] = Field(None, description="File extension")
    file_operation: Optional[str] = Field(None, description="File operation (Create, Delete, Modify)")

# Network Event Schema
class NetworkEventRequest(EventBase):
    """Schema for network event submission"""
    event_type: EventType = Field(default=EventType.NETWORK, description="Must be Network")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field(None, description="Network protocol")
    direction: Optional[str] = Field(None, description="Traffic direction")

# Registry Event Schema (Windows)
class RegistryEventRequest(EventBase):
    """Schema for registry event submission"""
    event_type: EventType = Field(default=EventType.REGISTRY, description="Must be Registry")
    registry_key: Optional[str] = Field(None, description="Registry key path")
    registry_value_name: Optional[str] = Field(None, description="Registry value name")
    registry_value_data: Optional[str] = Field(None, description="Registry value data")
    registry_operation: Optional[str] = Field(None, description="Registry operation")

# Authentication Event Schema
class AuthenticationEventRequest(EventBase):
    """Schema for authentication event submission"""
    event_type: EventType = Field(default=EventType.AUTHENTICATION, description="Must be Authentication")
    login_user: Optional[str] = Field(None, description="Username")
    login_type: Optional[str] = Field(None, description="Login type")
    login_result: Optional[str] = Field(None, description="Login result (Success/Failed)")

# Generic Event Submission Schema
class EventSubmissionRequest(BaseModel):
    """Schema for generic event submission"""
    agent_id: str = Field(..., description="Agent ID")
    event_type: EventType = Field(..., description="Event type")
    event_action: str = Field(..., description="Event action")
    event_timestamp: datetime = Field(..., description="Event timestamp")
    severity: EventSeverity = Field(default=EventSeverity.INFO, description="Severity")
    
    # Optional fields for all event types
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    process_user: Optional[str] = None
    process_hash: Optional[str] = None
    
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    file_extension: Optional[str] = None
    file_operation: Optional[str] = None
    
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None
    registry_value_data: Optional[str] = None
    registry_operation: Optional[str] = None
    
    login_user: Optional[str] = None
    login_type: Optional[str] = None
    login_result: Optional[str] = None
    
    raw_event_data: Optional[Dict[str, Any]] = None

# Batch Event Submission
class EventBatchRequest(BaseModel):
    """Schema for batch event submission"""
    agent_id: str = Field(..., description="Agent ID")
    events: List[EventSubmissionRequest] = Field(..., description="List of events")
    
    @validator('events')
    def validate_events_limit(cls, v):
        if len(v) > 1000:
            raise ValueError('Maximum 1000 events per batch')
        return v

# Event Response Schemas
class EventResponse(BaseModel):
    """Schema for event response"""
    event_id: int
    agent_id: str
    event_type: str
    event_action: str
    event_timestamp: datetime
    severity: str
    threat_level: str
    risk_score: int
    analyzed: bool
    analyzed_at: Optional[datetime]
    created_at: datetime
    primary_indicator: Optional[str]

class EventSummary(BaseModel):
    """Schema for event summary"""
    event_id: int
    agent_id: str
    event_type: str
    event_action: str
    event_timestamp: datetime
    severity: str
    threat_level: str
    risk_score: int
    primary_indicator: Optional[str]

class EventListResponse(BaseModel):
    """Schema for event list response"""
    events: List[EventSummary]
    total_count: int
    page: int
    page_size: int
    filters_applied: Dict

class EventSubmissionResponse(BaseModel):
    """Schema for event submission response"""
    success: bool
    message: str
    event_id: Optional[int] = None
    threat_detected: bool = False
    risk_score: int = 0
    alerts_generated: List[int] = []

class EventBatchResponse(BaseModel):
    """Schema for batch event submission response"""
    success: bool
    message: str
    total_events: int
    processed_events: int
    failed_events: int
    alerts_generated: List[int] = []
    errors: List[str] = []

# Event Statistics
class EventStats(BaseModel):
    """Schema for event statistics"""
    total_events: int
    time_range_hours: int
    type_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]
    threat_breakdown: Dict[str, int]
    analyzed_count: int
    top_agents: List[Dict[str, Any]]

class EventTimeline(BaseModel):
    """Schema for event timeline"""
    hour: int
    event_type: str
    severity: str
    event_count: int
    threat_events: int

# Event Analysis Schemas
class EventAnalysisRequest(BaseModel):
    """Schema for manual event analysis request"""
    event_id: int
    force_reanalysis: bool = False

class EventAnalysisResponse(BaseModel):
    """Schema for event analysis response"""
    event_id: int
    threat_level: str
    risk_score: int
    detection_methods: List[str]
    matched_rules: List[int]
    matched_threats: List[int]
    recommendations: List[str]

# Event Search and Filter Schemas
class EventSearchRequest(BaseModel):
    """Schema for event search request"""
    agent_id: Optional[str] = None
    event_type: Optional[EventType] = None
    severity: Optional[EventSeverity] = None
    threat_level: Optional[ThreatLevel] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search_text: Optional[str] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)

class EventExportRequest(BaseModel):
    """Schema for event export request"""
    agent_id: Optional[str] = None
    start_time: datetime
    end_time: datetime
    event_types: Optional[List[EventType]] = None
    format: str = Field(default="json", regex="^(json|csv|xlsx)$")
    include_raw_data: bool = False