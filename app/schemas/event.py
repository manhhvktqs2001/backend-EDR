# app/schemas/event.py - Complete Fixed Version
"""
Event API Schemas
Pydantic models for event-related API requests and responses
"""

from pydantic import BaseModel, Field, field_validator
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

# Event Submission Schema
class GeneratedAlert(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    risk_score: int
    timestamp: str
    detection_method: str

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
    
    @field_validator('events')
    @classmethod
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
    event_id: int
    threat_detected: bool = False
    risk_score: int = 0
    alerts_generated: List[GeneratedAlert] = []

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

# Event Search Schema - FIXED
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