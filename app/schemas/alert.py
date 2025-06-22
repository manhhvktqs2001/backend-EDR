# app/schemas/alert.py - MODIFIED (Add Agent Alert Submission Schemas)
"""
Alert API Schemas - MODIFIED
Added schemas for agent to submit alerts back to server
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Alert Status and Severity Enums
class AlertStatus(str, Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"
    SUPPRESSED = "Suppressed"

class AlertSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AlertPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

# NEW: Agent Alert Submission Schemas
class AgentAlertSubmission(BaseModel):
    """Schema for agent alert submission"""
    agent_id: str
    alert_type: str
    title: str
    severity: str
    detection_method: str
    description: str
    risk_score: Optional[int] = 50
    confidence: Optional[float] = 0.8
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    event_id: Optional[int] = None
    detected_at: Optional[str] = None

class AgentAlertResponse(BaseModel):
    """Schema for server response to agent alert submission - NEW"""
    success: bool
    alert_id: Optional[int] = None
    message: str
    correlation_alerts: List[int] = Field(default=[], description="Correlated alert IDs")
    recommended_actions: List[str] = Field(default=[], description="Recommended actions")

# Existing schemas remain the same...
class AlertStatusUpdateRequest(BaseModel):
    """Schema for updating alert status"""
    status: AlertStatus = Field(..., description="New alert status")
    assigned_to: Optional[str] = Field(None, description="Analyst assigned to alert")
    resolved_by: Optional[str] = Field(None, description="Who resolved the alert")
    response_action: Optional[str] = Field(None, description="Action taken on the alert")
    notes: Optional[str] = Field(None, description="Additional notes")

class AlertBulkUpdateRequest(BaseModel):
    """Schema for bulk alert updates"""
    alert_ids: List[int] = Field(..., description="List of alert IDs to update")
    status: AlertStatus = Field(..., description="New status for all alerts")
    assigned_to: Optional[str] = Field(None, description="Analyst to assign alerts to")
    notes: Optional[str] = Field(None, description="Bulk update notes")

# Alert Response Schemas
class AlertResponse(BaseModel):
    """Schema for detailed alert response"""
    alert_id: int
    agent_id: str
    event_id: Optional[int]
    rule_id: Optional[int]
    threat_id: Optional[int]
    alert_type: str
    title: str
    description: Optional[str]
    severity: str
    priority: str
    confidence: float
    detection_method: str
    risk_score: int
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    status: str
    assigned_to: Optional[str]
    first_detected: Optional[datetime]
    last_detected: Optional[datetime]
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]
    event_count: int
    response_action: Optional[str] = None
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    age_minutes: int
    is_critical: bool
    is_open: bool
    
    # Additional contextual information
    agent_hostname: Optional[str] = None
    agent_ip: Optional[str] = None
    agent_os: Optional[str] = None
    event_details: Optional[Dict] = None
    rule_details: Optional[Dict] = None
    threat_details: Optional[Dict] = None

class AlertSummary(BaseModel):
    """Schema for alert summary in lists"""
    alert_id: int
    agent_id: str
    alert_type: str
    title: str
    severity: str
    status: str
    detection_method: str
    first_detected: Optional[datetime]
    event_count: int
    age_minutes: int
    hostname: Optional[str] = None
    agent_ip: Optional[str] = None

class AlertListResponse(BaseModel):
    """Schema for alert list response"""
    alerts: List[AlertSummary]
    total_count: int
    open_count: int
    critical_count: int
    page: int
    page_size: int
    filters_applied: Dict

class AlertStatusUpdateResponse(BaseModel):
    """Schema for alert status update response"""
    success: bool
    message: str
    alert_id: int
    new_status: str
    updated_by: Optional[str]
    updated_at: Optional[str]

class AlertStatsResponse(BaseModel):
    """Schema for alert statistics response"""
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    resolved_alerts: int
    time_range_hours: int
    status_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]
    detection_method_breakdown: Dict[str, int]
    top_alert_types: List[Dict[str, Any]]
    mitre_tactics: List[Dict[str, Any]]

# Keep all other existing schemas unchanged...
class AlertSearchRequest(BaseModel):
    """Schema for alert search request"""
    agent_id: Optional[str] = None
    status: Optional[AlertStatus] = None
    severity: Optional[AlertSeverity] = None
    alert_type: Optional[str] = None
    detection_method: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    assigned_to: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search_text: Optional[str] = None
    risk_score_min: Optional[int] = Field(None, ge=0, le=100)
    risk_score_max: Optional[int] = Field(None, ge=0, le=100)
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)