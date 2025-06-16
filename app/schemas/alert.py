"""
Alert API Schemas
Pydantic models for alert-related API requests and responses
"""

from pydantic import BaseModel, Field, validator
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

# Alert Request Schemas
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

# Alert Search and Filter Schemas
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

class AlertExportRequest(BaseModel):
    """Schema for alert export request"""
    alert_ids: Optional[List[int]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: Optional[List[AlertStatus]] = None
    severity: Optional[List[AlertSeverity]] = None
    format: str = Field(default="json", regex="^(json|csv|xlsx)$")
    include_event_details: bool = False
    include_rule_details: bool = False

# Alert Analysis and Reporting Schemas
class AlertTrendAnalysis(BaseModel):
    """Schema for alert trend analysis"""
    time_period: str
    total_alerts: int
    alert_types: Dict[str, int]
    severity_trends: Dict[str, List[int]]
    detection_method_trends: Dict[str, List[int]]
    top_affected_agents: List[Dict[str, Any]]
    mitre_tactics_frequency: Dict[str, int]

class AlertCorrelationRequest(BaseModel):
    """Schema for alert correlation request"""
    alert_id: int
    correlation_window_hours: int = Field(default=24, ge=1, le=168)
    correlation_criteria: List[str] = Field(default=["agent_id", "alert_type", "mitre_tactic"])

class AlertCorrelationResponse(BaseModel):
    """Schema for alert correlation response"""
    source_alert_id: int
    correlated_alerts: List[AlertSummary]
    correlation_score: float
    correlation_criteria: List[str]
    time_window_hours: int
    analysis_summary: str

# Alert Workflow Schemas
class AlertEscalationRequest(BaseModel):
    """Schema for alert escalation"""
    alert_id: int
    escalation_reason: str
    escalated_by: str
    escalated_to: str
    escalation_notes: Optional[str] = None

class AlertEscalationResponse(BaseModel):
    """Schema for alert escalation response"""
    success: bool
    message: str
    alert_id: int
    escalated_from: str
    escalated_to: str
    escalation_timestamp: datetime

# Alert Metrics and KPIs
class AlertMetrics(BaseModel):
    """Schema for alert metrics and KPIs"""
    time_period: str
    total_alerts_generated: int
    total_alerts_resolved: int
    average_resolution_time_hours: float
    false_positive_rate: float
    critical_alerts_percentage: float
    top_detection_methods: List[Dict[str, Any]]
    alert_volume_trend: List[Dict[str, Any]]
    mean_time_to_acknowledge: float
    mean_time_to_resolve: float

class AlertDashboardSummary(BaseModel):
    """Schema for alert dashboard summary"""
    current_open_alerts: int
    critical_alerts_requiring_attention: int
    alerts_last_24_hours: int
    alerts_resolved_last_24_hours: int
    average_response_time_minutes: float
    top_alert_types_today: List[Dict[str, Any]]
    top_affected_agents: List[Dict[str, Any]]
    recent_critical_alerts: List[AlertSummary]
    alert_severity_distribution: Dict[str, int]
    detection_effectiveness: Dict[str, float]

# Alert Notification Schemas
class AlertNotificationRequest(BaseModel):
    """Schema for alert notification configuration"""
    alert_id: int
    notification_type: str = Field(..., regex="^(email|sms|webhook|slack)$")
    recipients: List[str]
    message_template: Optional[str] = None
    immediate: bool = True

class AlertNotificationResponse(BaseModel):
    """Schema for alert notification response"""
    success: bool
    message: str
    alert_id: int
    notification_type: str
    recipients_notified: List[str]
    notification_timestamp: datetime

# Alert Rule and Detection Schemas
class AlertSuppressionRule(BaseModel):
    """Schema for alert suppression rules"""
    rule_name: str
    alert_type: Optional[str] = None
    agent_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    suppression_duration_hours: int = Field(..., ge=1, le=8760)  # Max 1 year
    reason: str
    created_by: str
    is_active: bool = True

class AlertSuppressionRuleResponse(BaseModel):
    """Schema for alert suppression rule response"""
    rule_id: int
    rule_name: str
    alert_type: Optional[str]
    agent_id: Optional[str]
    mitre_tactic: Optional[str]
    suppression_duration_hours: int
    reason: str
    created_by: str
    created_at: datetime
    is_active: bool
    alerts_suppressed_count: int

# Alert Quality and Feedback Schemas
class AlertFeedbackRequest(BaseModel):
    """Schema for alert quality feedback"""
    alert_id: int
    feedback_type: str = Field(..., regex="^(accurate|false_positive|needs_tuning|informational)$")
    feedback_notes: Optional[str] = None
    analyst: str
    confidence_rating: int = Field(..., ge=1, le=5)

class AlertFeedbackResponse(BaseModel):
    """Schema for alert feedback response"""
    success: bool
    message: str
    alert_id: int
    feedback_type: str
    analyst: str
    feedback_timestamp: datetime