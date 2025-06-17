# app/schemas/dashboard.py - Fixed Pydantic 2.0 compatibility
"""
Dashboard API Schemas
Pydantic models for dashboard-related API responses
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

# Main Dashboard Stats Response
class DashboardStatsResponse(BaseModel):
    """Schema for main dashboard statistics"""
    agents: Dict[str, int] = Field(..., description="Agent statistics")
    events: Dict[str, int] = Field(..., description="Event statistics")
    alerts: Dict[str, int] = Field(..., description="Alert statistics")
    threats: Dict[str, int] = Field(..., description="Threat statistics")
    detection: Dict[str, Any] = Field(..., description="Detection engine statistics")
    system_health: Dict[str, Any] = Field(..., description="System health metrics")

# Agent Overview Schemas
class AgentOverviewResponse(BaseModel):
    """Schema for agent overview dashboard"""
    summary: Dict[str, Any] = Field(..., description="Agent summary statistics")
    status_distribution: Dict[str, int] = Field(..., description="Distribution by status")
    os_distribution: Dict[str, int] = Field(..., description="Distribution by OS")
    recent_activity: Dict[str, int] = Field(..., description="Recent agent activity")
    performance_issues: List[Dict[str, Any]] = Field(..., description="Agents with performance issues")
    top_event_generators: List[Dict[str, Any]] = Field(..., description="Top agents by event volume")

class AlertOverviewResponse(BaseModel):
    """Schema for alert overview dashboard"""
    summary: Dict[str, int] = Field(..., description="Alert summary statistics")
    severity_distribution: Dict[str, int] = Field(..., description="Distribution by severity")
    status_distribution: Dict[str, int] = Field(..., description="Distribution by status")
    top_alert_types: List[Dict[str, Any]] = Field(..., description="Most common alert types")
    mitre_tactics: List[Dict[str, Any]] = Field(..., description="MITRE ATT&CK tactics")
    recent_critical_alerts: List[Dict[str, Any]] = Field(..., description="Recent critical alerts")
    hourly_timeline: List[Dict[str, int]] = Field(..., description="Hourly alert timeline")
    time_range_hours: int = Field(..., description="Time range for statistics")

class EventTimelineResponse(BaseModel):
    """Schema for event timeline dashboard"""
    timeline: List[Dict[str, Any]] = Field(..., description="Event timeline data")
    threat_timeline: List[Dict[str, Any]] = Field(..., description="Threat event timeline")
    granularity: str = Field(..., description="Timeline granularity (hour/minute)")
    time_range_hours: int = Field(..., description="Time range for timeline")
    total_events: int = Field(..., description="Total events in timeline")
    total_threats: int = Field(..., description="Total threat events in timeline")

class ThreatOverviewResponse(BaseModel):
    """Schema for threat overview dashboard"""
    summary: Dict[str, int] = Field(..., description="Threat summary statistics")
    recent_detections: List[Dict[str, Any]] = Field(..., description="Recent threat detections")
    category_distribution: Dict[str, int] = Field(..., description="Distribution by category")
    mitre_tactics: List[Dict[str, Any]] = Field(..., description="MITRE tactics from threats")
    source_distribution: Dict[str, int] = Field(..., description="Distribution by source")
    time_range_hours: int = Field(..., description="Time range for statistics")

class SystemOverviewResponse(BaseModel):
    """Schema for system overview dashboard"""
    database: Dict[str, Any] = Field(..., description="Database status and metrics")
    performance: Dict[str, Any] = Field(..., description="System performance metrics")
    system_health: Dict[str, Any] = Field(..., description="Overall system health")
    resource_usage: Dict[str, float] = Field(..., description="Resource utilization")

# Report and Export Schemas
class DashboardReportRequest(BaseModel):
    """Schema for dashboard report generation"""
    report_type: str = Field(..., pattern=r"^(summary|detailed|executive|technical)$")
    time_range_hours: int = Field(default=24, ge=1, le=8760)
    include_sections: List[str] = Field(default=["agents", "events", "alerts", "threats"])
    format: str = Field(default="pdf", pattern=r"^(pdf|html|json)$")

class DashboardReportResponse(BaseModel):
    """Schema for dashboard report response"""
    success: bool
    report_id: str
    report_type: str
    generated_at: datetime
    file_path: Optional[str]
    download_url: Optional[str]
    expires_at: datetime