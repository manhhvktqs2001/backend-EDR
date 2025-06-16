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

class AgentHealthMetrics(BaseModel):
    """Schema for agent health metrics"""
    agent_id: str
    hostname: str
    ip_address: str
    status: str
    connection_status: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_latency: int
    last_heartbeat: Optional[datetime]
    health_score: float
    issues: List[str]

# Alert Overview Schemas
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

class AlertTrendData(BaseModel):
    """Schema for alert trend analysis"""
    time_period: str
    alert_count: int
    severity_breakdown: Dict[str, int]
    resolution_rate: float
    false_positive_rate: float
    average_response_time: float

# Event Timeline Schemas
class EventTimelineResponse(BaseModel):
    """Schema for event timeline dashboard"""
    timeline: List[Dict[str, Any]] = Field(..., description="Event timeline data")
    threat_timeline: List[Dict[str, Any]] = Field(..., description="Threat event timeline")
    granularity: str = Field(..., description="Timeline granularity (hour/minute)")
    time_range_hours: int = Field(..., description="Time range for timeline")
    total_events: int = Field(..., description="Total events in timeline")
    total_threats: int = Field(..., description="Total threat events in timeline")

class EventVolumeMetrics(BaseModel):
    """Schema for event volume metrics"""
    timestamp: datetime
    event_type: str
    event_count: int
    threat_events: int
    severity_breakdown: Dict[str, int]
    top_processes: List[str]
    top_files: List[str]
    network_connections: int

# Threat Overview Schemas
class ThreatOverviewResponse(BaseModel):
    """Schema for threat overview dashboard"""
    summary: Dict[str, int] = Field(..., description="Threat summary statistics")
    recent_detections: List[Dict[str, Any]] = Field(..., description="Recent threat detections")
    category_distribution: Dict[str, int] = Field(..., description="Distribution by category")
    mitre_tactics: List[Dict[str, Any]] = Field(..., description="MITRE tactics from threats")
    source_distribution: Dict[str, int] = Field(..., description="Distribution by source")
    time_range_hours: int = Field(..., description="Time range for statistics")

class ThreatIntelligenceMetrics(BaseModel):
    """Schema for threat intelligence metrics"""
    total_indicators: int
    active_indicators: int
    indicator_types: Dict[str, int]
    confidence_distribution: Dict[str, int]
    recent_updates: List[Dict[str, Any]]
    detection_coverage: float
    source_reliability: Dict[str, float]

# System Overview Schemas
class SystemOverviewResponse(BaseModel):
    """Schema for system overview dashboard"""
    database: Dict[str, Any] = Field(..., description="Database status and metrics")
    performance: Dict[str, Any] = Field(..., description="System performance metrics")
    system_health: Dict[str, Any] = Field(..., description="Overall system health")
    resource_usage: Dict[str, float] = Field(..., description="Resource utilization")

class SystemPerformanceMetrics(BaseModel):
    """Schema for system performance metrics"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: float
    database_response_time: float
    event_processing_rate: float
    alert_generation_rate: float
    detection_latency: float

# Detection Engine Schemas
class DetectionEngineMetrics(BaseModel):
    """Schema for detection engine metrics"""
    rules_active: int
    rules_total: int
    detection_rate: float
    false_positive_rate: float
    threat_intel_hits: int
    ml_detections: int
    behavioral_detections: int
    signature_detections: int
    processing_latency: float
    rule_performance: List[Dict[str, Any]]

class RulePerformanceMetrics(BaseModel):
    """Schema for individual rule performance"""
    rule_id: int
    rule_name: str
    trigger_count: int
    false_positive_count: int
    accuracy_rate: float
    processing_time: float
    last_triggered: Optional[datetime]
    effectiveness_score: float

# Network and Geographic Schemas
class NetworkActivityMetrics(BaseModel):
    """Schema for network activity metrics"""
    total_connections: int
    unique_destinations: int
    suspicious_connections: int
    blocked_connections: int
    top_destinations: List[Dict[str, Any]]
    protocol_distribution: Dict[str, int]
    geographic_distribution: Dict[str, int]
    bandwidth_usage: float

class GeographicThreatData(BaseModel):
    """Schema for geographic threat distribution"""
    country_code: str
    country_name: str
    threat_count: int
    threat_types: List[str]
    risk_score: float
    coordinates: List[float]

# Real-time Dashboard Schemas
class RealTimeDashboardUpdate(BaseModel):
    """Schema for real-time dashboard updates"""
    timestamp: datetime
    agents_online: int
    events_last_minute: int
    alerts_last_minute: int
    critical_alerts_open: int
    system_health_score: float
    recent_events: List[Dict[str, Any]]
    recent_alerts: List[Dict[str, Any]]
    performance_metrics: Dict[str, float]

class LiveActivityFeed(BaseModel):
    """Schema for live activity feed"""
    activity_type: str  # event, alert, agent_connect, agent_disconnect
    timestamp: datetime
    description: str
    severity: str
    agent_info: Dict[str, str]
    additional_data: Optional[Dict[str, Any]]

# Report and Export Schemas
class DashboardReportRequest(BaseModel):
    """Schema for dashboard report generation"""
    report_type: str = Field(..., regex="^(summary|detailed|executive|technical)$")
    time_range_hours: int = Field(default=24, ge=1, le=8760)
    include_sections: List[str] = Field(default=["agents", "events", "alerts", "threats"])
    format: str = Field(default="pdf", regex="^(pdf|html|json)$")