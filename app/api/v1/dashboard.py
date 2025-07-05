"""
Dashboard API Endpoints
Real-time dashboard data, statistics, and monitoring
"""

import logging
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from datetime import datetime, timedelta

from ...database import get_db
from ...models.agent import Agent
from ...models.event import Event
from ...models.alert import Alert
from ...models.threat import Threat
from ...models.detection_rule import DetectionRule
from ...schemas.dashboard import (
    DashboardStatsResponse, SystemOverviewResponse,
    AgentOverviewResponse, AlertOverviewResponse,
    ThreatOverviewResponse, EventTimelineResponse
)

logger = logging.getLogger('dashboard_api')
router = APIRouter()

def calculate_system_health_score(online_agents: int, total_agents: int, critical_alerts: int, events_24h: int) -> float:
    """Calculate overall system health score (0-100)"""
    try:
        # Agent health (40% weight)
        agent_health = (online_agents / total_agents * 100) if total_agents > 0 else 0
        agent_score = agent_health * 0.4
        
        # Alert health (30% weight) - fewer critical alerts is better
        alert_health = max(0, 100 - (critical_alerts * 5))  # Penalty for critical alerts
        alert_score = alert_health * 0.3
        
        # Processing health (30% weight) - reasonable event volume
        processing_health = 100 if events_24h > 0 else 50  # Basic processing indicator
        processing_score = processing_health * 0.3
        
        total_score = agent_score + alert_score + processing_score
        return round(min(100, max(0, total_score)), 1)
    except Exception:
        return 50.0  # Default score if calculation fails

def get_health_status(score: float) -> str:
    """Get health status text from score"""
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Good"
    elif score >= 60:
        return "Fair"
    elif score >= 40:
        return "Poor"
    else:
        return "Critical"

def get_overall_system_status(db_status: dict, healthy_agents: int, total_agents: int) -> str:
    """Get overall system status"""
    if not db_status.get('healthy'):
        return "Critical"
    
    if total_agents == 0:
        return "No Agents"
    
    health_ratio = healthy_agents / total_agents
    
    if health_ratio >= 0.9:
        return "Healthy"
    elif health_ratio >= 0.7:
        return "Warning"
    else:
        return "Critical"

@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get overall dashboard statistics"""
    try:
        # Get current timestamp
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        
        # Agent statistics
        total_agents = session.query(Agent).count()
        active_agents = session.query(Agent).filter(Agent.Status == 'Active').count()
        online_agents = session.query(Agent).filter(Agent.Status == 'Active').count()
        
        # Event statistics
        events_last_24h = session.query(Event).filter(Event.EventTimestamp >= last_24h).count()
        suspicious_events = session.query(Event).filter(
            Event.EventTimestamp >= last_24h,
            Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
        ).count()
        
        # Alert statistics
        open_alerts = session.query(Alert).filter(Alert.Status.in_(['Open', 'Investigating'])).count()
        critical_alerts = session.query(Alert).filter(
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.Severity.in_(['High', 'Critical'])
        ).count()
        alerts_last_24h = session.query(Alert).filter(Alert.FirstDetected >= last_24h).count()
        
        # Threat statistics
        active_threats = session.query(Threat).filter(Threat.IsActive == True).count()
        threats_detected_24h = session.query(Alert).filter(
            Alert.FirstDetected >= last_24h,
            Alert.ThreatID.isnot(None)
        ).count()
        
        # Detection statistics
        active_rules = session.query(DetectionRule).filter(DetectionRule.IsActive == True).count()
        
        # System health
        offline_agents = total_agents - online_agents
        health_score = calculate_system_health_score(
            online_agents, total_agents, critical_alerts, events_last_24h
        )
        
        return DashboardStatsResponse(
            agents={
                "total": total_agents,
                "active": active_agents,
                "online": online_agents,
                "offline": offline_agents
            },
            events={
                "last_24h": events_last_24h,
                "suspicious_24h": suspicious_events,
                "avg_per_hour": events_last_24h // 24 if events_last_24h > 0 else 0
            },
            alerts={
                "open": open_alerts,
                "critical": critical_alerts,
                "last_24h": alerts_last_24h,
                "resolved_24h": alerts_last_24h - open_alerts
            },
            threats={
                "active_indicators": active_threats,
                "detected_24h": threats_detected_24h
            },
            detection={
                "active_rules": active_rules,
                "detection_rate": round((suspicious_events / events_last_24h * 100) if events_last_24h > 0 else 0, 2)
            },
            system_health={
                "score": health_score,
                "status": get_health_status(health_score),
                "last_updated": now.isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Get dashboard stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard statistics")

@router.get("/agents-overview", response_model=AgentOverviewResponse)
async def get_agents_overview(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get agents overview for dashboard"""
    try:
        # Get agent summary statistics
        agents_summary = Agent.get_agents_summary(session)
        
        # Get agent status distribution
        status_distribution = session.query(
            Agent.Status,
            func.count(Agent.AgentID).label('count')
        ).group_by(Agent.Status).all()
        
        # Get OS distribution
        os_distribution = session.query(
            Agent.OperatingSystem,
            func.count(Agent.AgentID).label('count')
        ).group_by(Agent.OperatingSystem).all()
        
        # Get recent agent activity
        cutoff_time = datetime.now() - timedelta(hours=1)
        recent_heartbeats = session.query(Agent).filter(
            Agent.LastHeartbeat >= cutoff_time
        ).count()
        
        # Get agents with performance issues
        performance_issues = session.query(Agent).filter(
            Agent.Status == 'Active',
            (Agent.CPUUsage > 90) | (Agent.MemoryUsage > 95) | (Agent.DiskUsage > 90)
        ).all()
        
        # Get top agents by event volume (last 24h)
        last_24h = datetime.now() - timedelta(hours=24)
        top_event_agents = session.query(
            Event.AgentID,
            Agent.HostName,
            func.count(Event.EventID).label('event_count')
        ).join(
            Agent, Event.AgentID == Agent.AgentID
        ).filter(
            Event.EventTimestamp >= last_24h
        ).group_by(
            Event.AgentID, Agent.HostName
        ).order_by(
            func.count(Event.EventID).desc()
        ).limit(10).all()
        
        return AgentOverviewResponse(
            summary=agents_summary,
            status_distribution={status: count for status, count in status_distribution},
            os_distribution={os: count for os, count in os_distribution},
            recent_activity={
                "heartbeats_last_hour": recent_heartbeats,
                "avg_heartbeat_rate": recent_heartbeats // 60 if recent_heartbeats > 0 else 0
            },
            performance_issues=[
                {
                    "agent_id": str(agent.AgentID),
                    "hostname": agent.HostName,
                    "cpu_usage": float(agent.CPUUsage) if agent.CPUUsage else 0,
                    "memory_usage": float(agent.MemoryUsage) if agent.MemoryUsage else 0,
                    "disk_usage": float(agent.DiskUsage) if agent.DiskUsage else 0
                }
                for agent in performance_issues
            ],
            top_event_generators=[
                {
                    "agent_id": str(row.AgentID),
                    "hostname": row.HostName,
                    "event_count": row.event_count
                }
                for row in top_event_agents
            ]
        )
    except Exception as e:
        logger.error(f"Get agents overview failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agents overview")

@router.get("/alerts-overview", response_model=AlertOverviewResponse)
async def get_alerts_overview(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get alerts overview for dashboard"""
    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get alert summary
        alerts_summary = Alert.get_alerts_summary(session, hours)
        
        # Get severity distribution
        severity_distribution = session.query(
            Alert.Severity,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.Severity).all()
        
        # Get status distribution
        status_distribution = session.query(
            Alert.Status,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.Status).all()
        
        # Get top alert types
        top_alert_types = session.query(
            Alert.AlertType,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.AlertType).order_by(
            func.count(Alert.AlertID).desc()
        ).limit(10).all()
        
        # Get MITRE tactics
        mitre_tactics = session.query(
            Alert.MitreTactic,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time,
            Alert.MitreTactic.isnot(None)
        ).group_by(Alert.MitreTactic).order_by(
            func.count(Alert.AlertID).desc()
        ).limit(10).all()
        
        # Get recent critical alerts
        recent_critical = session.query(Alert).filter(
            Alert.Severity.in_(['High', 'Critical']),
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.FirstDetected >= cutoff_time
        ).order_by(Alert.FirstDetected.desc()).limit(10).all()
        
        # Get alert timeline (hourly)
        alert_timeline = session.query(
            func.DATEPART(text('hour'), Alert.FirstDetected).label('hour'),
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(
            func.DATEPART(text('hour'), Alert.FirstDetected)
        ).order_by('hour').all()
        
        return AlertOverviewResponse(
            summary=alerts_summary,
            severity_distribution={severity: count for severity, count in severity_distribution},
            status_distribution={status: count for status, count in status_distribution},
            top_alert_types=[
                {"type": alert_type, "count": count}
                for alert_type, count in top_alert_types
            ],
            mitre_tactics=[
                {"tactic": tactic, "count": count}
                for tactic, count in mitre_tactics if tactic
            ],
            recent_critical_alerts=[
                {
                    "alert_id": alert.AlertID,
                    "title": alert.Title,
                    "severity": alert.Severity,
                    "agent_id": str(alert.AgentID),
                    "first_detected": alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                    "age_minutes": alert.get_age_minutes()
                }
                for alert in recent_critical
            ],
            hourly_timeline=[
                {"hour": hour, "count": count}
                for hour, count in alert_timeline
            ],
            time_range_hours=hours
        )
    except Exception as e:
        logger.error(f"Get alerts overview failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get alerts overview")

@router.get("/events-timeline", response_model=EventTimelineResponse)
async def get_events_timeline(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    granularity: str = Query("hour", regex="^(hour|minute)$", description="Timeline granularity"),
    session: Session = Depends(get_db)
):
    """Get events timeline for dashboard charts"""
    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Use appropriate date part function based on granularity
        if granularity == "hour":
            time_part = func.DATEPART(text('hour'), Event.EventTimestamp)
        else:  # minute
            time_part = func.DATEPART(text('minute'), Event.EventTimestamp)
        
        # Get timeline data
        timeline_data = session.query(
            time_part.label('time_unit'),
            Event.EventType,
            Event.Severity,
            func.count(Event.EventID).label('count')
        ).filter(
            Event.EventTimestamp >= cutoff_time
        ).group_by(
            time_part,
            Event.EventType,
            Event.Severity
        ).order_by('time_unit').all()
        
        # Get threat events timeline
        threat_timeline = session.query(
            time_part.label('time_unit'),
            func.count(Event.EventID).label('threat_count')
        ).filter(
            Event.EventTimestamp >= cutoff_time,
            Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
        ).group_by(time_part).order_by('time_unit').all()
        
        # Get events breakdown by type for pie chart
        events_by_type = session.query(
            Event.EventType,
            func.count(Event.EventID).label('count')
        ).filter(
            Event.EventTimestamp >= cutoff_time
        ).group_by(Event.EventType).all()
        
        # Convert to dictionary format
        events_by_type_dict = {event_type: count for event_type, count in events_by_type}
        
        # Format timeline data
        timeline = []
        for row in timeline_data:
            timeline.append({
                'time_unit': row.time_unit,
                'event_type': row.EventType,
                'severity': row.Severity,
                'count': row.count
            })
        
        threat_timeline_formatted = [
            {
                'time_unit': row.time_unit,
                'threat_count': row.threat_count
            }
            for row in threat_timeline
        ]
        
        return EventTimelineResponse(
            timeline=timeline,
            threat_timeline=threat_timeline_formatted,
            events_by_type=events_by_type_dict,
            granularity=granularity,
            time_range_hours=hours,
            total_events=sum(row['count'] for row in timeline),
            total_threats=sum(row['threat_count'] for row in threat_timeline_formatted)
        )
    except Exception as e:
        logger.error(f"Get events timeline failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get events timeline")

@router.get("/threats-overview", response_model=ThreatOverviewResponse)
async def get_threats_overview(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get threats overview for dashboard"""
    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get threat summary
        threats_summary = Threat.get_threats_summary(session)
        
        # Get recent threat detections
        recent_detections = session.query(
            Alert.ThreatID,
            Threat.ThreatName,
            Threat.ThreatCategory,
            func.count(Alert.AlertID).label('detection_count')
        ).join(
            Threat, Alert.ThreatID == Threat.ThreatID
        ).filter(
            Alert.FirstDetected >= cutoff_time,
            Alert.ThreatID.isnot(None)
        ).group_by(
            Alert.ThreatID, Threat.ThreatName, Threat.ThreatCategory
        ).order_by(
            func.count(Alert.AlertID).desc()
        ).limit(10).all()
        
        # Get threat categories distribution
        category_distribution = session.query(
            Threat.ThreatCategory,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True
        ).group_by(Threat.ThreatCategory).all()
        
        # Get MITRE tactics from threat data
        mitre_tactics_threats = session.query(
            Threat.MitreTactic,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True,
            Threat.MitreTactic.isnot(None)
        ).group_by(Threat.MitreTactic).order_by(
            func.count(Threat.ThreatID).desc()
        ).limit(10).all()
        
        # Get threat intelligence sources
        source_distribution = session.query(
            Threat.ThreatSource,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True,
            Threat.ThreatSource.isnot(None)
        ).group_by(Threat.ThreatSource).all()
        
        return ThreatOverviewResponse(
            summary=threats_summary,
            recent_detections=[
                {
                    "threat_id": detection.ThreatID,
                    "threat_name": detection.ThreatName,
                    "category": detection.ThreatCategory,
                    "detection_count": detection.detection_count
                }
                for detection in recent_detections
            ],
            category_distribution={category: count for category, count in category_distribution if category},
            mitre_tactics=[
                {"tactic": tactic, "count": count}
                for tactic, count in mitre_tactics_threats if tactic
            ],
            source_distribution={source: count for source, count in source_distribution if source},
            time_range_hours=hours
        )
    except Exception as e:
        logger.error(f"Get threats overview failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get threats overview")

@router.get("/system-overview", response_model=SystemOverviewResponse)
async def get_system_overview(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get overall system overview"""
    try:
        from ...database import get_database_status
        
        # Get database status
        db_status = get_database_status()
        
        # Get system performance metrics
        last_hour = datetime.now() - timedelta(hours=1)
        
        # Processing rates
        events_last_hour = session.query(Event).filter(Event.CreatedAt >= last_hour).count()
        alerts_last_hour = session.query(Alert).filter(Alert.FirstDetected >= last_hour).count()
        
        # Detection engine performance
        analyzed_events = session.query(Event).filter(
            Event.CreatedAt >= last_hour,
            Event.Analyzed == True
        ).count()
        
        analysis_rate = (analyzed_events / events_last_hour * 100) if events_last_hour > 0 else 100
        
        # System health indicators
        total_agents = session.query(Agent).count()
        healthy_agents = session.query(Agent).filter(
            Agent.Status == 'Active',
            Agent.LastHeartbeat >= datetime.now() - timedelta(minutes=5)
        ).count()
        
        # Storage statistics
        table_counts = db_status.get('table_counts', {})
        
        return SystemOverviewResponse(
            database={
                "status": "connected" if db_status.get('healthy') else "disconnected",
                "response_time_ms": db_status.get('response_time_ms', 0),
                "table_counts": table_counts,
                "size_mb": db_status.get('database_info', {}).get('size_mb', 0)
            },
            performance={
                "events_per_hour": events_last_hour,
                "alerts_per_hour": alerts_last_hour,
                "analysis_rate_percent": round(analysis_rate, 2),
                "detection_latency_ms": 0  # Would be calculated from actual metrics
            },
            system_health={
                "agents_health_percent": round((healthy_agents / total_agents * 100) if total_agents > 0 else 0, 2),
                "detection_engine_status": "running",
                "threat_intel_status": "active",
                "overall_status": get_overall_system_status(db_status, healthy_agents, total_agents)
            },
            resource_usage={
                "cpu_usage_percent": 0,  # Would be from system monitoring
                "memory_usage_percent": 0,  # Would be from system monitoring
                "disk_usage_percent": 0,  # Would be from system monitoring
                "network_io_mbps": 0  # Would be from system monitoring
            }
        )
    except Exception as e:
        logger.error(f"Get system overview failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get system overview")

@router.get("/real-time-stats")
async def get_real_time_stats(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get real-time statistics for live dashboard updates"""
    try:
        now = datetime.now()
        last_5_min = now - timedelta(minutes=5)
        last_hour = now - timedelta(hours=1)
        
        # Real-time counters
        stats = {
            "timestamp": now.isoformat(),
            "recent_activity": {
                "events_last_5min": session.query(Event).filter(Event.CreatedAt >= last_5_min).count(),
                "alerts_last_5min": session.query(Alert).filter(Alert.FirstDetected >= last_5_min).count(),
                "agent_heartbeats_last_5min": session.query(Agent).filter(Agent.LastHeartbeat >= last_5_min).count()
            },
            "current_status": {
                "online_agents": session.query(Agent).filter(
                    Agent.Status == 'Active',
                    Agent.LastHeartbeat >= now - timedelta(minutes=5)
                ).count(),
                "open_alerts": session.query(Alert).filter(Alert.Status.in_(['Open', 'Investigating'])).count(),
                "critical_alerts": session.query(Alert).filter(
                    Alert.Status.in_(['Open', 'Investigating']),
                    Alert.Severity.in_(['High', 'Critical'])
                ).count(),
                "unanalyzed_events": session.query(Event).filter(Event.Analyzed == False).count()
            },
            "hourly_rates": {
                "events_per_hour": session.query(Event).filter(Event.CreatedAt >= last_hour).count(),
                "alerts_per_hour": session.query(Alert).filter(Alert.FirstDetected >= last_hour).count(),
                "threats_detected_per_hour": session.query(Event).filter(
                    Event.CreatedAt >= last_hour,
                    Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
                ).count()
            }
        }
        
        return stats
    except Exception as e:
        logger.error(f"Get real-time stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get real-time stats")