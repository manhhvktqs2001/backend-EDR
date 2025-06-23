"""
Alerts API Endpoints - FIXED VERSION
Alert management, status updates, and monitoring
FIXED: Added root endpoint for agent compatibility
"""

import logging
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from datetime import datetime, timedelta
import json

from ...database import get_db
from ...models.alert import Alert
from ...models.agent import Agent
from ...schemas.alert import (
    AlertResponse, AlertSummary, AlertListResponse,
    AlertStatusUpdateRequest, AlertStatusUpdateResponse,
    AlertStatsResponse, AgentAlertSubmission
)

logger = logging.getLogger('alert_management')
router = APIRouter()

# FIXED: ROOT endpoint for agent compatibility (Agent calls /api/v1/alerts directly)
@router.get("")  # Remove response_model to avoid schema issues
async def list_alerts_root(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, le=1000, description="Maximum alerts to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    realtime: Optional[bool] = Query(None, description="Realtime mode flag"),
    session: Session = Depends(get_db)
):
    """ROOT endpoint - List alerts for agent compatibility"""
    return await list_alerts_implementation(request, status, severity, agent_id, alert_type, hours, limit, offset, session, realtime)

@router.get("/list", response_model=AlertListResponse)
async def list_alerts(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, le=1000, description="Maximum alerts to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    realtime: Optional[bool] = Query(None, description="Realtime mode flag"),
    session: Session = Depends(get_db)
):
    """List alerts with filtering and pagination"""
    return await list_alerts_implementation(request, status, severity, agent_id, alert_type, hours, limit, offset, session, realtime)

async def list_alerts_implementation(
    request: Request,
    status: Optional[str],
    severity: Optional[str],
    agent_id: Optional[str],
    alert_type: Optional[str],
    hours: int,
    limit: int,
    offset: int,
    session: Session,
    realtime: Optional[bool] = None
) -> AlertListResponse:
    """Shared implementation for listing alerts with special agent handling"""
    try:
        # Build query
        query = session.query(Alert)
        
        # Apply filters
        filters_applied = {}
        
        # SPECIAL HANDLING for agent queries with status "pending"
        if agent_id and status and status.lower() == 'pending':
            # Agent is asking for pending alerts - map to Open/Investigating
            query = query.filter(
                Alert.AgentID == agent_id,
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.ResolvedAt.is_(None)
            )
            filters_applied['agent_id'] = agent_id
            filters_applied['status'] = 'pending (mapped to Open/Investigating)'
            logger.info(f"📋 Agent {agent_id} requesting pending alerts")
        else:
            # Standard filtering
            if status:
                if status.lower() == 'pending':
                    # Map "pending" to Open/Investigating
                    query = query.filter(Alert.Status.in_(['Open', 'Investigating']))
                    filters_applied['status'] = 'pending (mapped to Open/Investigating)'
                else:
                    query = query.filter(Alert.Status == status)
                    filters_applied['status'] = status
            
            if severity:
                query = query.filter(Alert.Severity == severity)
                filters_applied['severity'] = severity
            
            if agent_id:
                query = query.filter(Alert.AgentID == agent_id)
                filters_applied['agent_id'] = agent_id
            
            if alert_type:
                query = query.filter(Alert.AlertType == alert_type)
                filters_applied['alert_type'] = alert_type
            
            # Time range filter
            if hours:
                cutoff_time = datetime.now() - timedelta(hours=hours)
                query = query.filter(Alert.FirstDetected >= cutoff_time)
                filters_applied['hours'] = hours
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination and get results
        alerts = query.order_by(Alert.FirstDetected.desc()).offset(offset).limit(limit).all()
        
        # Convert to summary format and add agent info
        alert_summaries = []
        for alert in alerts:
            alert_data = alert.to_summary()
            
            # Add agent hostname
            agent = session.query(Agent).filter(Agent.AgentID == alert.AgentID).first()
            if agent:
                alert_data['hostname'] = agent.HostName
                alert_data['agent_ip'] = agent.IPAddress
            
            # BỔ SUNG: Nếu là rule/threat alert, thêm trường nhận diện cho agent
            if getattr(alert, 'RuleID', None):
                alert_data['rule_violation'] = True
                alert_data['rule_id'] = alert.RuleID
                alert_data['server_generated'] = True
                alert_data['rule_name'] = getattr(alert, 'Title', None) or getattr(alert, 'AlertTitle', None)
            if getattr(alert, 'ThreatID', None):
                alert_data['rule_violation'] = True
                alert_data['threat_id'] = alert.ThreatID
                alert_data['server_generated'] = True
                alert_data['rule_name'] = getattr(alert, 'Title', None) or getattr(alert, 'AlertTitle', None)
            
            # Convert to AlertSummary object safely
            try:
                alert_summary = AlertSummary(**alert_data)
                alert_summaries.append(alert_summary)
            except Exception as conversion_error:
                logger.warning(f"Alert summary conversion error: {conversion_error}")
                # Add as dict if Pydantic conversion fails
                alert_summaries.append(alert_data)
        
        # Calculate page info
        page = (offset // limit) + 1 if limit > 0 else 1
        
        # Get summary statistics
        open_count = session.query(Alert).filter(Alert.Status.in_(['Open', 'Investigating'])).count()
        critical_count = session.query(Alert).filter(
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.Severity.in_(['High', 'Critical'])
        ).count()
        
        logger.info(f"📋 Alerts query: {len(alert_summaries)}/{total_count} results, filters: {filters_applied}, realtime: {realtime}")
        
        # Prepare response data with proper schema handling
        try:
            # Return simple dict format for better compatibility
            return {
                "alerts": alert_summaries,
                "total_count": total_count,
                "open_count": open_count,
                "critical_count": critical_count,
                "page": page,
                "page_size": limit,
                "filters_applied": filters_applied,
                "realtime_mode": realtime or False,
                "success": True,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as schema_error:
            logger.error(f"Schema error: {schema_error}")
            # Return minimal response
            return {
                "alerts": [],
                "total_count": 0,
                "error": "Response formatting error",
                "success": False
            }
        
    except Exception as e:
        logger.error(f"List alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list alerts")

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert_details(
    request: Request,
    alert_id: int,
    session: Session = Depends(get_db)
):
    """Get specific alert details"""
    try:
        alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Get alert data
        alert_data = alert.to_dict()
        
        # Add agent information
        agent = session.query(Agent).filter(Agent.AgentID == alert.AgentID).first()
        if agent:
            alert_data['agent_hostname'] = agent.HostName
            alert_data['agent_ip'] = agent.IPAddress
            alert_data['agent_os'] = agent.OperatingSystem
        
        # Add event information if linked
        if alert.EventID:
            from ...models.event import Event
            event = session.query(Event).filter(Event.EventID == alert.EventID).first()
            if event:
                alert_data['event_details'] = event.to_summary()
        
        # Add rule information if linked
        if alert.RuleID:
            from ...models.detection_rule import DetectionRule
            rule = session.query(DetectionRule).filter(DetectionRule.RuleID == alert.RuleID).first()
            if rule:
                alert_data['rule_details'] = rule.to_summary()
        
        # Add threat information if linked
        if alert.ThreatID:
            from ...models.threat import Threat
            threat = session.query(Threat).filter(Threat.ThreatID == alert.ThreatID).first()
            if threat:
                alert_data['threat_details'] = threat.to_summary()
        
        return AlertResponse(**alert_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get alert details failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get alert details")

@router.put("/{alert_id}/status", response_model=AlertStatusUpdateResponse)
async def update_alert_status(
    request: Request,
    alert_id: int,
    status_update: AlertStatusUpdateRequest,
    session: Session = Depends(get_db)
):
    """Update alert status"""
    try:
        alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Update alert status
        alert.update_status(
            status=status_update.status,
            assigned_to=status_update.assigned_to,
            resolved_by=status_update.resolved_by if status_update.status == 'Resolved' else None
        )
        
        # Add response action if provided
        if status_update.response_action:
            alert.ResponseAction = status_update.response_action
        
        session.commit()
        
        logger.info(f"Alert {alert_id} status updated to {status_update.status} by {status_update.assigned_to or 'system'}")
        
        return AlertStatusUpdateResponse(
            success=True,
            message=f"Alert status updated to {status_update.status}",
            alert_id=alert_id,
            new_status=status_update.status,
            updated_by=status_update.assigned_to,
            updated_at=alert.UpdatedAt.isoformat() if alert.UpdatedAt else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Update alert status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update alert status")

@router.post("/bulk-update")
async def bulk_update_alerts(
    request: Request,
    alert_ids: List[int],
    status: str,
    assigned_to: Optional[str] = None,
    session: Session = Depends(get_db)
):
    """Bulk update multiple alerts"""
    try:
        # Validate status
        valid_statuses = ['Open', 'Investigating', 'Resolved', 'False Positive', 'Suppressed']
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")
        
        # Update alerts
        updated_count = 0
        errors = []
        
        for alert_id in alert_ids:
            try:
                alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
                if alert:
                    alert.update_status(status=status, assigned_to=assigned_to)
                    updated_count += 1
                else:
                    errors.append(f"Alert {alert_id} not found")
            except Exception as e:
                errors.append(f"Failed to update alert {alert_id}: {str(e)}")
        
        session.commit()
        
        logger.info(f"Bulk updated {updated_count} alerts to status {status}")
        
        return {
            "success": True,
            "message": f"Updated {updated_count} alerts",
            "updated_count": updated_count,
            "total_requested": len(alert_ids),
            "errors": errors,
            "new_status": status,
            "assigned_to": assigned_to
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk update alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk update failed")

@router.get("/critical/list")
async def get_critical_alerts(
    request: Request,
    limit: int = Query(50, le=200, description="Maximum alerts to return"),
    session: Session = Depends(get_db)
):
    """Get critical alerts requiring immediate attention"""
    try:
        critical_alerts = Alert.get_critical_alerts(session)
        
        # Apply limit
        if limit and len(critical_alerts) > limit:
            critical_alerts = critical_alerts[:limit]
        
        # Convert to summary format with agent info
        alert_summaries = []
        for alert in critical_alerts:
            alert_data = alert.to_summary()
            
            # Add agent info
            agent = session.query(Agent).filter(Agent.AgentID == alert.AgentID).first()
            if agent:
                alert_data['hostname'] = agent.HostName
                alert_data['agent_ip'] = agent.IPAddress
            
            alert_summaries.append(alert_data)
        
        return {
            "critical_alerts": alert_summaries,
            "total_count": len(alert_summaries),
            "requires_immediate_attention": len([a for a in critical_alerts if a.get_age_minutes() > 60])
        }
        
    except Exception as e:
        logger.error(f"Get critical alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get critical alerts")

@router.get("/stats/summary", response_model=AlertStatsResponse)
async def get_alert_statistics(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get alert statistics summary"""
    try:
        stats = Alert.get_alerts_summary(session, hours)
        
        # Get additional statistics
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Status breakdown
        status_breakdown = session.query(
            Alert.Status,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.Status).all()
        
        # Severity breakdown
        severity_breakdown = session.query(
            Alert.Severity,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.Severity).all()
        
        # Detection method breakdown
        detection_breakdown = session.query(
            Alert.DetectionMethod,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.DetectionMethod).all()
        
        # Top alert types
        top_alert_types = session.query(
            Alert.AlertType,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(Alert.AlertType).order_by(
            func.count(Alert.AlertID).desc()
        ).limit(10).all()
        
        # MITRE tactics breakdown
        mitre_tactics = session.query(
            Alert.MitreTactic,
            func.count(Alert.AlertID).label('count')
        ).filter(
            Alert.FirstDetected >= cutoff_time,
            Alert.MitreTactic.isnot(None)
        ).group_by(Alert.MitreTactic).order_by(
            func.count(Alert.AlertID).desc()
        ).limit(10).all()
        
        return AlertStatsResponse(
            total_alerts=stats['total_alerts'],
            open_alerts=stats['open_alerts'],
            critical_alerts=stats.get('critical_alerts', 0),
            resolved_alerts=stats['resolved_alerts'],
            time_range_hours=hours,
            status_breakdown={status: count for status, count in status_breakdown},
            severity_breakdown={severity: count for severity, count in severity_breakdown},
            detection_method_breakdown={method: count for method, count in detection_breakdown},
            top_alert_types=[{"type": alert_type, "count": count} for alert_type, count in top_alert_types],
            mitre_tactics=[{"tactic": tactic, "count": count} for tactic, count in mitre_tactics if tactic]
        )
        
    except Exception as e:
        logger.error(f"Get alert statistics failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get alert statistics")

@router.get("/timeline/hourly")
async def get_alerts_timeline(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get alerts timeline for dashboard"""
    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Use SQL Server DATEPART with text() for compatibility
        timeline_data = session.query(
            func.datepart(text('hour'), Alert.FirstDetected).label('hour'),
            Alert.Severity,
            func.count(Alert.AlertID).label('alert_count')
        ).filter(
            Alert.FirstDetected >= cutoff_time
        ).group_by(
            func.datepart(text('hour'), Alert.FirstDetected),
            Alert.Severity
        ).order_by('hour', Alert.Severity).all()
        
        # Convert to timeline format
        timeline = []
        for row in timeline_data:
            timeline.append({
                'hour': row.hour,
                'severity': row.Severity,
                'alert_count': row.alert_count
            })
        
        return {
            "timeline": timeline,
            "time_range_hours": hours,
            "total_points": len(timeline)
        }
        
    except Exception as e:
        logger.error(f"Get alerts timeline failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get alerts timeline")

@router.get("/agent/{agent_id}/alerts")
async def get_agent_alerts(
    request: Request,
    agent_id: str,
    status: Optional[str] = Query(None, description="Filter by status"),
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, le=1000, description="Maximum alerts to return"),
    session: Session = Depends(get_db)
):
    """Get alerts for specific agent"""
    try:
        # Verify agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Build query
        query = session.query(Alert).filter(Alert.AgentID == agent_id)
        
        if status:
            if status.lower() == 'pending':
                query = query.filter(Alert.Status.in_(['Open', 'Investigating']))
            else:
                query = query.filter(Alert.Status == status)
        
        if hours:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            query = query.filter(Alert.FirstDetected >= cutoff_time)
        
        # Get alerts
        alerts = query.order_by(Alert.FirstDetected.desc()).limit(limit).all()
        
        # Convert to summary format
        alert_summaries = [alert.to_summary() for alert in alerts]
        
        # Get agent statistics
        total_alerts = len(alert_summaries)
        open_alerts = len([a for a in alerts if a.is_open()])
        critical_alerts = len([a for a in alerts if a.is_critical()])
        
        return {
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "alerts": alert_summaries,
            "statistics": {
                "total_alerts": total_alerts,
                "open_alerts": open_alerts,
                "critical_alerts": critical_alerts,
                "resolved_alerts": total_alerts - open_alerts
            },
            "time_range_hours": hours
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent alerts")

# AGENT-SPECIFIC ENDPOINTS
@router.get("/pending")
async def get_pending_alerts_for_agent(
    request: Request,
    agent_id: str = Query(..., description="Agent ID to check alerts for"),
    limit: int = Query(30, le=100, description="Maximum alerts to return"),
    realtime: Optional[bool] = Query(None, description="Realtime mode flag"),
    session: Session = Depends(get_db)
):
    """Get pending alerts for an agent - AGENT ENDPOINT"""
    try:
        # Get pending alerts for the agent
        pending_alerts = session.query(Alert).filter(
            Alert.AgentID == agent_id,
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.ResolvedAt.is_(None)
        ).order_by(Alert.FirstDetected.desc()).limit(limit).all()
        
        alerts_data = []
        for alert in pending_alerts:
            alerts_data.append({
                'alert_id': alert.AlertID,
                'title': alert.Title,
                'description': alert.Description,
                'severity': alert.Severity,
                'priority': alert.Priority,
                'risk_score': alert.RiskScore or 0,
                'detection_method': alert.DetectionMethod,
                'first_detected': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                'mitre_tactic': alert.MitreTactic,
                'mitre_technique': alert.MitreTechnique,
                'event_count': alert.EventCount or 1,
                'age_minutes': alert.get_age_minutes(),
                'status': alert.Status
            })
        
        logger.info(f"📋 Retrieved {len(alerts_data)} pending alerts for agent {agent_id}")
        
        return {
            "success": True,
            "agent_id": agent_id,
            "alerts": alerts_data,
            "total_pending": len(alerts_data),
            "realtime_mode": realtime or False,
            "retrieved_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get pending alerts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get pending alerts")

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert_by_id(
    request: Request,
    alert_id: int,
    session: Session = Depends(get_db)
):
    """Acknowledge an alert by ID - Enhanced for agent acknowledgment"""
    try:
        # Get request body for acknowledgment details
        body = await request.json()
        
        alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Extract acknowledgment details
        status = body.get('status', 'acknowledged')
        acknowledged_by = body.get('acknowledged_by', 'agent')
        details = body.get('details', {})
        agent_id = body.get('agent_id')
        
        # Validate agent_id matches alert
        if agent_id and str(alert.AgentID) != agent_id:
            raise HTTPException(status_code=403, detail="Agent ID mismatch")
        
        # Update alert status
        if status == 'acknowledged':
            new_status = 'Investigating'
        elif status == 'dismissed':
            new_status = 'Suppressed'
        else:
            new_status = status
        
        alert.update_status(status=new_status, assigned_to=acknowledged_by)
        
        # Add acknowledgment details to response action
        ack_details = f"Alert acknowledged at {datetime.now().isoformat()}"
        if details.get('notification_displayed'):
            ack_details += f" - Notification displayed via {details.get('display_method', 'unknown')}"
        if details.get('agent_version'):
            ack_details += f" - Agent version: {details['agent_version']}"
        
        alert.add_response_action(ack_details)
        
        session.commit()
        
        logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by} via agent")
        
        return {
            "success": True,
            "message": f"Alert acknowledged by {acknowledged_by}",
            "alert_id": alert_id,
            "acknowledged_by": acknowledged_by,
            "new_status": new_status,
            "acknowledgment_details": details,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Alert acknowledgment failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert")

@router.post("/{alert_id}/feedback")
async def send_alert_feedback(
    request: Request,
    alert_id: int,
    session: Session = Depends(get_db)
):
    """Send alert feedback from agent"""
    try:
        # Get request body
        body = await request.json()
        
        alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Extract feedback details
        feedback_type = body.get('feedback_type', 'general')
        feedback_data = body.get('feedback_data', {})
        agent_id = body.get('agent_id')
        timestamp = body.get('timestamp', datetime.now().isoformat())
        
        # Validate agent_id matches alert
        if agent_id and str(alert.AgentID) != agent_id:
            raise HTTPException(status_code=403, detail="Agent ID mismatch")
        
        # Add feedback to response action
        feedback_text = f"Feedback ({feedback_type}) at {timestamp}"
        if feedback_data:
            feedback_text += f" - {json.dumps(feedback_data, default=str)}"
        
        alert.add_response_action(feedback_text)
        
        # Update alert based on feedback type
        if feedback_type == "notification_displayed_successfully":
            if feedback_data.get('display_success'):
                alert.add_response_action("✅ Notification displayed successfully to user")
            else:
                alert.add_response_action("⚠️ Notification display failed")
        
        elif feedback_type == "user_clicked":
            alert.add_response_action("👆 User clicked on notification")
            alert.update_status(status='Investigating', assigned_to='user')
        
        elif feedback_type == "user_dismissed":
            alert.add_response_action("❌ User dismissed notification")
        
        session.commit()
        
        logger.info(f"Alert {alert_id} feedback received: {feedback_type}")
        
        return {
            "success": True,
            "message": f"Feedback received for alert {alert_id}",
            "alert_id": alert_id,
            "feedback_type": feedback_type,
            "timestamp": timestamp
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Alert feedback failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process alert feedback")

@router.post("/submit-from-agent")
async def submit_alert_from_agent(
    request: Request,
    alert_data: AgentAlertSubmission,
    session: Session = Depends(get_db)
):
    """Submit alert from agent to server"""
    try:
        # Validate agent exists
        from ...models.agent import Agent
        agent = session.query(Agent).filter(Agent.AgentID == alert_data.agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Create alert in database
        from ...models.alert import Alert
        
        new_alert = Alert.create_alert(
            agent_id=alert_data.agent_id,
            alert_type=alert_data.alert_type,
            title=alert_data.title,
            severity=alert_data.severity,
            detection_method=alert_data.detection_method,
            description=alert_data.description,
            risk_score=alert_data.risk_score or 50,
            confidence=alert_data.confidence or 0.8,
            mitre_tactic=alert_data.mitre_tactic,
            mitre_technique=alert_data.mitre_technique
        )
        
        session.add(new_alert)
        session.commit()
        session.refresh(new_alert)
        
        logger.info(f"Alert submitted from agent {agent.HostName}: {new_alert.AlertID}")
        
        return {
            "success": True,
            "alert_id": new_alert.AlertID,
            "message": "Alert submitted successfully",
            "correlation_alerts": [],
            "recommended_actions": [
                "Monitor system for additional suspicious activity",
                "Review related events in the timeline",
                "Consider isolating the affected system if necessary"
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Alert submission from agent failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit alert")

@router.get("/health/status")
async def get_alert_health_status(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get alert processing health status"""
    try:
        # Get current alert statistics
        open_alerts = session.query(Alert).filter(Alert.Status.in_(['Open', 'Investigating'])).count()
        critical_alerts = session.query(Alert).filter(
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.Severity.in_(['High', 'Critical'])
        ).count()
        
        # Get recent alert generation rate
        last_hour = datetime.now() - timedelta(hours=1)
        alerts_last_hour = session.query(Alert).filter(Alert.FirstDetected >= last_hour).count()
        
        # Get old unresolved alerts
        old_threshold = datetime.now() - timedelta(hours=24)
        old_unresolved = session.query(Alert).filter(
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.FirstDetected < old_threshold
        ).count()
        
        # Determine health status
        health_status = "healthy"
        issues = []
        
        if critical_alerts > 10:
            health_status = "critical"
            issues.append(f"High number of critical alerts: {critical_alerts}")
        
        if old_unresolved > 50:
            if health_status != "critical":
                health_status = "warning"
            issues.append(f"Many old unresolved alerts: {old_unresolved}")
        
        if alerts_last_hour > 100:
            if health_status == "healthy":
                health_status = "warning"
            issues.append(f"High alert generation rate: {alerts_last_hour}/hour")
        
        return {
            "status": health_status,
            "alert_statistics": {
                "open_alerts": open_alerts,
                "critical_alerts": critical_alerts,
                "alerts_last_hour": alerts_last_hour,
                "old_unresolved_alerts": old_unresolved
            },
            "issues": issues,
            "recommendations": [
                "Review and resolve critical alerts" if critical_alerts > 5 else None,
                "Investigate high alert generation rate" if alerts_last_hour > 50 else None,
                "Review old unresolved alerts" if old_unresolved > 20 else None
            ],
            "last_checked": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Alert health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Alert health check failed")

@router.get("/search/mitre")
async def search_alerts_by_mitre(
    request: Request,
    tactic: Optional[str] = Query(None, description="MITRE ATT&CK tactic"),
    technique: Optional[str] = Query(None, description="MITRE ATT&CK technique"),
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Search alerts by MITRE ATT&CK tactics and techniques"""
    try:
        query = session.query(Alert)
        
        if tactic:
            query = query.filter(Alert.MitreTactic.ilike(f'%{tactic}%'))
        
        if technique:
            query = query.filter(Alert.MitreTechnique.ilike(f'%{technique}%'))
        
        if hours:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            query = query.filter(Alert.FirstDetected >= cutoff_time)
        
        alerts = query.order_by(Alert.FirstDetected.desc()).all()
        
        # Convert to summary format
        alert_summaries = []
        for alert in alerts:
            alert_data = alert.to_summary()
            
            # Add agent info
            agent = session.query(Agent).filter(Agent.AgentID == alert.AgentID).first()
            if agent:
                alert_data['hostname'] = agent.HostName
            
            alert_summaries.append(alert_data)
        
        return {
            "alerts": alert_summaries,
            "total_count": len(alert_summaries),
            "search_criteria": {
                "tactic": tactic,
                "technique": technique,
                "hours": hours
            }
        }
        
    except Exception as e:
        logger.error(f"MITRE search failed: {str(e)}")
        raise HTTPException(status_code=500, detail="MITRE search failed")

@router.post("/cleanup-nonrule-alerts")
async def cleanup_nonrule_alerts(
    request: Request,
    session: Session = Depends(get_db)
):
    """Cleanup (resolve) all alerts không phải rule/threat match (RuleID, ThreatID null/0, trạng thái Open/Investigating)"""
    try:
        alerts = session.query(Alert).filter(
            (Alert.RuleID == None) | (Alert.RuleID == 0),
            (Alert.ThreatID == None) | (Alert.ThreatID == 0),
            Alert.Status.in_(['Open', 'Investigating'])
        ).all()
        count = 0
        for alert in alerts:
            alert.Status = 'Resolved'
            alert.ResolvedAt = datetime.now()
            count += 1
        session.commit()
        logger.info(f"✅ Cleaned up {count} non-rule alerts (set to Resolved)")
        return {"success": True, "resolved_alerts": count}
    except Exception as e:
        session.rollback()
        logger.error(f"Cleanup non-rule alerts failed: {e}")
        return {"success": False, "error": str(e)}