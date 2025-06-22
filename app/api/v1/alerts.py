# app/api/v1/alerts.py - MODIFIED (Add agent alert submission endpoints)
"""
Alerts API Endpoints - MODIFIED
Added endpoints for agent to submit alerts back to server
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query, Header
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from datetime import datetime, timedelta

from ...database import get_db
from ...models.alert import Alert
from ...models.agent import Agent
from ...schemas.alert import (
    AlertResponse, AlertSummary, AlertListResponse,
    AlertStatusUpdateRequest, AlertStatusUpdateResponse,
    AlertStatsResponse,
    # NEW: Agent alert submission schemas
    AgentAlertSubmission, AgentAlertResponse
)

logger = logging.getLogger('alert_management')
router = APIRouter()

# Authentication helper
def verify_agent_token(x_agent_token: Optional[str] = Header(None)):
    """Verify agent authentication token"""
    if not x_agent_token or x_agent_token != "edr_agent_auth_2024":
        raise HTTPException(status_code=401, detail="Invalid or missing agent token")
    return True

# NEW: Agent alert submission endpoint
@router.post("/submit-from-agent", response_model=AgentAlertResponse)
async def submit_alert_from_agent(
    request: Request,
    alert_data: AgentAlertSubmission,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Agent submits alert to server - NEW ENDPOINT"""
    try:
        client_ip = request.client.host
        
        # Validate agent exists
        agent = Agent.get_by_id(session, alert_data.agent_id)
        if not agent:
            logger.warning(f"Agent not found: {alert_data.agent_id}")
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Create alert from agent data
        alert = Alert.create_alert(
            agent_id=alert_data.agent_id,
            alert_type=alert_data.alert_type,
            title=alert_data.title,
            severity=alert_data.severity.value,
            detection_method="Agent Detection",
            Description=alert_data.description,
            FirstDetected=alert_data.detected_at,
            RiskScore=alert_data.risk_score or 50,
            Confidence=alert_data.confidence or 0.7,
            MitreTactic=alert_data.mitre_tactic,
            MitreTechnique=alert_data.mitre_technique,
            Status='Open'
        )
        
        # Store local analysis data if provided
        if alert_data.local_analysis:
            alert.set_raw_data(alert_data.local_analysis)
        
        # Link to related events if provided
        if alert_data.related_events:
            # Store related event IDs in ResponseAction field
            related_info = f"Related Events: {', '.join(alert_data.related_events)}"
            alert.ResponseAction = related_info
        
        session.add(alert)
        session.flush()  # Get alert ID
        
        # Check for correlation with existing alerts
        correlated_alerts = []
        try:
            correlation_window = timedelta(hours=1)
            time_start = alert.FirstDetected - correlation_window
            time_end = alert.FirstDetected + correlation_window
            
            # Find related alerts
            related_query = session.query(Alert).filter(
                Alert.AlertID != alert.AlertID,
                Alert.FirstDetected.between(time_start, time_end),
                Alert.Status.in_(['Open', 'Investigating'])
            )
            
            # Same agent correlation
            same_agent_alerts = related_query.filter(Alert.AgentID == alert.AgentID).all()
            correlated_alerts.extend([a.AlertID for a in same_agent_alerts])
            
            # Same MITRE tactic correlation
            if alert.MitreTactic:
                same_tactic_alerts = related_query.filter(
                    Alert.MitreTactic == alert.MitreTactic
                ).all()
                correlated_alerts.extend([a.AlertID for a in same_tactic_alerts])
            
            # Remove duplicates
            correlated_alerts = list(set(correlated_alerts))
            
        except Exception as e:
            logger.error(f"Alert correlation failed: {e}")
            correlated_alerts = []
        
        # Generate recommendations
        recommendations = []
        if alert_data.severity.value in ['High', 'Critical']:
            recommendations.extend([
                "Immediate investigation required",
                "Consider isolating the affected endpoint",
                "Review security logs for related activities"
            ])
        elif alert_data.severity.value == 'Medium':
            recommendations.extend([
                "Monitor endpoint closely",
                "Review recent activities",
                "Consider additional endpoint hardening"
            ])
        else:
            recommendations.extend([
                "Continue monitoring",
                "Document findings for future reference"
            ])
        
        # Add indicator-specific recommendations
        if alert_data.indicators:
            if 'malware' in str(alert_data.indicators).lower():
                recommendations.append("Run full antimalware scan")
            if 'network' in str(alert_data.indicators).lower():
                recommendations.append("Review network connections")
            if 'process' in str(alert_data.indicators).lower():
                recommendations.append("Analyze running processes")
        
        session.commit()
        session.refresh(alert)
        
        logger.info(f"🚨 Alert submitted by agent {agent.HostName}: {alert.Title} (ID: {alert.AlertID})")
        
        return AgentAlertResponse(
            success=True,
            alert_id=alert.AlertID,
            message="Alert submitted successfully",
            correlation_alerts=correlated_alerts[:10],  # Limit to 10
            recommended_actions=recommendations[:5]  # Limit to 5
        )
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Agent alert submission failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Alert submission failed")

# NEW: Batch alert submission from agent
@router.post("/submit-batch-from-agent")
async def submit_alert_batch_from_agent(
    request: Request,
    alerts_data: List[AgentAlertSubmission],
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Agent submits multiple alerts to server - NEW ENDPOINT"""
    try:
        if len(alerts_data) > 100:  # Limit batch size
            raise HTTPException(status_code=400, detail="Batch size exceeds maximum (100)")
        
        created_alerts = []
        failed_alerts = []
        
        for alert_data in alerts_data:
            try:
                # Validate agent exists
                agent = Agent.get_by_id(session, alert_data.agent_id)
                if not agent:
                    failed_alerts.append({
                        'title': alert_data.title,
                        'error': 'Agent not found'
                    })
                    continue
                
                # Create alert
                alert = Alert.create_alert(
                    agent_id=alert_data.agent_id,
                    alert_type=alert_data.alert_type,
                    title=alert_data.title,
                    severity=alert_data.severity.value,
                    detection_method="Agent Detection",
                    Description=alert_data.description,
                    FirstDetected=alert_data.detected_at,
                    RiskScore=alert_data.risk_score or 50,
                    Confidence=alert_data.confidence or 0.7,
                    MitreTactic=alert_data.mitre_tactic,
                    MitreTechnique=alert_data.mitre_technique,
                    Status='Open'
                )
                
                # Store local analysis data
                if alert_data.local_analysis:
                    alert.set_raw_data(alert_data.local_analysis)
                
                session.add(alert)
                session.flush()
                
                created_alerts.append({
                    'alert_id': alert.AlertID,
                    'title': alert.Title,
                    'agent_hostname': agent.HostName
                })
                
            except Exception as e:
                failed_alerts.append({
                    'title': alert_data.title,
                    'error': str(e)
                })
                logger.error(f"Failed to create alert in batch: {e}")
        
        session.commit()
        
        logger.info(f"Batch alert submission: {len(created_alerts)} created, {len(failed_alerts)} failed")
        
        return {
            "success": True,
            "message": f"Batch processed: {len(created_alerts)} alerts created",
            "created_alerts": created_alerts,
            "failed_alerts": failed_alerts,
            "total_submitted": len(alerts_data),
            "success_count": len(created_alerts),
            "failed_count": len(failed_alerts)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Batch alert submission failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Batch alert submission failed")

# Keep existing alert management endpoints...
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
    session: Session = Depends(get_db)
):
    """List alerts with filtering and pagination"""
    try:
        # Build query
        query = session.query(Alert)
        
        # Apply filters
        filters_applied = {}
        
        if status:
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
            
            alert_summaries.append(AlertSummary(**alert_data))
        
        # Calculate page info
        page = (offset // limit) + 1 if limit > 0 else 1
        
        # Get summary statistics
        open_count = session.query(Alert).filter(Alert.Status.in_(['Open', 'Investigating'])).count()
        critical_count = session.query(Alert).filter(
            Alert.Status.in_(['Open', 'Investigating']),
            Alert.Severity.in_(['High', 'Critical'])
        ).count()
        
        return AlertListResponse(
            alerts=alert_summaries,
            total_count=total_count,
            open_count=open_count,
            critical_count=critical_count,
            page=page,
            page_size=limit,
            filters_applied=filters_applied
        )
        
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

# Continue with other existing endpoints... (keeping all existing functionality)