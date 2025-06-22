# app/api/v1/agents.py - FIXED VERSION (Add missing endpoints)
"""
Agents API Endpoints - FIXED
Added missing endpoints that agents are trying to access
"""

import logging
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
import json

from ...database import get_db
from ...models.agent import Agent
from ...models.alert import Alert
from ...models.system_config import SystemConfig
from ...schemas.agent import (
    AgentRegisterRequest, AgentRegisterResponse,
    AgentHeartbeatRequest, AgentHeartbeatResponse,
    AgentResponse, AgentListResponse, AgentStatusUpdate,
    AgentConfigResponse, AgentStatsResponse
)
from ...services.agent_service import agent_service

logger = logging.getLogger('agent_communication')
router = APIRouter()

# Authentication helper
def verify_agent_token(x_agent_token: Optional[str] = Header(None)):
    """Verify agent authentication token"""
    if not x_agent_token or x_agent_token != "edr_agent_auth_2024":
        raise HTTPException(status_code=401, detail="Invalid or missing agent token")
    return True

@router.post("/register", response_model=AgentRegisterResponse)
async def register_agent(
    request: Request,
    agent_data: AgentRegisterRequest,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Agent registration endpoint"""
    try:
        client_ip = request.client.host
        success, response, error = agent_service.register_agent(session, agent_data, client_ip)
        
        if not success:
            logger.warning(f"Agent registration failed: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        logger.info(f"Agent registered successfully: {agent_data.hostname} from {client_ip}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Agent registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Agent registration failed")

@router.post("/heartbeat", response_model=AgentHeartbeatResponse)
async def heartbeat(
    request: Request,
    heartbeat_data: AgentHeartbeatRequest,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Agent heartbeat endpoint"""
    try:
        client_ip = request.client.host
        success, response, error = agent_service.process_heartbeat(session, heartbeat_data, client_ip)
        
        if not success:
            logger.warning(f"Heartbeat failed: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat processing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Heartbeat processing failed")

# FIXED: Add missing pending-alerts endpoint
@router.get("/{agent_id}/pending-alerts")
async def get_pending_alerts(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get pending alerts for agent - MISSING ENDPOINT FIXED"""
    try:
        # Validate agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get pending alerts for the agent
        pending_alerts = session.query(Alert).filter(
            Alert.AgentID == agent_id,
            Alert.Status.in_(['Open', 'Investigating'])
        ).order_by(Alert.FirstDetected.desc()).limit(20).all()
        
        alerts_data = []
        for alert in pending_alerts:
            alerts_data.append({
                'alert_id': alert.AlertID,
                'title': alert.Title,
                'description': alert.Description,
                'severity': alert.Severity,
                'priority': alert.Priority,
                'risk_score': alert.RiskScore,
                'detection_method': alert.DetectionMethod,
                'first_detected': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                'mitre_tactic': alert.MitreTactic,
                'mitre_technique': alert.MitreTechnique,
                'event_count': alert.EventCount,
                'age_minutes': alert.get_age_minutes()
            })
        
        logger.info(f"📋 Retrieved {len(alerts_data)} pending alerts for agent {agent.HostName}")
        
        return {
            "success": True,
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "alerts": alerts_data,
            "total_pending": len(alerts_data),
            "retrieved_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get pending alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get pending alerts")

# NEW: Agent status check endpoint (often requested)
@router.get("/{agent_id}/status")
async def get_agent_status(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get agent status - NEW ENDPOINT"""
    try:
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get recent activity
        last_24h = datetime.now() - timedelta(hours=24)
        recent_events = session.query(Alert).filter(
            Alert.AgentID == agent_id,
            Alert.FirstDetected >= last_24h
        ).count()
        
        return {
            "success": True,
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "status": agent.Status,
            "connection_status": agent.get_connection_status(),
            "monitoring_enabled": agent.MonitoringEnabled,
            "last_heartbeat": agent.LastHeartbeat.isoformat() if agent.LastHeartbeat else None,
            "recent_events_24h": recent_events,
            "health_status": agent.get_health_status(),
            "checked_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent status")

# EXISTING: Detection notifications endpoint
@router.get("/{agent_id}/notifications")
async def get_detection_notifications(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get pending detection notifications for agent"""
    try:
        # Validate agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get pending notifications from system config
        notifications = session.query(SystemConfig).filter(
            SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
            SystemConfig.Category == 'AgentNotifications'
        ).all()
        
        notification_list = []
        for config in notifications:
            try:
                notification_data = json.loads(config.ConfigValue)
                if notification_data.get('status') == 'pending':
                    notification_list.append(notification_data['notification_data'])
                    
                    # Mark as retrieved
                    config.ConfigValue = json.dumps({
                        **notification_data,
                        'status': 'retrieved',
                        'retrieved_at': datetime.now().isoformat()
                    })
                    
            except Exception as e:
                logger.error(f"Failed to parse notification: {e}")
                continue
        
        session.commit()
        
        logger.info(f"📤 Sent {len(notification_list)} notifications to agent {agent.HostName}")
        
        return {
            "success": True,
            "agent_id": agent_id,
            "notifications": notification_list,
            "count": len(notification_list),
            "retrieved_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get notifications failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get notifications")

# EXISTING: Pending actions endpoint
@router.get("/{agent_id}/pending-actions")
async def get_pending_actions(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get pending response actions for agent"""
    try:
        from ...services.agent_communication_service import agent_communication_service
        
        # Validate agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get pending actions
        pending_actions = agent_communication_service.get_pending_actions(session, agent_id)
        
        return {
            "success": True,
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "pending_actions": pending_actions,
            "count": len(pending_actions),
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get pending actions failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get pending actions")

# NEW: Agent settings/config endpoint
@router.get("/{agent_id}/settings")
async def get_agent_settings(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get agent settings/configuration - NEW ENDPOINT"""
    try:
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get agent config
        config_response = agent_service.get_agent_config(session, agent_id)
        if not config_response:
            raise HTTPException(status_code=404, detail="Agent configuration not found")
        
        return {
            "success": True,
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "settings": config_response.dict(),
            "last_updated": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent settings failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent settings")

# NEW: Agent metrics endpoint
@router.get("/{agent_id}/metrics")
async def get_agent_metrics(
    request: Request,
    agent_id: str,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get agent metrics and statistics - NEW ENDPOINT"""
    try:
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get time range
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get event metrics
        from ...models.event import Event
        total_events = session.query(Event).filter(
            Event.AgentID == agent_id,
            Event.EventTimestamp >= cutoff_time
        ).count()
        
        # Get alert metrics
        total_alerts = session.query(Alert).filter(
            Alert.AgentID == agent_id,
            Alert.FirstDetected >= cutoff_time
        ).count()
        
        open_alerts = session.query(Alert).filter(
            Alert.AgentID == agent_id,
            Alert.Status.in_(['Open', 'Investigating'])
        ).count()
        
        # Event type breakdown
        event_types = session.query(
            Event.EventType,
            func.count(Event.EventID).label('count')
        ).filter(
            Event.AgentID == agent_id,
            Event.EventTimestamp >= cutoff_time
        ).group_by(Event.EventType).all()
        
        return {
            "success": True,
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "time_range_hours": hours,
            "metrics": {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "open_alerts": open_alerts,
                "events_per_hour": total_events // hours if hours > 0 else 0,
                "event_types": {event_type: count for event_type, count in event_types}
            },
            "performance": {
                "cpu_usage": float(agent.CPUUsage) if agent.CPUUsage else 0.0,
                "memory_usage": float(agent.MemoryUsage) if agent.MemoryUsage else 0.0,
                "disk_usage": float(agent.DiskUsage) if agent.DiskUsage else 0.0,
                "network_latency": agent.NetworkLatency or 0
            },
            "generated_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent metrics failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent metrics")

# EXISTING: Action response endpoint
@router.post("/{agent_id}/action-response")
async def submit_action_response(
    request: Request,
    agent_id: str,
    action_data: dict,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Submit action response from agent"""
    try:
        from ...services.agent_communication_service import agent_communication_service
        
        # Validate agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Extract action data
        alert_id = action_data.get('alert_id')
        action_type = action_data.get('action_type')
        success = action_data.get('success', False)
        details = action_data.get('details', '')
        
        if not alert_id or not action_type:
            raise HTTPException(status_code=400, detail="Missing alert_id or action_type")
        
        # Record action response
        result = agent_communication_service.record_action_response(
            session, agent_id, alert_id, action_type, success, details
        )
        
        if result:
            logger.info(f"📝 Action response recorded: Agent {agent.HostName}, Alert {alert_id}, Action {action_type}")
            return {
                "success": True,
                "message": "Action response recorded",
                "agent_id": agent_id,
                "alert_id": alert_id,
                "action_type": action_type
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to record action response")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Submit action response failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit action response")

# Keep all existing endpoints unchanged...
@router.get("/config/{agent_id}", response_model=AgentConfigResponse)
async def get_agent_config(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get agent configuration"""
    try:
        config_response = agent_service.get_agent_config(session, agent_id)
        if not config_response:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return config_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent config error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent configuration")

@router.get("/list", response_model=AgentListResponse)
async def list_agents(
    request: Request,
    session: Session = Depends(get_db)
):
    """List all agents"""
    try:
        # Get agent summaries
        agents_summary = Agent.get_agents_summary(session)
        
        # Get detailed agent list
        agents = session.query(Agent).order_by(Agent.LastHeartbeat.desc()).all()
        
        agent_summaries = []
        for agent in agents:
            summary_data = agent.to_summary()
            agent_summaries.append(summary_data)
        
        # Calculate counts
        online_count = sum(1 for agent in agents if agent.is_online())
        offline_count = len(agents) - online_count
        
        return AgentListResponse(
            agents=agent_summaries,
            total_count=len(agents),
            online_count=online_count,
            offline_count=offline_count,
            summary=agents_summary
        )
        
    except Exception as e:
        logger.error(f"List agents error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list agents")

@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent_details(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db)
):
    """Get specific agent details"""
    try:
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent_data = agent.to_dict()
        return AgentResponse(**agent_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent details error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent details")

@router.put("/{agent_id}/status")
async def update_agent_status(
    request: Request,
    agent_id: str,
    status_update: AgentStatusUpdate,
    session: Session = Depends(get_db)
):
    """Update agent status"""
    try:
        success, message = agent_service.update_agent_status(
            session, agent_id, status_update.status, status_update.monitoring_enabled
        )
        
        if success:
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=400, detail=message)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update agent status error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update agent status")

@router.get("/stats/summary", response_model=AgentStatsResponse)
async def get_agent_statistics(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get agent statistics"""
    try:
        summary = Agent.get_agents_summary(session)
        
        # Additional statistics
        from sqlalchemy import func
        
        # Connection status breakdown
        online_agents = session.query(Agent).filter(
            Agent.Status == 'Active',
            Agent.LastHeartbeat >= datetime.now() - timedelta(minutes=5)
        ).count()
        
        connection_status_breakdown = {
            'online': online_agents,
            'offline': summary['total_agents'] - online_agents
        }
        
        # Performance summary
        agents_with_high_cpu = session.query(Agent).filter(Agent.CPUUsage > 80).count()
        agents_with_high_memory = session.query(Agent).filter(Agent.MemoryUsage > 80).count()
        
        performance_summary = {
            'high_cpu_usage': agents_with_high_cpu,
            'high_memory_usage': agents_with_high_memory,
            'total_monitored': summary['active_agents']
        }
        
        return AgentStatsResponse(
            total_agents=summary['total_agents'],
            active_agents=summary['active_agents'],
            online_agents=summary['online_agents'],
            offline_agents=summary['offline_agents'],
            inactive_agents=summary['inactive_agents'],
            os_breakdown=summary['os_breakdown'],
            connection_status_breakdown=connection_status_breakdown,
            performance_summary=performance_summary
        )
        
    except Exception as e:
        logger.error(f"Get agent statistics error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent statistics")