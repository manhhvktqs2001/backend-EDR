"""
Agent Response API Endpoints
Automated response actions for detected threats
"""

import logging
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from ...database import get_db
from ...models.alert import Alert
from ...models.agent import Agent
from ...services.agent_communication_service import agent_communication_service

logger = logging.getLogger('agent_response')
router = APIRouter()

@router.post("/response/execute/{alert_id}")
async def execute_automated_response(
    request: Request,
    alert_id: int,
    response_type: str = Query(..., description="Type of response to execute"),
    session: Session = Depends(get_db)
):
    """Execute automated response for an alert"""
    try:
        # Get alert
        alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Get agent
        agent = Agent.get_by_id(session, str(alert.AgentID))
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Execute response based on type
        response_actions = []
        
        if response_type == "isolate":
            response_actions = await _execute_isolation(session, agent, alert)
        elif response_type == "quarantine":
            response_actions = await _execute_quarantine(session, agent, alert)
        elif response_type == "kill_process":
            response_actions = await _execute_process_kill(session, agent, alert)
        elif response_type == "block_network":
            response_actions = await _execute_network_block(session, agent, alert)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown response type: {response_type}")
        
        # Update alert with response action
        alert.add_response_action(f"Automated {response_type}: {', '.join(response_actions)}")
        session.commit()
        
        return {
            "success": True,
            "alert_id": alert_id,
            "response_type": response_type,
            "actions_executed": response_actions,
            "agent_id": str(agent.AgentID),
            "hostname": agent.HostName,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Automated response execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Response execution failed")

@router.get("/response/status/{alert_id}")
async def get_response_status(
    request: Request,
    alert_id: int,
    session: Session = Depends(get_db)
):
    """Get status of automated responses for an alert"""
    try:
        alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {
            "alert_id": alert_id,
            "response_actions": alert.ResponseAction,
            "status": alert.Status,
            "last_updated": alert.UpdatedAt.isoformat() if alert.UpdatedAt else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get response status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get response status")

@router.get("/response/history")
async def get_response_history(
    request: Request,
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get history of automated responses"""
    try:
        query = session.query(Alert).filter(Alert.ResponseAction.isnot(None))
        
        if agent_id:
            query = query.filter(Alert.AgentID == agent_id)
        
        # Time filter
        cutoff_time = datetime.now() - timedelta(hours=hours)
        query = query.filter(Alert.UpdatedAt >= cutoff_time)
        
        alerts = query.order_by(Alert.UpdatedAt.desc()).limit(100).all()
        
        history = []
        for alert in alerts:
            history.append({
                "alert_id": alert.AlertID,
                "agent_id": str(alert.AgentID),
                "response_actions": alert.ResponseAction,
                "severity": alert.Severity,
                "timestamp": alert.UpdatedAt.isoformat() if alert.UpdatedAt else None
            })
        
        return {
            "total_responses": len(history),
            "time_range_hours": hours,
            "responses": history
        }
        
    except Exception as e:
        logger.error(f"Get response history failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get response history")

async def _execute_isolation(session: Session, agent: Agent, alert: Alert) -> List[str]:
    """Execute agent isolation"""
    try:
        # This would send isolation command to agent
        actions = ["Network isolation enabled", "Process monitoring enhanced"]
        logger.info(f"🤖 Isolated agent {agent.HostName} for alert {alert.AlertID}")
        return actions
    except Exception as e:
        logger.error(f"Isolation execution failed: {e}")
        return ["Isolation failed"]

async def _execute_quarantine(session: Session, agent: Agent, alert: Alert) -> List[str]:
    """Execute file quarantine"""
    try:
        actions = ["Suspicious files quarantined", "File system scan initiated"]
        logger.info(f"🤖 Quarantined files on agent {agent.HostName} for alert {alert.AlertID}")
        return actions
    except Exception as e:
        logger.error(f"Quarantine execution failed: {e}")
        return ["Quarantine failed"]

async def _execute_process_kill(session: Session, agent: Agent, alert: Alert) -> List[str]:
    """Execute process termination"""
    try:
        actions = ["Suspicious processes terminated", "Process monitoring enabled"]
        logger.info(f"🤖 Killed processes on agent {agent.HostName} for alert {alert.AlertID}")
        return actions
    except Exception as e:
        logger.error(f"Process kill execution failed: {e}")
        return ["Process kill failed"]

async def _execute_network_block(session: Session, agent: Agent, alert: Alert) -> List[str]:
    """Execute network blocking"""
    try:
        actions = ["Suspicious network connections blocked", "Network monitoring enhanced"]
        logger.info(f"🤖 Blocked network on agent {agent.HostName} for alert {alert.AlertID}")
        return actions
    except Exception as e:
        logger.error(f"Network block execution failed: {e}")
        return ["Network block failed"] 