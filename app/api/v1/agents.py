"""
Agents API Endpoints
Agent registration, heartbeat, and management
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.orm import Session

from ...database import get_db
from ...models.agent import Agent
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
        raise HTTPException(status_code=500, detail="Registration failed")

@router.post("/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(
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
            logger.warning(f"Heartbeat failed for {heartbeat_data.hostname}: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat processing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Heartbeat processing failed")

@router.get("/list", response_model=AgentListResponse)
async def list_agents(
    request: Request,
    status: Optional[str] = None,
    limit: int = 100,
    session: Session = Depends(get_db)
):
    """List all agents with optional filtering"""
    try:
        query = session.query(Agent)
        
        if status:
            query = query.filter(Agent.Status == status)
        
        agents = query.order_by(Agent.LastHeartbeat.desc()).limit(limit).all()
        
        # Convert to summary format
        agent_summaries = []
        for agent in agents:
            summary = agent.to_summary()
            agent_summaries.append(summary)
        
        # Get counts
        total_count = len(agent_summaries)
        online_count = len([a for a in agents if a.is_online()])
        offline_count = total_count - online_count
        
        # Get overall summary
        overall_summary = Agent.get_agents_summary(session)
        
        return AgentListResponse(
            agents=agent_summaries,
            total_count=total_count,
            online_count=online_count,
            offline_count=offline_count,
            summary=overall_summary
        )
        
    except Exception as e:
        logger.error(f"List agents failed: {str(e)}")
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
        
        agent_data = agent.to_dict(include_sensitive=False)
        return AgentResponse(**agent_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent details failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent details")

@router.get("/{agent_id}/config", response_model=AgentConfigResponse)
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
        logger.error(f"Get agent config failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent configuration")

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
        
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        return {
            "success": True,
            "message": message,
            "agent_id": agent_id,
            "updated_status": status_update.status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update agent status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update agent status")

@router.get("/stats/summary", response_model=AgentStatsResponse)
async def get_agent_statistics(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get agent statistics summary"""
    try:
        health_status = agent_service.get_agent_health_status(session)
        
        if 'error' in health_status:
            raise HTTPException(status_code=500, detail=health_status['error'])
        
        # Build response
        summary = health_status['summary']
        
        # Connection status breakdown
        connection_breakdown = {
            'online': health_status['online_agents'],
            'offline': health_status['offline_agents']
        }
        
        # Performance summary
        performance_summary = {
            'healthy_agents': summary['total_agents'] - health_status['unhealthy_agents'],
            'unhealthy_agents': health_status['unhealthy_agents'],
            'performance_issues': len(health_status['unhealthy_details'])
        }
        
        return AgentStatsResponse(
            total_agents=summary['total_agents'],
            active_agents=summary['active_agents'],
            online_agents=summary['online_agents'],
            offline_agents=summary['offline_agents'],
            inactive_agents=summary['inactive_agents'],
            os_breakdown=summary['os_breakdown'],
            connection_status_breakdown=connection_breakdown,
            performance_summary=performance_summary
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent statistics failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent statistics")

@router.post("/cleanup")
async def cleanup_stale_agents(
    request: Request,
    hours: int = 24,
    session: Session = Depends(get_db)
):
    """Cleanup stale agents (mark as offline)"""
    try:
        count, agent_list = agent_service.cleanup_stale_agents(session, hours)
        
        return {
            "success": True,
            "message": f"Marked {count} agents as offline",
            "agents_updated": agent_list,
            "hours_threshold": hours
        }
        
    except Exception as e:
        logger.error(f"Cleanup stale agents failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup stale agents")

@router.get("/health/overview")
async def get_agents_health_overview(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get agents health overview"""
    try:
        health_status = agent_service.get_agent_health_status(session)
        
        if 'error' in health_status:
            raise HTTPException(status_code=500, detail=health_status['error'])
        
        return {
            "status": "success",
            "data": health_status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agents health overview failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get health overview")