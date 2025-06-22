# app/api/v1/agents.py - MODIFIED (Add notification endpoints)
"""
Agents API Endpoints - MODIFIED
Added endpoints for agent to get detection notifications
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.orm import Session
from datetime import datetime
import json

from ...database import get_db
from ...models.agent import Agent
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