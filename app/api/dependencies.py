# app/api/dependencies.py
"""
API Dependencies
Database sessions, authentication, and validation helpers for EDR API
"""

import logging
from typing import Generator, Optional, Dict
from fastapi import Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.agent import Agent
from ..config import config
from ..utils.network_utils import is_internal_ip

logger = logging.getLogger(__name__)

# Database dependency (already handled in database.py but kept for consistency)
def get_database_session() -> Generator[Session, None, None]:
    """Get database session dependency"""
    return get_db()

# Agent authentication dependency
def verify_agent_token(x_agent_token: Optional[str] = Header(None, alias="X-Agent-Token")):
    """Verify agent authentication token"""
    expected_token = config['security']['agent_auth_token']
    
    if not x_agent_token:
        logger.warning("Missing agent authentication token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent authentication token required",
            headers={"X-Agent-Token": "Required"}
        )
    
    if x_agent_token != expected_token:
        logger.warning(f"Invalid agent authentication token: {x_agent_token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent authentication token"
        )
    
    return True

# Agent validation dependency
def get_agent_by_id(agent_id: str, session: Session = Depends(get_database_session)) -> Agent:
    """Get agent by ID and validate existence"""
    agent = Agent.get_by_id(session, agent_id)
    if not agent:
        logger.warning(f"Agent not found: {agent_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent not found: {agent_id}"
        )
    return agent

# Network access validation for agent endpoints
def validate_agent_network(request: Request):
    """Validate agent network access"""
    client_ip = request.client.host
    allowed_network = config['network']['allowed_agent_network']
    
    if not is_internal_ip(client_ip, allowed_network):
        logger.warning(f"🚫 Unauthorized access attempt from: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied from this network",
            headers={"X-Client-IP": client_ip}
        )
    return client_ip

# Request validation dependency
def validate_agent_request(
    request: Request,
    agent_token: str = Depends(verify_agent_token)
) -> dict:
    """Validate agent request and extract client info"""
    client_ip = request.client.host
    user_agent = request.headers.get("User-Agent", "Unknown")
    
    # Basic validation
    if not client_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to determine client IP"
        )
    
    return {
        "client_ip": client_ip,
        "user_agent": user_agent,
        "authenticated": True
    }

# Pagination dependency
def get_pagination_params(
    offset: int = 0,
    limit: int = 100
) -> dict:
    """Get and validate pagination parameters"""
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Offset must be non-negative"
        )
    
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be between 1 and 1000"
        )
    
    return {"offset": offset, "limit": limit}

# Time range validation
def validate_time_range(hours: int = 24) -> int:
    """Validate time range parameter"""
    if hours < 1 or hours > 8760:  # Max 1 year
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hours must be between 1 and 8760 (1 year)"
        )
    return hours

# Feature flag dependency
def require_feature(feature_name: str):
    """Require specific feature to be enabled"""
    def feature_dependency():
        if not config['features'].get(feature_name, False):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Feature '{feature_name}' is not enabled"
            )
        return True
    return feature_dependency

# Detection engine dependency
require_detection_engine = require_feature('real_time_detection')
require_threat_intelligence = require_feature('threat_intelligence')
require_event_collection = require_feature('event_collection')
require_agent_registration = require_feature('agent_registration')

# Common validation helpers
def validate_agent_status(status: str) -> str:
    """Validate agent status"""
    valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    return status

def validate_severity(severity: str) -> str:
    """Validate severity level"""
    valid_severities = ['Info', 'Low', 'Medium', 'High', 'Critical']
    if severity not in valid_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity. Must be one of: {valid_severities}"
        )
    return severity

def validate_event_type(event_type: str) -> str:
    """Validate event type"""
    valid_types = ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
    if event_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event type. Must be one of: {valid_types}"
        )
    return event_type

# Rate limiting helper (simplified)
class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed based on rate limit"""
        import time
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        if key in self.requests:
            self.requests[key] = [req_time for req_time in self.requests[key] if req_time > window_start]
        else:
            self.requests[key] = []
        
        # Check limit
        if len(self.requests[key]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[key].append(now)
        return True

# Rate limiting dependencies
agent_rate_limiter = RateLimiter(max_requests=120, window_seconds=60)  # 2 requests per second
event_rate_limiter = RateLimiter(max_requests=1000, window_seconds=60)  # High volume for events

def check_agent_rate_limit(request: Request):
    """Check rate limit for agent endpoints"""
    client_ip = request.client.host
    if not agent_rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for agent requests"
        )
    return True

def check_event_rate_limit(request: Request):
    """Check rate limit for event endpoints"""
    client_ip = request.client.host
    if not event_rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for event submissions"
        )
    return True