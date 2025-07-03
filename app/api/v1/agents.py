# app/api/v1/agents.py - FIXED: Handle unknown hostname gracefully
"""
Agents API Endpoints - FIXED
Handle agents with "unknown" hostname and provide helpful error messages
"""

import logging
import asyncio
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query, BackgroundTasks
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
    """Agent registration endpoint - FIXED for hostname issues"""
    try:
        client_ip = request.client.host
        
        # FIXED: Log registration attempt with better info
        logger.info(f"📝 AGENT REGISTRATION ATTEMPT:")
        logger.info(f"   🌐 Client IP: {client_ip}")
        logger.info(f"   🖥️ Hostname: '{agent_data.hostname}'")
        logger.info(f"   📍 IP Address: '{agent_data.ip_address}'")
        logger.info(f"   💻 OS: {agent_data.operating_system}")
        
        success, response, error = agent_service.register_agent(session, agent_data, client_ip)
        
        if not success:
            logger.warning(f"❌ Agent registration failed: {error}")
            
            # FIXED: Provide helpful error response for debugging
            if "hostname" in error.lower() and "unknown" in agent_data.hostname.lower():
                helpful_error = (
                    f"Registration failed: {error}. "
                    f"Consider using hostname 'Agent-{client_ip.replace('.', '-')}' or configure proper hostname on the agent."
                )
                raise HTTPException(status_code=400, detail=helpful_error)
            
            raise HTTPException(status_code=400, detail=error)
        
        logger.info(f"✅ Agent registered successfully: {response.agent_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Get agent status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent status")

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
    all: bool = False,
    limit: int = None,
    session: Session = Depends(get_db)
):
    """List all agents, hỗ trợ lấy toàn bộ nếu all=true hoặc limit=0"""
    try:
        # Get agent summaries
        agents_summary = Agent.get_agents_summary(session)
        # Lấy agents theo all/limit
        query = session.query(Agent).order_by(Agent.LastHeartbeat.desc())
        if not all and limit not in (None, 0):
            query = query.limit(limit)
        agents = query.all()
        agent_summaries = [agent.to_summary() for agent in agents]
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
    """Get specific agent details - FIXED with IP fallback"""
    try:
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            # FIXED: Try to find by IP as fallback
            client_ip = request.client.host
            agent = Agent.get_by_ip(session, client_ip)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            else:
                logger.info(f"🔍 Found agent by IP: {agent.HostName} ({client_ip})")
        
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

# ========================================================================================
# DIAGNOSTIC ENDPOINTS - NEW for troubleshooting
# ========================================================================================

@router.get("/diagnostic/by-ip/{client_ip}")
async def get_agent_by_ip_diagnostic(
    request: Request,
    client_ip: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Diagnostic endpoint to find agent by IP"""
    try:
        logger.info(f"🔍 DIAGNOSTIC: Looking for agent with IP {client_ip}")
        
        agent = Agent.get_by_ip(session, client_ip)
        if agent:
            logger.info(f"✅ Found agent: {agent.HostName} (ID: {agent.AgentID})")
            return {
                "success": True,
                "found": True,
                "agent": {
                    "agent_id": str(agent.AgentID),
                    "hostname": agent.HostName,
                    "ip_address": agent.IPAddress,
                    "status": agent.Status,
                    "last_heartbeat": agent.LastHeartbeat.isoformat() if agent.LastHeartbeat else None,
                    "monitoring_enabled": agent.MonitoringEnabled
                }
            }
        else:
            logger.info(f"❌ No agent found with IP {client_ip}")
            
            # Suggest possible matches
            all_agents = session.query(Agent).all()
            suggestions = []
            for ag in all_agents:
                if ag.IPAddress and client_ip in ag.IPAddress:
                    suggestions.append({
                        "hostname": ag.HostName,
                        "ip_address": ag.IPAddress,
                        "similarity": "IP contains query"
                    })
            
            return {
                "success": True,
                "found": False,
                "message": f"No agent found with IP {client_ip}",
                "suggestions": suggestions,
                "suggested_hostname": f"Agent-{client_ip.replace('.', '-')}"
            }
        
    except Exception as e:
        logger.error(f"💥 Diagnostic by IP failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Diagnostic failed")

@router.get("/diagnostic/by-hostname/{hostname}")
async def get_agent_by_hostname_diagnostic(
    request: Request,
    hostname: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Diagnostic endpoint to find agent by hostname"""
    try:
        logger.info(f"🔍 DIAGNOSTIC: Looking for agent with hostname '{hostname}'")
        
        agent = Agent.get_by_hostname(session, hostname)
        if agent:
            logger.info(f"✅ Found agent: {agent.HostName} (ID: {agent.AgentID})")
            return {
                "success": True,
                "found": True,
                "agent": {
                    "agent_id": str(agent.AgentID),
                    "hostname": agent.HostName,
                    "ip_address": agent.IPAddress,
                    "status": agent.Status,
                    "last_heartbeat": agent.LastHeartbeat.isoformat() if agent.LastHeartbeat else None
                }
            }
        else:
            logger.info(f"❌ No agent found with hostname '{hostname}'")
            
            # Suggest possible matches
            all_agents = session.query(Agent).all()
            suggestions = []
            hostname_lower = hostname.lower()
            
            for ag in all_agents:
                if ag.HostName and hostname_lower in ag.HostName.lower():
                    suggestions.append({
                        "hostname": ag.HostName,
                        "ip_address": ag.IPAddress,
                        "similarity": "Hostname contains query"
                    })
            
            return {
                "success": True,
                "found": False,
                "message": f"No agent found with hostname '{hostname}'",
                "suggestions": suggestions,
                "all_hostnames": [ag.HostName for ag in all_agents if ag.HostName]
            }
        
    except Exception as e:
        logger.error(f"💥 Diagnostic by hostname failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Diagnostic failed")

@router.post("/diagnostic/auto-register/{client_ip}")
async def auto_register_agent_diagnostic(
    request: Request,
    client_ip: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Diagnostic endpoint to manually trigger auto-registration"""
    try:
        logger.info(f"🔧 DIAGNOSTIC: Manual auto-registration for {client_ip}")
        
        # Check if agent already exists
        existing = Agent.get_by_ip(session, client_ip)
        if existing:
            return {
                "success": False,
                "message": f"Agent already exists: {existing.HostName}",
                "existing_agent": {
                    "hostname": existing.HostName,
                    "agent_id": str(existing.AgentID),
                    "status": existing.Status
                }
            }
        
        # Generate hostname and create agent
        suggested_hostname = f"Agent-{client_ip.replace('.', '-')}"
        
        registration_data = AgentRegisterRequest(
            hostname=suggested_hostname,
            ip_address=client_ip,
            operating_system="Windows (Diagnostic Auto-Registration)",
            agent_version="2.1.0"
        )
        
        success, response, error = agent_service.register_agent(session, registration_data, client_ip)
        
        if success:
            logger.info(f"✅ Diagnostic auto-registration successful: {response.agent_id}")
            return {
                "success": True,
                "message": "Auto-registration successful",
                "agent": {
                    "agent_id": response.agent_id,
                    "hostname": suggested_hostname,
                    "ip_address": client_ip
                }
            }
        else:
            logger.error(f"❌ Diagnostic auto-registration failed: {error}")
            return {
                "success": False,
                "message": f"Auto-registration failed: {error}"
            }
        
    except Exception as e:
        logger.error(f"💥 Diagnostic auto-registration failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Diagnostic auto-registration failed")

# ========================================================================================
# REMAINING ENDPOINTS (unchanged)
# ========================================================================================

@router.get("/{agent_id}/pending-alerts")
async def get_pending_alerts(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get pending alerts for agent"""
    try:
        # Validate agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            logger.error(f"❌ Agent not found: {agent_id}")
            raise HTTPException(status_code=404, detail="Agent not found")
        
        logger.info(f"📋 PENDING ALERTS REQUEST:")
        logger.info(f"   🎯 Agent: {agent.HostName} ({agent_id})")
        
        # Get pending alerts for the agent
        pending_alerts = session.query(Alert).filter(
            Alert.AgentID == agent_id,
            Alert.Status.in_(['Open', 'Investigating'])
        ).order_by(Alert.FirstDetected.desc()).limit(50).all()
        
        alerts_data = []
        for alert in pending_alerts:
            try:
                alert_data = {
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
                    'age_minutes': alert.get_age_minutes() if hasattr(alert, 'get_age_minutes') else 0,
                    'status': alert.Status,
                    'event_id': alert.EventID,
                    'rule_id': alert.RuleID,
                    'threat_id': alert.ThreatID,
                    'server_generated': True,
                    'rule_violation': True
                }
                alerts_data.append(alert_data)
                
            except Exception as e:
                logger.error(f"   💥 Failed to process alert {alert.AlertID}: {e}")
                continue
        
        logger.info(f"📋 PENDING ALERTS RESPONSE:")
        logger.info(f"   🎯 Agent: {agent.HostName}")
        logger.info(f"   📊 Alert Count: {len(alerts_data)}")
        
        if alerts_data:
            # Log alert details
            for alert in alerts_data:
                logger.info(f"   📋 Alert {alert['alert_id']}: {alert['title']} (Severity: {alert['severity']})")
        
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
        logger.error(f"💥 Get pending alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get pending alerts")

@router.post("/heartbeat", response_model=AgentHeartbeatResponse)
async def heartbeat(
    request: Request,
    heartbeat_data: AgentHeartbeatRequest,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Agent heartbeat endpoint - FIXED for unknown hostname"""
    try:
        client_ip = request.client.host
        
        # FIXED: Enhanced logging for debugging
        logger.debug(f"💓 HEARTBEAT from {client_ip}:")
        logger.debug(f"   🖥️ Hostname: '{heartbeat_data.hostname}'")
        logger.debug(f"   📊 CPU: {heartbeat_data.cpu_usage}%, Memory: {heartbeat_data.memory_usage}%, Disk: {heartbeat_data.disk_usage}%")
        
        success, response, error = agent_service.process_heartbeat(session, heartbeat_data, client_ip)
        
        if not success:
            logger.warning(f"⚠️ Heartbeat failed from {client_ip}: {error}")
            
            # FIXED: Provide helpful error messages for common issues
            if "not found" in error.lower() and "unknown" in heartbeat_data.hostname.lower():
                helpful_error = (
                    f"Agent not found with hostname '{heartbeat_data.hostname}'. "
                    f"This usually happens when the agent hasn't been registered yet. "
                    f"Please register the agent first using the /register endpoint."
                )
                
                # Try to auto-register with suggested hostname if enabled
                if _should_auto_register(client_ip):
                    logger.info(f"🔧 Attempting auto-registration for {client_ip}")
                    auto_reg_result = await _attempt_auto_registration(session, client_ip, heartbeat_data)
                    if auto_reg_result:
                        logger.info(f"✅ Auto-registration successful for {client_ip}")
                        return auto_reg_result
                
                raise HTTPException(status_code=404, detail=helpful_error)
            
            raise HTTPException(status_code=400, detail=error)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Heartbeat processing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Heartbeat processing failed")

async def _should_auto_register(client_ip: str) -> bool:
    """Check if auto-registration should be attempted"""
    try:
        # Only auto-register for internal IPs
        from ...utils.network_utils import is_internal_ip
        from ...config import config
        
        allowed_network = config['network']['allowed_agent_network']
        auto_approve = config['agent'].get('auto_approve_registration', True)
        
        return auto_approve and is_internal_ip(client_ip, allowed_network)
    except:
        return False

async def _attempt_auto_registration(session: Session, client_ip: str, 
                                   heartbeat_data: AgentHeartbeatRequest) -> Optional[AgentHeartbeatResponse]:
    """Attempt to auto-register agent and then process heartbeat"""
    try:
        # Generate hostname from IP
        suggested_hostname = f"Agent-{client_ip.replace('.', '-')}"
        
        # Create registration data from heartbeat data
        registration_data = AgentRegisterRequest(
            hostname=suggested_hostname,
            ip_address=client_ip,
            operating_system="Windows (Auto-detected)",  # Default assumption
            agent_version="2.1.0"
        )
        
        # Attempt registration
        success, reg_response, error = agent_service.register_agent(session, registration_data, client_ip)
        
        if success:
            logger.info(f"🎯 Auto-registered agent: {suggested_hostname} ({client_ip})")
            
            # Now process the heartbeat with the new hostname
            heartbeat_data.hostname = suggested_hostname
            hb_success, hb_response, hb_error = agent_service.process_heartbeat(session, heartbeat_data, client_ip)
            
            if hb_success:
                return hb_response
            else:
                logger.warning(f"⚠️ Auto-registration succeeded but heartbeat failed: {hb_error}")
        else:
            logger.warning(f"⚠️ Auto-registration failed: {error}")
        
        return None
        
    except Exception as e:
        logger.error(f"💥 Auto-registration failed: {str(e)}")
        return None

# ========================================================================================
# EXISTING NOTIFICATION ENDPOINTS (unchanged)
# ========================================================================================

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
            logger.error(f"❌ Agent not found: {agent_id}")
            raise HTTPException(status_code=404, detail="Agent not found")
        
        logger.info(f"📥 NOTIFICATION REQUEST:")
        logger.info(f"   🎯 Agent: {agent.HostName} ({agent_id})")
        logger.info(f"   📡 Client IP: {request.client.host}")
        
        # Get notifications using the communication service
        from ...services.agent_communication_service import agent_communication_service
        
        notifications = agent_communication_service.get_pending_notifications(session, agent_id)
        
        if notifications:
            logger.warning(f"📤 NOTIFICATIONS DELIVERED:")
            logger.warning(f"   🎯 Agent: {agent.HostName}")
            logger.warning(f"   📊 Count: {len(notifications)}")
            
            # Log each notification for debugging
            for i, notif in enumerate(notifications):
                notif_type = notif.get('type', 'unknown')
                notif_title = notif.get('title', 'No title')
                notif_severity = notif.get('severity', 'Unknown')
                alert_id = notif.get('alert_id', 'N/A')
                logger.warning(f"   📋 {i+1}. {notif_type}: {notif_title} (Severity: {notif_severity}, Alert: {alert_id})")
        else:
            logger.info(f"📭 No pending notifications for {agent.HostName}")
        
        response = {
            "success": True,
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "notifications": notifications,
            "count": len(notifications),
            "retrieved_at": datetime.now().isoformat(),
            "client_ip": request.client.host
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Get notifications failed: {str(e)}")
        logger.error(f"   🎯 Agent: {agent_id}")
        raise HTTPException(status_code=500, detail="Failed to get notifications")

@router.get("/{agent_id}/status")
async def get_agent_status(
    request: Request,
    agent_id: str,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Get agent status - FIXED with better error handling"""
    try:
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            # FIXED: Try to find by IP as fallback
            client_ip = request.client.host
            agent = Agent.get_by_ip(session, client_ip)
            if not agent:
                logger.warning(f"❌ Agent not found: {agent_id} (IP: {client_ip})")
                raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
            else:
                logger.info(f"🔍 Found agent by IP instead: {agent.HostName} ({client_ip})")
        
        # Get recent activity
        last_24h = datetime.now() - timedelta(hours=24)
        recent_events = session.query(Alert).filter(
            Alert.AgentID == str(agent.AgentID),
            Alert.FirstDetected >= last_24h
        ).count()
        
        return {
            "success": True,
            "agent_id": str(agent.AgentID),
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
        logger.error(f"💥 Get agent status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent status")