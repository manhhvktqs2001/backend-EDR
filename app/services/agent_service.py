"""
Agent Management Service
Business logic for agent registration, heartbeat, and management
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from ..models.agent import Agent
from ..schemas.agent import (
    AgentRegisterRequest, AgentRegisterResponse,
    AgentHeartbeatRequest, AgentHeartbeatResponse,
    AgentConfigResponse
)
from ..config import config
from ..utils.network_utils import validate_ip_address, is_internal_ip

logger = logging.getLogger('agent_communication')

class AgentService:
    """Service for managing EDR agents"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.network_config = config['network']
    
    def register_agent(self, session: Session, registration_data: AgentRegisterRequest, 
                      client_ip: str) -> Tuple[bool, AgentRegisterResponse, Optional[str]]:
        """
        Register new agent or update existing agent
        Returns: (success, response, error_message)
        """
        try:
            # Validate network access
            if not self._validate_agent_network(client_ip):
                error_msg = f"Agent registration denied from IP: {client_ip}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # Check if agent already exists by hostname
            existing_agent = Agent.get_by_hostname(session, registration_data.hostname)
            
            if existing_agent:
                # Update existing agent
                success, response, error = self._update_existing_agent(
                    session, existing_agent, registration_data, client_ip
                )
                return success, response, error
            else:
                # Register new agent
                success, response, error = self._register_new_agent(
                    session, registration_data, client_ip
                )
                return success, response, error
                
        except Exception as e:
            error_msg = f"Agent registration failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def _register_new_agent(self, session: Session, registration_data: AgentRegisterRequest,
                           client_ip: str) -> Tuple[bool, AgentRegisterResponse, Optional[str]]:
        """Register completely new agent"""
        try:
            # Check for IP conflicts
            existing_ip_agent = Agent.get_by_ip(session, registration_data.ip_address)
            if existing_ip_agent and existing_ip_agent.HostName != registration_data.hostname:
                logger.warning(f"IP conflict: {registration_data.ip_address} already used by {existing_ip_agent.HostName}")
            
            # Create new agent
            new_agent = Agent.create_agent(
                hostname=registration_data.hostname,
                ip_address=registration_data.ip_address,
                operating_system=registration_data.operating_system,
                OSVersion=registration_data.os_version,
                Architecture=registration_data.architecture,
                AgentVersion=registration_data.agent_version,
                MACAddress=registration_data.mac_address,
                Domain=registration_data.domain,
                InstallPath=registration_data.install_path,
                Status='Active',
                MonitoringEnabled=True
            )
            
            session.add(new_agent)
            session.commit()
            session.refresh(new_agent)
            
            logger.info(f"New agent registered: {registration_data.hostname} ({registration_data.ip_address})")
            
            response = AgentRegisterResponse(
                success=True,
                agent_id=str(new_agent.AgentID),
                message="Agent registered successfully",
                config_version=self.agent_config['config_version'],
                heartbeat_interval=self.agent_config['heartbeat_interval'],
                monitoring_enabled=True
            )
            
            return True, response, None
            
        except IntegrityError as e:
            session.rollback()
            error_msg = f"Agent registration failed - duplicate entry: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
        except Exception as e:
            session.rollback()
            error_msg = f"Agent registration failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def _update_existing_agent(self, session: Session, existing_agent: Agent,
                              registration_data: AgentRegisterRequest, client_ip: str) -> Tuple[bool, AgentRegisterResponse, Optional[str]]:
        """Update existing agent information"""
        try:
            # Update agent information
            existing_agent.IPAddress = registration_data.ip_address
            existing_agent.OperatingSystem = registration_data.operating_system
            existing_agent.OSVersion = registration_data.os_version
            existing_agent.Architecture = registration_data.architecture
            existing_agent.AgentVersion = registration_data.agent_version
            existing_agent.MACAddress = registration_data.mac_address
            existing_agent.Domain = registration_data.domain
            existing_agent.InstallPath = registration_data.install_path
            existing_agent.Status = 'Active'
            existing_agent.update_heartbeat()
            
            session.commit()
            
            logger.info(f"Existing agent updated: {registration_data.hostname} ({registration_data.ip_address})")
            
            response = AgentRegisterResponse(
                success=True,
                agent_id=str(existing_agent.AgentID),
                message="Agent information updated successfully",
                config_version=self.agent_config['config_version'],
                heartbeat_interval=self.agent_config['heartbeat_interval'],
                monitoring_enabled=existing_agent.MonitoringEnabled
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            error_msg = f"Agent update failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def process_heartbeat(self, session: Session, heartbeat_data: AgentHeartbeatRequest,
                         client_ip: str) -> Tuple[bool, AgentHeartbeatResponse, Optional[str]]:
        """
        Process agent heartbeat
        Returns: (success, response, error_message)
        """
        try:
            # Find agent by hostname
            agent = Agent.get_by_hostname(session, heartbeat_data.hostname)
            if not agent:
                error_msg = f"Agent not found: {heartbeat_data.hostname}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # Update heartbeat and performance metrics
            performance_data = {
                'cpu_usage': heartbeat_data.cpu_usage,
                'memory_usage': heartbeat_data.memory_usage,
                'disk_usage': heartbeat_data.disk_usage,
                'network_latency': heartbeat_data.network_latency
            }
            
            agent.update_heartbeat(performance_data)
            
            # Update status if provided
            if heartbeat_data.status:
                agent.set_status(heartbeat_data.status)
            
            session.commit()
            
            logger.debug(f"Heartbeat received from {heartbeat_data.hostname}")
            
            response = AgentHeartbeatResponse(
                success=True,
                message="Heartbeat received",
                config_version=self.agent_config['config_version'],
                monitoring_enabled=agent.MonitoringEnabled,
                next_heartbeat=self.agent_config['heartbeat_interval']
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            error_msg = f"Heartbeat processing failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def get_agent_config(self, session: Session, agent_id: str) -> Optional[AgentConfigResponse]:
        """Get agent configuration"""
        try:
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                return None
            
            config_response = AgentConfigResponse(
                agent_id=str(agent.AgentID),
                hostname=agent.HostName,
                config_version=self.agent_config['config_version'],
                monitoring_enabled=agent.MonitoringEnabled,
                heartbeat_interval=self.agent_config['heartbeat_interval'],
                event_batch_size=self.agent_config['event_batch_size'],
                collection_settings={
                    'collect_processes': True,
                    'collect_files': True,
                    'collect_network': True,
                    'collect_registry': agent.OperatingSystem.lower().startswith('windows'),
                    'collect_authentication': True
                },
                detection_settings={
                    'enable_realtime_detection': config['detection']['rules_enabled'],
                    'enable_threat_intel': config['detection']['threat_intel_enabled'],
                    'risk_threshold': config['detection']['risk_score_threshold']
                }
            )
            
            return config_response
            
        except Exception as e:
            logger.error(f"Failed to get agent config: {str(e)}")
            return None
    
    def update_agent_status(self, session: Session, agent_id: str, status: str,
                           monitoring_enabled: Optional[bool] = None) -> Tuple[bool, str]:
        """Update agent status and monitoring settings"""
        try:
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                return False, "Agent not found"
            
            agent.set_status(status)
            
            if monitoring_enabled is not None:
                if monitoring_enabled:
                    agent.enable_monitoring()
                else:
                    agent.disable_monitoring()
            
            session.commit()
            
            logger.info(f"Agent {agent.HostName} status updated to {status}")
            return True, "Agent status updated successfully"
            
        except Exception as e:
            session.rollback()
            error_msg = f"Failed to update agent status: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_agent_health_status(self, session: Session) -> Dict:
        """Get overall agent health status"""
        try:
            summary = Agent.get_agents_summary(session)
            
            # Get agents by connection status
            online_agents = Agent.get_online_agents(session, timeout_minutes=5)
            offline_agents = Agent.get_offline_agents(session, timeout_minutes=30)
            
            # Performance analysis
            unhealthy_agents = []
            for agent in online_agents:
                if not agent.is_healthy():
                    unhealthy_agents.append({
                        'agent_id': str(agent.AgentID),
                        'hostname': agent.HostName,
                        'health_status': agent.get_health_status()
                    })
            
            return {
                'summary': summary,
                'online_agents': len(online_agents),
                'offline_agents': len(offline_agents),
                'unhealthy_agents': len(unhealthy_agents),
                'unhealthy_details': unhealthy_agents,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get agent health status: {str(e)}")
            return {'error': str(e)}
    
    def cleanup_stale_agents(self, session: Session, hours: int = 24) -> Tuple[int, List[str]]:
        """Mark agents as offline if they haven't sent heartbeat in specified hours"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            stale_agents = session.query(Agent).filter(
                Agent.LastHeartbeat < cutoff_time,
                Agent.Status != 'Offline'
            ).all()
            
            updated_agents = []
            for agent in stale_agents:
                agent.set_status('Offline')
                updated_agents.append(agent.HostName)
                logger.info(f"Marked agent as offline: {agent.HostName}")
            
            session.commit()
            
            return len(updated_agents), updated_agents
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to cleanup stale agents: {str(e)}")
            return 0, []
    
    def _validate_agent_network(self, client_ip: str) -> bool:
        """Validate if agent IP is allowed"""
        try:
            # Check if IP is valid
            if not validate_ip_address(client_ip):
                return False
            
            # Check if IP is in allowed network range
            allowed_network = self.network_config['allowed_agent_network']
            return is_internal_ip(client_ip, allowed_network)
            
        except Exception as e:
            logger.error(f"Network validation failed: {str(e)}")
            return False

# Global service instance
agent_service = AgentService()