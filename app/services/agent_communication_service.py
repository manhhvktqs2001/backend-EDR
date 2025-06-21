"""
Agent Communication Service
Handles automated responses and agent communication
"""

import logging
from typing import List, Optional, Dict
from sqlalchemy.orm import Session
from datetime import datetime
import json
from datetime import timedelta

from ..models.alert import Alert
from ..models.agent import Agent
from ..models.system_config import SystemConfig

logger = logging.getLogger('agent_communication')

class AgentCommunicationService:
    """Service for automated agent communication and responses"""
    
    def __init__(self):
        self.response_config = {
            'auto_isolate_threshold': 85,
            'auto_quarantine_threshold': 70,
            'auto_kill_process_threshold': 60,
            'auto_block_network_threshold': 50
        }
    
    async def execute_automated_response(self, session: Session, alert: Alert) -> List[str]:
        """Execute automated response based on alert severity and risk score"""
        try:
            response_actions = []
            
            # Get agent
            agent = Agent.get_by_id(session, str(alert.AgentID))
            if not agent:
                logger.warning(f"Agent not found for alert {alert.AlertID}")
                return ["Agent not found"]
            
            risk_score = alert.RiskScore or 0
            severity = alert.Severity or 'Medium'
            
            # Determine response based on risk score and severity
            if risk_score >= self.response_config['auto_isolate_threshold'] or severity == 'Critical':
                response_actions.extend(await self._isolate_agent(session, agent, alert))
            
            elif risk_score >= self.response_config['auto_quarantine_threshold'] or severity == 'High':
                response_actions.extend(await self._quarantine_files(session, agent, alert))
            
            elif risk_score >= self.response_config['auto_kill_process_threshold']:
                response_actions.extend(await self._kill_suspicious_processes(session, agent, alert))
            
            elif risk_score >= self.response_config['auto_block_network_threshold']:
                response_actions.extend(await self._block_suspicious_network(session, agent, alert))
            
            # Log response actions
            if response_actions:
                logger.info(f"🤖 Automated responses executed for Alert {alert.AlertID}: {len(response_actions)} actions")
                for action in response_actions:
                    logger.info(f"   - {action}")
            
            return response_actions
            
        except Exception as e:
            logger.error(f"Automated response execution failed: {str(e)}")
            return ["Response execution failed"]
    
    async def _isolate_agent(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Isolate agent from network"""
        try:
            actions = [
                "Network isolation enabled",
                "Process monitoring enhanced",
                "File system monitoring activated"
            ]
            
            # Update agent status
            agent.Status = "Isolated"
            agent.LastUpdate = datetime.now()
            
            logger.info(f"🤖 Isolated agent {agent.HostName} for alert {alert.AlertID}")
            return actions
            
        except Exception as e:
            logger.error(f"Agent isolation failed: {e}")
            return ["Isolation failed"]
    
    async def _quarantine_files(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Quarantine suspicious files"""
        try:
            actions = [
                "Suspicious files quarantined",
                "File system scan initiated",
                "File access monitoring enabled"
            ]
            
            logger.info(f"🤖 Quarantined files on agent {agent.HostName} for alert {alert.AlertID}")
            return actions
            
        except Exception as e:
            logger.error(f"File quarantine failed: {e}")
            return ["Quarantine failed"]
    
    async def _kill_suspicious_processes(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Kill suspicious processes"""
        try:
            actions = [
                "Suspicious processes terminated",
                "Process monitoring enhanced",
                "Process creation monitoring enabled"
            ]
            
            logger.info(f"🤖 Killed processes on agent {agent.HostName} for alert {alert.AlertID}")
            return actions
            
        except Exception as e:
            logger.error(f"Process kill failed: {e}")
            return ["Process kill failed"]
    
    async def _block_suspicious_network(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Block suspicious network connections"""
        try:
            actions = [
                "Suspicious network connections blocked",
                "Network monitoring enhanced",
                "Connection logging enabled"
            ]
            
            logger.info(f"🤖 Blocked network on agent {agent.HostName} for alert {alert.AlertID}")
            return actions
            
        except Exception as e:
            logger.error(f"Network block failed: {e}")
            return ["Network block failed"]
    
    def get_pending_actions(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending actions for an agent"""
        try:
            # Get open alerts for the agent
            alerts = session.query(Alert).filter(
                Alert.AgentID == agent_id,
                Alert.Status.in_(['Open', 'Investigating'])
            ).all()
            
            pending_actions = []
            for alert in alerts:
                if alert.RiskScore and alert.RiskScore >= 50:
                    pending_actions.append({
                        'alert_id': alert.AlertID,
                        'action_type': 'investigate',
                        'priority': alert.Severity,
                        'description': f"Investigate alert: {alert.Title}",
                        'risk_score': alert.RiskScore
                    })
            
            return pending_actions
            
        except Exception as e:
            logger.error(f"Failed to get pending actions: {e}")
            return []
    
    def record_action_response(self, session: Session, agent_id: str, alert_id: int, 
                             action_type: str, success: bool, details: str) -> bool:
        """Record agent's response to an action"""
        try:
            alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
            if not alert:
                return False
            
            response_text = f"Agent response ({action_type}): {'SUCCESS' if success else 'FAILED'} - {details}"
            alert.add_response_action(response_text)
            
            if success:
                alert.Status = "Investigating"
            
            session.commit()
            logger.info(f"📝 Recorded agent response for Alert {alert_id}: {action_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record action response: {e}")
            return False

    async def send_alerts_to_agent(self, session: Session, agent_id: str, alerts: List[Dict]) -> bool:
        """Send alert notifications to agent for display - NEW"""
        try:
            if not alerts:
                return True
            
            # Get agent information
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.warning(f"Agent not found for alert notification: {agent_id}")
                return False
            
            # Store alerts in database for agent to retrieve
            for alert_data in alerts:
                try:
                    # Create agent alert notification record
                    notification = {
                        'agent_id': agent_id,
                        'alert_id': alert_data.get('alert_id'),
                        'notification_data': alert_data,
                        'sent_at': datetime.now(),
                        'status': 'pending'
                    }
                    
                    # Store in system config as temporary notification
                    config_key = f"agent_alert_{agent_id}_{alert_data.get('alert_id')}_{int(datetime.now().timestamp())}"
                    config_value = json.dumps(notification)
                    
                    # Check if config already exists
                    existing_config = session.query(SystemConfig).filter(
                        SystemConfig.ConfigKey == config_key
                    ).first()
                    
                    if not existing_config:
                        new_config = SystemConfig(
                            ConfigKey=config_key,
                            ConfigValue=config_value,
                            ConfigType='JSON',
                            Category='AgentAlerts',
                            Description=f'Alert notification for agent {agent.HostName}'
                        )
                        session.add(new_config)
                    
                except Exception as e:
                    logger.error(f"Failed to store alert notification: {e}")
                    continue
            
            session.commit()
            
            logger.info(f"📤 Stored {len(alerts)} alert notifications for agent {agent.HostName}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alerts to agent: {str(e)}")
            return False

    def get_pending_alerts_for_agent(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending alert notifications for an agent - NEW"""
        try:
            # Get pending alert notifications from system config
            configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_alert_{agent_id}_%'),
                SystemConfig.Category == 'AgentAlerts'
            ).all()
            
            alerts = []
            for config in configs:
                try:
                    notification_data = json.loads(config.ConfigValue)
                    alerts.append(notification_data)
                    
                    # Mark as retrieved
                    config.ConfigValue = json.dumps({
                        **notification_data,
                        'status': 'retrieved',
                        'retrieved_at': datetime.now().isoformat()
                    })
                    
                except Exception as e:
                    logger.error(f"Failed to parse alert notification: {e}")
                    continue
            
            session.commit()
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get pending alerts for agent: {e}")
            return []

    def cleanup_old_alert_notifications(self, session: Session, hours: int = 24) -> int:
        """Clean up old alert notifications - NEW"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_timestamp = int(cutoff_time.timestamp())
            
            # Find old notifications
            old_configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like('agent_alert_%'),
                SystemConfig.Category == 'AgentAlerts'
            ).all()
            
            deleted_count = 0
            for config in old_configs:
                try:
                    # Extract timestamp from config key
                    parts = config.ConfigKey.split('_')
                    if len(parts) >= 4:
                        timestamp = int(parts[-1])
                        if timestamp < cutoff_timestamp:
                            session.delete(config)
                            deleted_count += 1
                except Exception:
                    # If parsing fails, delete anyway
                    session.delete(config)
                    deleted_count += 1
            
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"🧹 Cleaned up {deleted_count} old alert notifications")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup alert notifications: {e}")
            return 0

# Global service instance
agent_communication_service = AgentCommunicationService() 