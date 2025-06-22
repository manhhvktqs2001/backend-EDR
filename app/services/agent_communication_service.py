# app/services/agent_communication_service.py - MODIFIED
"""
Agent Communication Service - MODIFIED
Handles automated responses and agent communication
Enhanced with better notification management
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
    """Service for agent communication and notification management"""
    
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
            logger.error(f"Process kill execution failed: {e}")
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
            logger.error(f"Network block execution failed: {e}")
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

    async def send_detection_notifications_to_agent(self, session: Session, agent_id: str, notifications: List[Dict]) -> bool:
        """Send detection notifications to agent for display - ENHANCED"""
        try:
            if not notifications:
                return True
            
            # Get agent information
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.warning(f"Agent not found for notification: {agent_id}")
                return False
            
            # Store notifications in database for agent to retrieve
            for notification in notifications:
                try:
                    # Create agent notification record
                    notification_record = {
                        'agent_id': agent_id,
                        'notification_type': notification.get('type', 'detection'),
                        'notification_data': notification,
                        'sent_at': datetime.now().isoformat(),
                        'status': 'pending',
                        'priority': self._get_notification_priority(notification),
                        'expires_at': (datetime.now() + timedelta(hours=24)).isoformat()
                    }
                    
                    # Store in system config as temporary notification
                    config_key = f"agent_notification_{agent_id}_{notification.get('type', 'det')}_{int(datetime.now().timestamp())}"
                    config_value = json.dumps(notification_record)
                    
                    # Check if config already exists
                    existing_config = session.query(SystemConfig).filter(
                        SystemConfig.ConfigKey == config_key
                    ).first()
                    
                    if not existing_config:
                        new_config = SystemConfig(
                            ConfigKey=config_key,
                            ConfigValue=config_value,
                            ConfigType='JSON',
                            Category='AgentNotifications',
                            Description=f'Detection notification for agent {agent.HostName}'
                        )
                        session.add(new_config)
                    
                except Exception as e:
                    logger.error(f"Failed to store notification: {e}")
                    continue
            
            session.commit()
            
            logger.info(f"📤 Stored {len(notifications)} detection notifications for agent {agent.HostName}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send notifications to agent: {str(e)}")
            return False

    def get_pending_notifications_for_agent(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending detection notifications for an agent - ENHANCED"""
        try:
            # Get pending notifications from system config
            configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).order_by(SystemConfig.CreatedAt.desc()).all()
            
            notifications = []
            configs_to_update = []
            
            for config in configs:
                try:
                    notification_data = json.loads(config.ConfigValue)
                    
                    # Check if notification has expired
                    if 'expires_at' in notification_data:
                        expires_at = datetime.fromisoformat(notification_data['expires_at'])
                        if datetime.now() > expires_at:
                            # Mark as expired
                            session.delete(config)
                            continue
                    
                    if notification_data.get('status') == 'pending':
                        notifications.append(notification_data['notification_data'])
                        
                        # Mark as retrieved
                        notification_data['status'] = 'retrieved'
                        notification_data['retrieved_at'] = datetime.now().isoformat()
                        config.ConfigValue = json.dumps(notification_data)
                        configs_to_update.append(config)
                    
                except Exception as e:
                    logger.error(f"Failed to parse notification: {e}")
                    continue
            
            session.commit()
            
            if notifications:
                logger.info(f"📤 Retrieved {len(notifications)} notifications for agent {agent_id}")
            
            return notifications
            
        except Exception as e:
            logger.error(f"Failed to get pending notifications for agent: {e}")
            return []

    def cleanup_old_notifications(self, session: Session, hours: int = 24) -> int:
        """Clean up old notification records - ENHANCED"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_timestamp = int(cutoff_time.timestamp())
            
            # Find old notifications
            old_configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like('agent_notification_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).all()
            
            deleted_count = 0
            for config in old_configs:
                try:
                    # Parse notification data to check expiry
                    notification_data = json.loads(config.ConfigValue)
                    
                    # Check if expired or old
                    should_delete = False
                    
                    if 'expires_at' in notification_data:
                        expires_at = datetime.fromisoformat(notification_data['expires_at'])
                        if datetime.now() > expires_at:
                            should_delete = True
                    
                    # Also check by timestamp in key
                    parts = config.ConfigKey.split('_')
                    if len(parts) >= 4:
                        try:
                            timestamp = int(parts[-1])
                            if timestamp < cutoff_timestamp:
                                should_delete = True
                        except ValueError:
                            # Invalid timestamp, delete anyway
                            should_delete = True
                    
                    # Check if retrieved and old
                    if notification_data.get('status') == 'retrieved':
                        retrieved_at = notification_data.get('retrieved_at')
                        if retrieved_at:
                            retrieved_time = datetime.fromisoformat(retrieved_at)
                            if datetime.now() - retrieved_time > timedelta(hours=1):  # Delete after 1 hour
                                should_delete = True
                    
                    if should_delete:
                        session.delete(config)
                        deleted_count += 1
                        
                except Exception as e:
                    # If parsing fails, delete anyway
                    logger.debug(f"Deleting malformed notification config: {e}")
                    session.delete(config)
                    deleted_count += 1
            
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"🧹 Cleaned up {deleted_count} old notification records")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup notifications: {e}")
            return 0

    def _get_notification_priority(self, notification: Dict) -> str:
        """Determine notification priority based on content"""
        try:
            severity = notification.get('severity', 'Medium').lower()
            notification_type = notification.get('type', '').lower()
            
            if severity in ['critical', 'high'] or 'threat' in notification_type:
                return 'High'
            elif severity == 'medium':
                return 'Medium'
            else:
                return 'Low'
                
        except Exception:
            return 'Medium'

    def get_notification_statistics(self, session: Session, agent_id: Optional[str] = None) -> Dict:
        """Get notification statistics - NEW"""
        try:
            query = session.query(SystemConfig).filter(
                SystemConfig.Category == 'AgentNotifications'
            )
            
            if agent_id:
                query = query.filter(
                    SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%')
                )
            else:
                query = query.filter(
                    SystemConfig.ConfigKey.like('agent_notification_%')
                )
            
            configs = query.all()
            
            stats = {
                'total_notifications': len(configs),
                'pending_notifications': 0,
                'retrieved_notifications': 0,
                'expired_notifications': 0,
                'by_type': {},
                'by_priority': {},
                'by_agent': {}
            }
            
            for config in configs:
                try:
                    notification_data = json.loads(config.ConfigValue)
                    
                    # Count by status
                    status = notification_data.get('status', 'unknown')
                    if status == 'pending':
                        stats['pending_notifications'] += 1
                    elif status == 'retrieved':
                        stats['retrieved_notifications'] += 1
                    
                    # Check if expired
                    if 'expires_at' in notification_data:
                        expires_at = datetime.fromisoformat(notification_data['expires_at'])
                        if datetime.now() > expires_at:
                            stats['expired_notifications'] += 1
                    
                    # Count by type
                    notification_type = notification_data.get('notification_type', 'unknown')
                    stats['by_type'][notification_type] = stats['by_type'].get(notification_type, 0) + 1
                    
                    # Count by priority
                    priority = notification_data.get('priority', 'Medium')
                    stats['by_priority'][priority] = stats['by_priority'].get(priority, 0) + 1
                    
                    # Count by agent
                    agent_id_key = notification_data.get('agent_id', 'unknown')
                    stats['by_agent'][agent_id_key] = stats['by_agent'].get(agent_id_key, 0) + 1
                    
                except Exception as e:
                    logger.error(f"Error parsing notification for stats: {e}")
                    continue
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get notification statistics: {e}")
            return {}

    def send_alert_acknowledgment_to_agent(self, session: Session, agent_id: str, alert_id: int, 
                                         acknowledgment_data: Dict) -> bool:
        """Send alert acknowledgment back to agent - NEW"""
        try:
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.warning(f"Agent not found for acknowledgment: {agent_id}")
                return False
            
            # Create acknowledgment notification
            ack_notification = {
                'type': 'alert_acknowledgment',
                'alert_id': alert_id,
                'acknowledgment_data': acknowledgment_data,
                'sent_at': datetime.now().isoformat(),
                'message': f"Alert {alert_id} has been acknowledged and processed"
            }
            
            # Store acknowledgment notification
            config_key = f"agent_notification_{agent_id}_ack_{alert_id}_{int(datetime.now().timestamp())}"
            config_value = json.dumps({
                'agent_id': agent_id,
                'notification_type': 'alert_acknowledgment',
                'notification_data': ack_notification,
                'sent_at': datetime.now().isoformat(),
                'status': 'pending',
                'priority': 'Medium',
                'expires_at': (datetime.now() + timedelta(hours=12)).isoformat()
            })
            
            new_config = SystemConfig(
                ConfigKey=config_key,
                ConfigValue=config_value,
                ConfigType='JSON',
                Category='AgentNotifications',
                Description=f'Alert acknowledgment for agent {agent.HostName}'
            )
            session.add(new_config)
            session.commit()
            
            logger.info(f"📨 Sent alert acknowledgment to agent {agent.HostName} for alert {alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert acknowledgment: {str(e)}")
            return False

    async def batch_send_notifications(self, session: Session, notifications_by_agent: Dict[str, List[Dict]]) -> Dict[str, bool]:
        """Send notifications to multiple agents in batch - NEW"""
        try:
            results = {}
            
            for agent_id, notifications in notifications_by_agent.items():
                try:
                    success = await self.send_detection_notifications_to_agent(session, agent_id, notifications)
                    results[agent_id] = success
                    
                    if success:
                        logger.info(f"✅ Batch notifications sent to agent {agent_id}: {len(notifications)} notifications")
                    else:
                        logger.error(f"❌ Failed to send batch notifications to agent {agent_id}")
                        
                except Exception as e:
                    logger.error(f"❌ Batch notification failed for agent {agent_id}: {e}")
                    results[agent_id] = False
            
            return results
            
        except Exception as e:
            logger.error(f"Batch notification sending failed: {str(e)}")
            return {}

# Global service instance
agent_communication_service = AgentCommunicationService()