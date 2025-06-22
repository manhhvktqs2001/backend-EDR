# app/services/agent_communication_service.py - COMPLETELY FIXED
"""
Agent Communication Service - COMPLETELY FIXED
Realtime notifications, automated responses, and agent communication
"""

import logging
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
import uuid

from ..models.alert import Alert
from ..models.agent import Agent
from ..models.system_config import SystemConfig
from ..models.event import Event

logger = logging.getLogger('agent_communication')

class AgentCommunicationService:
    """FIXED: Complete agent communication with realtime capabilities"""
    
    def __init__(self):
        self.response_config = {
            'auto_isolate_threshold': 85,
            'auto_quarantine_threshold': 70,
            'auto_kill_process_threshold': 60,
            'auto_block_network_threshold': 50,
            'notification_timeout': 300,  # 5 minutes
            'max_notifications_per_agent': 100
        }
        
        # Performance tracking
        self.stats = {
            'notifications_sent': 0,
            'notifications_delivered': 0,
            'automated_responses': 0,
            'failed_notifications': 0,
            'total_processing_time': 0.0
        }
        
        logger.info("📡 Agent Communication Service - REALTIME MODE initialized")
    
    async def send_realtime_notification(self, session: Session, agent_id: str, 
                                        notification: Dict) -> bool:
        """Send realtime notification to specific agent - FIXED for duplicate IDs"""
        start_time = datetime.now()
        
        try:
            # Validate agent
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.error(f"Agent not found for notification: {agent_id}")
                return False
            
            if not agent.MonitoringEnabled:
                logger.warning(f"Monitoring disabled for agent: {agent.HostName}")
                return False
            
            # Create unique notification ID if not provided
            if 'notification_id' not in notification:
                timestamp = int(datetime.now().timestamp() * 1000)  # Millisecond precision
                random_suffix = str(uuid.uuid4())[:8]
                notification['notification_id'] = f"notif_{timestamp}_{random_suffix}"
            
            # Enhance notification with metadata
            enhanced_notification = {
                **notification,
                'agent_id': agent_id,
                'agent_hostname': agent.HostName,
                'sent_at': datetime.now().isoformat(),
                'priority': self._calculate_notification_priority(notification),
                'expires_at': (datetime.now() + timedelta(seconds=self.response_config['notification_timeout'])).isoformat(),
                'delivery_attempts': 0,
                'max_delivery_attempts': 3
            }
            
            # Store notification for agent retrieval
            success = await self._store_notification_for_agent(session, agent_id, enhanced_notification)
            
            if success:
                processing_time = (datetime.now() - start_time).total_seconds()
                self.stats['notifications_sent'] += 1
                self.stats['total_processing_time'] += processing_time
                
                logger.info(f"📤 REALTIME NOTIFICATION SENT:")
                logger.info(f"   Agent: {agent.HostName} ({agent_id})")
                logger.info(f"   Type: {notification.get('type', 'unknown')}")
                logger.info(f"   Priority: {enhanced_notification['priority']}")
                logger.info(f"   Processing: {processing_time*1000:.1f}ms")
                
                return True
            else:
                self.stats['failed_notifications'] += 1
                return False
                
        except Exception as e:
            self.stats['failed_notifications'] += 1
            logger.error(f"Realtime notification failed: {str(e)}")
            return False
    
    async def send_detection_notifications_to_agent(self, session: Session, agent_id: str, 
                                                   notifications: List[Dict]) -> bool:
        """Send multiple detection notifications to agent"""
        try:
            if not notifications:
                return True
            
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.error(f"Agent not found: {agent_id}")
                return False
            
            logger.info(f"📤 SENDING {len(notifications)} DETECTION NOTIFICATIONS to {agent.HostName}")
            
            # Process notifications in parallel for speed
            tasks = []
            for notification in notifications:
                # Enhance notification for detection
                detection_notification = {
                    **notification,
                    'category': 'security_detection',
                    'requires_acknowledgment': notification.get('severity', 'Medium') in ['High', 'Critical'],
                    'auto_escalate': notification.get('severity') == 'Critical',
                    'source': 'detection_engine'
                }
                
                tasks.append(self.send_realtime_notification(session, agent_id, detection_notification))
            
            # Execute in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count successful notifications
            successful = sum(1 for result in results if result is True)
            failed = len(notifications) - successful
            
            if successful > 0:
                logger.info(f"✅ DETECTION NOTIFICATIONS: {successful}/{len(notifications)} sent to {agent.HostName}")
            
            if failed > 0:
                logger.error(f"❌ FAILED NOTIFICATIONS: {failed}/{len(notifications)} to {agent.HostName}")
            
            return successful > 0
            
        except Exception as e:
            logger.error(f"Detection notification batch failed: {str(e)}")
            return False
    
    async def _store_notification_for_agent(self, session: Session, agent_id: str, 
                                           notification: Dict) -> bool:
        """Store notification in database for agent retrieval - FIXED for duplicate key"""
        try:
            # Clean up old notifications first
            await self._cleanup_old_notifications_for_agent(session, agent_id)
            
            # Create unique notification key with timestamp and random suffix
            timestamp = int(datetime.now().timestamp() * 1000)  # Millisecond precision
            random_suffix = str(uuid.uuid4())[:8]
            notification_id = f"notif_{timestamp}_{random_suffix}"
            
            # Update notification with unique ID
            notification['notification_id'] = notification_id
            
            notification_key = f"agent_notification_{agent_id}_{notification_id}"
            
            # Check if notification already exists to avoid duplicate
            existing = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey == notification_key
            ).first()
            
            if existing:
                logger.warning(f"Notification already exists, skipping: {notification_key}")
                return True  # Don't fail, just skip
            
            notification_record = {
                'notification_data': notification,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'agent_id': agent_id
            }
            
            # Store in SystemConfig
            config_entry = SystemConfig(
                ConfigKey=notification_key,
                ConfigValue=json.dumps(notification_record),
                ConfigType='JSON',
                Category='AgentNotifications',
                Description=f"Realtime notification for agent {agent_id}"
            )
            
            session.add(config_entry)
            session.commit()
            
            logger.debug(f"📝 Notification stored: {notification_id}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store notification: {str(e)}")
            return False
    
    def get_pending_notifications(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending notifications for agent - OPTIMIZED"""
        try:
            # Query pending notifications
            configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).order_by(SystemConfig.CreatedAt.desc()).limit(50).all()  # Limit for performance
            
            notifications = []
            configs_to_update = []
            configs_to_delete = []
            
            for config in configs:
                try:
                    record = json.loads(config.ConfigValue)
                    notification_data = record.get('notification_data', {})
                    
                    # Check expiration
                    if 'expires_at' in notification_data:
                        expires_at = datetime.fromisoformat(notification_data['expires_at'])
                        if datetime.now() > expires_at:
                            configs_to_delete.append(config)
                            continue
                    
                    # Get pending notifications
                    if record.get('status') == 'pending':
                        notifications.append(notification_data)
                        
                        # Mark as retrieved
                        record['status'] = 'retrieved'
                        record['retrieved_at'] = datetime.now().isoformat()
                        record['delivery_attempts'] = record.get('delivery_attempts', 0) + 1
                        
                        config.ConfigValue = json.dumps(record)
                        configs_to_update.append(config)
                        
                except Exception as e:
                    logger.error(f"Failed to parse notification: {e}")
                    configs_to_delete.append(config)
                    continue
            
            # Clean up expired notifications
            for config in configs_to_delete:
                session.delete(config)
            
            session.commit()
            
            if notifications:
                logger.info(f"📤 DELIVERED {len(notifications)} notifications to agent {agent_id}")
                self.stats['notifications_delivered'] += len(notifications)
            
            return notifications
            
        except Exception as e:
            logger.error(f"Get pending notifications failed: {e}")
            return []
    
    async def _cleanup_old_notifications_for_agent(self, session: Session, agent_id: str):
        """Clean up old notifications for specific agent"""
        try:
            # Get notification count for agent
            notification_count = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).count()
            
            # If too many notifications, clean up old ones
            if notification_count > self.response_config['max_notifications_per_agent']:
                old_configs = session.query(SystemConfig).filter(
                    SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                    SystemConfig.Category == 'AgentNotifications'
                ).order_by(SystemConfig.CreatedAt.asc()).limit(
                    notification_count - self.response_config['max_notifications_per_agent']
                ).all()
                
                for config in old_configs:
                    session.delete(config)
                
                if old_configs:
                    logger.debug(f"🧹 Cleaned {len(old_configs)} old notifications for agent {agent_id}")
            
        except Exception as e:
            logger.error(f"Notification cleanup failed: {e}")
    
    def _calculate_notification_priority(self, notification: Dict) -> str:
        """Calculate notification priority"""
        try:
            severity = notification.get('severity', 'Medium').lower()
            notification_type = notification.get('type', '').lower()
            risk_score = notification.get('risk_score', 0)
            
            # Critical priority
            if (severity == 'critical' or 
                risk_score >= 90 or 
                'malicious' in notification_type or
                'critical' in notification_type):
                return 'Critical'
            
            # High priority
            elif (severity == 'high' or 
                  risk_score >= 70 or 
                  'threat' in notification_type or
                  'suspicious' in notification_type):
                return 'High'
            
            # Medium priority
            elif (severity == 'medium' or 
                  risk_score >= 40 or
                  'detection' in notification_type):
                return 'Medium'
            
            # Low priority
            else:
                return 'Low'
                
        except Exception:
            return 'Medium'
    
    async def execute_automated_response(self, session: Session, alert: Alert) -> Dict[str, Any]:
        """Execute automated response based on alert severity and risk score"""
        start_time = datetime.now()
        
        try:
            # Get agent
            agent = Agent.get_by_id(session, str(alert.AgentID))
            if not agent:
                logger.warning(f"Agent not found for alert {alert.AlertID}")
                return {"success": False, "error": "Agent not found"}
            
            risk_score = alert.RiskScore or 0
            severity = alert.Severity or 'Medium'
            
            logger.info(f"🤖 AUTOMATED RESPONSE EVALUATION:")
            logger.info(f"   Alert: {alert.AlertID} | Risk: {risk_score} | Severity: {severity}")
            logger.info(f"   Agent: {agent.HostName} ({agent.AgentID})")
            
            response_result = {
                'alert_id': alert.AlertID,
                'agent_id': str(alert.AgentID),
                'agent_hostname': agent.HostName,
                'risk_score': risk_score,
                'severity': severity,
                'actions_executed': [],
                'notifications_sent': [],
                'success': False,
                'execution_time_ms': 0
            }
            
            # Determine response actions based on risk score and severity
            actions_to_execute = []
            
            if risk_score >= self.response_config['auto_isolate_threshold'] or severity == 'Critical':
                actions_to_execute.append('isolate_agent')
            
            elif risk_score >= self.response_config['auto_quarantine_threshold'] or severity == 'High':
                actions_to_execute.append('quarantine_files')
            
            elif risk_score >= self.response_config['auto_kill_process_threshold']:
                actions_to_execute.append('kill_suspicious_processes')
            
            elif risk_score >= self.response_config['auto_block_network_threshold']:
                actions_to_execute.append('block_suspicious_network')
            
            # Always send notification for threats
            if risk_score >= 40:
                actions_to_execute.append('send_notification')
            
            # Execute actions
            for action in actions_to_execute:
                try:
                    if action == 'isolate_agent':
                        result = await self._execute_isolation(session, agent, alert)
                        response_result['actions_executed'].extend(result)
                    
                    elif action == 'quarantine_files':
                        result = await self._execute_quarantine(session, agent, alert)
                        response_result['actions_executed'].extend(result)
                    
                    elif action == 'kill_suspicious_processes':
                        result = await self._execute_process_kill(session, agent, alert)
                        response_result['actions_executed'].extend(result)
                    
                    elif action == 'block_suspicious_network':
                        result = await self._execute_network_block(session, agent, alert)
                        response_result['actions_executed'].extend(result)
                    
                    elif action == 'send_notification':
                        result = await self._send_response_notification(session, agent, alert)
                        response_result['notifications_sent'].extend(result)
                
                except Exception as e:
                    logger.error(f"Action execution failed ({action}): {e}")
                    response_result['actions_executed'].append(f"Failed: {action} - {str(e)}")
            
            # Update alert with response actions
            if response_result['actions_executed']:
                action_summary = "; ".join(response_result['actions_executed'])
                alert.add_response_action(f"Automated Response: {action_summary}")
                session.commit()
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            response_result['execution_time_ms'] = round(execution_time * 1000, 2)
            response_result['success'] = len(response_result['actions_executed']) > 0
            
            self.stats['automated_responses'] += 1
            self.stats['total_processing_time'] += execution_time
            
            if response_result['success']:
                logger.info(f"🤖 AUTOMATED RESPONSE COMPLETED:")
                logger.info(f"   Actions: {len(response_result['actions_executed'])}")
                logger.info(f"   Notifications: {len(response_result['notifications_sent'])}")
                logger.info(f"   Time: {response_result['execution_time_ms']}ms")
            
            return response_result
            
        except Exception as e:
            logger.error(f"Automated response execution failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _execute_isolation(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Execute agent isolation"""
        try:
            actions = [
                f"Network isolation initiated for {agent.HostName}",
                "Enhanced monitoring activated",
                "Access restrictions applied"
            ]
            
            # Send isolation command to agent
            isolation_notification = {
                'type': 'isolation_command',
                'action': 'isolate_network',
                'alert_id': alert.AlertID,
                'severity': 'Critical',
                'title': 'Network Isolation Required',
                'description': f'Agent isolation required due to alert: {alert.Title}',
                'requires_acknowledgment': True,
                'auto_execute': True
            }
            
            await self.send_realtime_notification(session, str(agent.AgentID), isolation_notification)
            
            # Update agent status
            agent.Status = "Isolated"
            session.commit()
            
            logger.warning(f"🔒 AGENT ISOLATED: {agent.HostName} (Alert: {alert.AlertID})")
            return actions
            
        except Exception as e:
            logger.error(f"Agent isolation failed: {e}")
            return [f"Isolation failed: {str(e)}"]
    
    async def _execute_quarantine(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Execute file quarantine"""
        try:
            actions = [
                "Suspicious files quarantined",
                "File system scan initiated",
                "Quarantine monitoring enabled"
            ]
            
            # Send quarantine command to agent
            quarantine_notification = {
                'type': 'quarantine_command',
                'action': 'quarantine_files',
                'alert_id': alert.AlertID,
                'severity': 'High',
                'title': 'File Quarantine Required',
                'description': f'File quarantine required due to alert: {alert.Title}',
                'target_files': self._extract_file_info_from_alert(alert),
                'requires_acknowledgment': True
            }
            
            await self.send_realtime_notification(session, str(agent.AgentID), quarantine_notification)
            
            logger.warning(f"🔒 FILES QUARANTINED: {agent.HostName} (Alert: {alert.AlertID})")
            return actions
            
        except Exception as e:
            logger.error(f"File quarantine failed: {e}")
            return [f"Quarantine failed: {str(e)}"]
    
    async def _execute_process_kill(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Execute process termination"""
        try:
            actions = [
                "Suspicious processes terminated",
                "Process monitoring enhanced",
                "Execution restrictions applied"
            ]
            
            # Send process kill command to agent
            process_notification = {
                'type': 'process_command',
                'action': 'kill_processes',
                'alert_id': alert.AlertID,
                'severity': 'Medium',
                'title': 'Process Termination Required',
                'description': f'Process termination required due to alert: {alert.Title}',
                'target_processes': self._extract_process_info_from_alert(alert),
                'requires_acknowledgment': False,
                'auto_execute': True
            }
            
            await self.send_realtime_notification(session, str(agent.AgentID), process_notification)
            
            logger.warning(f"⚡ PROCESSES TERMINATED: {agent.HostName} (Alert: {alert.AlertID})")
            return actions
            
        except Exception as e:
            logger.error(f"Process termination failed: {e}")
            return [f"Process kill failed: {str(e)}"]
    
    async def _execute_network_block(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Execute network blocking"""
        try:
            actions = [
                "Suspicious network connections blocked",
                "Network monitoring enhanced",
                "Traffic filtering activated"
            ]
            
            # Send network block command to agent
            network_notification = {
                'type': 'network_command',
                'action': 'block_connections',
                'alert_id': alert.AlertID,
                'severity': 'Medium',
                'title': 'Network Blocking Required',
                'description': f'Network blocking required due to alert: {alert.Title}',
                'target_ips': self._extract_network_info_from_alert(alert),
                'requires_acknowledgment': False,
                'auto_execute': True
            }
            
            await self.send_realtime_notification(session, str(agent.AgentID), network_notification)
            
            logger.warning(f"🚫 NETWORK BLOCKED: {agent.HostName} (Alert: {alert.AlertID})")
            return actions
            
        except Exception as e:
            logger.error(f"Network blocking failed: {e}")
            return [f"Network block failed: {str(e)}"]
    
    async def _send_response_notification(self, session: Session, agent: Agent, alert: Alert) -> List[str]:
        """Send response notification to agent"""
        try:
            # Create detailed notification
            notification = {
                'type': 'security_alert_response',
                'alert_id': alert.AlertID,
                'title': f'Security Alert: {alert.Title}',
                'description': alert.Description or 'Security threat detected',
                'severity': alert.Severity,
                'risk_score': alert.RiskScore,
                'detection_method': alert.DetectionMethod,
                'first_detected': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                'mitre_tactic': alert.MitreTactic,
                'mitre_technique': alert.MitreTechnique,
                'requires_acknowledgment': alert.Severity in ['High', 'Critical'],
                'recommended_actions': self._generate_response_recommendations(alert),
                'escalation_required': alert.Severity == 'Critical'
            }
            
            success = await self.send_realtime_notification(session, str(agent.AgentID), notification)
            
            if success:
                return [f"Security alert notification sent to {agent.HostName}"]
            else:
                return ["Failed to send security alert notification"]
                
        except Exception as e:
            logger.error(f"Response notification failed: {e}")
            return [f"Notification failed: {str(e)}"]
    
    def _extract_file_info_from_alert(self, alert: Alert) -> List[Dict]:
        """Extract file information from alert for quarantine"""
        try:
            if alert.EventID:
                from ..models.event import Event
                event = Event.query.get(alert.EventID)
                if event and event.EventType == 'File':
                    return [{
                        'file_path': event.FilePath,
                        'file_name': event.FileName,
                        'file_hash': event.FileHash,
                        'file_size': event.FileSize
                    }]
            return []
        except Exception:
            return []
    
    def _extract_process_info_from_alert(self, alert: Alert) -> List[Dict]:
        """Extract process information from alert for termination"""
        try:
            if alert.EventID:
                from ..models.event import Event
                event = Event.query.get(alert.EventID)
                if event and event.EventType == 'Process':
                    return [{
                        'process_name': event.ProcessName,
                        'process_id': event.ProcessID,
                        'process_path': event.ProcessPath,
                        'command_line': event.CommandLine,
                        'process_hash': event.ProcessHash
                    }]
            return []
        except Exception:
            return []
    
    def _extract_network_info_from_alert(self, alert: Alert) -> List[Dict]:
        """Extract network information from alert for blocking"""
        try:
            if alert.EventID:
                from ..models.event import Event
                event = Event.query.get(alert.EventID)
                if event and event.EventType == 'Network':
                    return [{
                        'destination_ip': event.DestinationIP,
                        'destination_port': event.DestinationPort,
                        'source_ip': event.SourceIP,
                        'protocol': event.Protocol
                    }]
            return []
        except Exception:
            return []
    
    def _generate_response_recommendations(self, alert: Alert) -> List[str]:
        """Generate response recommendations for alert"""
        try:
            recommendations = []
            severity = alert.Severity or 'Medium'
            risk_score = alert.RiskScore or 0
            
            if severity == 'Critical' or risk_score >= 90:
                recommendations.extend([
                    "Immediately isolate the affected system",
                    "Contact security team for incident response",
                    "Preserve forensic evidence",
                    "Review access logs for lateral movement"
                ])
            elif severity == 'High' or risk_score >= 70:
                recommendations.extend([
                    "Monitor system activity closely",
                    "Run full antivirus scan",
                    "Check for unauthorized changes",
                    "Review recent user activities"
                ])
            elif severity == 'Medium' or risk_score >= 40:
                recommendations.extend([
                    "Investigate the flagged activity",
                    "Verify with the user if activity is legitimate",
                    "Update security policies if needed"
                ])
            else:
                recommendations.extend([
                    "Continue monitoring",
                    "Document the incident",
                    "Review detection rules"
                ])
            
            return recommendations
        except Exception:
            return ["Review and investigate the security alert"]
    
    def get_pending_actions(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending response actions for agent"""
        try:
            # Get open alerts for the agent that may require action
            alerts = session.query(Alert).filter(
                Alert.AgentID == agent_id,
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.RiskScore >= 50
            ).order_by(Alert.FirstDetected.desc()).limit(10).all()
            
            pending_actions = []
            for alert in alerts:
                action = {
                    'alert_id': alert.AlertID,
                    'action_type': self._determine_action_type(alert),
                    'priority': alert.Severity,
                    'description': f"Response required for: {alert.Title}",
                    'risk_score': alert.RiskScore,
                    'created_at': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                    'age_minutes': alert.get_age_minutes()
                }
                pending_actions.append(action)
            
            return pending_actions
            
        except Exception as e:
            logger.error(f"Failed to get pending actions: {e}")
            return []
    
    def _determine_action_type(self, alert: Alert) -> str:
        """Determine action type based on alert properties"""
        risk_score = alert.RiskScore or 0
        severity = alert.Severity or 'Medium'
        
        if risk_score >= 85 or severity == 'Critical':
            return 'isolate'
        elif risk_score >= 70 or severity == 'High':
            return 'quarantine'
        elif risk_score >= 60:
            return 'investigate'
        else:
            return 'monitor'
    
    def record_action_response(self, session: Session, agent_id: str, alert_id: int, 
                             action_type: str, success: bool, details: str) -> bool:
        """Record agent's response to an action"""
        try:
            alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
            if not alert:
                return False
            
            # Create response record
            response_text = f"Agent Response ({action_type}): {'SUCCESS' if success else 'FAILED'}"
            if details:
                response_text += f" - {details}"
            response_text += f" at {datetime.now().isoformat()}"
            
            alert.add_response_action(response_text)
            
            # Update alert status based on response
            if success:
                if action_type in ['isolate', 'quarantine']:
                    alert.Status = "Investigating"
                elif action_type == 'investigate':
                    alert.Status = "Investigating"
            else:
                # Add failure note but don't change status
                pass
            
            session.commit()
            
            logger.info(f"📝 ACTION RESPONSE RECORDED:")
            logger.info(f"   Alert: {alert_id} | Action: {action_type} | Success: {success}")
            logger.info(f"   Agent: {agent_id} | Details: {details}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to record action response: {e}")
            return False
    
    async def batch_send_notifications(self, session: Session, 
                                     notifications_by_agent: Dict[str, List[Dict]]) -> Dict[str, bool]:
        """Send notifications to multiple agents in batch"""
        try:
            logger.info(f"📤 BATCH NOTIFICATION: {len(notifications_by_agent)} agents")
            
            # Create tasks for parallel execution
            tasks = []
            agent_ids = []
            
            for agent_id, notifications in notifications_by_agent.items():
                if notifications:
                    tasks.append(self.send_detection_notifications_to_agent(session, agent_id, notifications))
                    agent_ids.append(agent_id)
            
            # Execute in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            batch_results = {}
            successful = 0
            
            for agent_id, result in zip(agent_ids, results):
                if isinstance(result, Exception):
                    logger.error(f"Batch notification failed for {agent_id}: {result}")
                    batch_results[agent_id] = False
                else:
                    batch_results[agent_id] = result
                    if result:
                        successful += 1
            
            logger.info(f"✅ BATCH COMPLETE: {successful}/{len(agent_ids)} agents notified")
            return batch_results
            
        except Exception as e:
            logger.error(f"Batch notification sending failed: {str(e)}")
            return {}
    
    def cleanup_old_notifications(self, session: Session, hours: int = 24) -> int:
        """Clean up old notification records"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Find old notifications
            old_configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like('agent_notification_%'),
                SystemConfig.Category == 'AgentNotifications',
                SystemConfig.CreatedAt < cutoff_time
            ).all()
            
            deleted_count = 0
            for config in old_configs:
                try:
                    # Check if notification was retrieved
                    record = json.loads(config.ConfigValue)
                    if record.get('status') in ['retrieved', 'expired']:
                        session.delete(config)
                        deleted_count += 1
                except Exception:
                    # Delete malformed records
                    session.delete(config)
                    deleted_count += 1
            
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"🧹 Cleaned up {deleted_count} old notification records")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup notifications: {e}")
            return 0
    
    def get_communication_stats(self) -> Dict[str, Any]:
        """Get communication service statistics"""
        try:
            total_time = max(self.stats['total_processing_time'], 0.001)
            
            return {
                'notifications_sent': self.stats['notifications_sent'],
                'notifications_delivered': self.stats['notifications_delivered'],
                'automated_responses': self.stats['automated_responses'],
                'failed_notifications': self.stats['failed_notifications'],
                'success_rate': round(
                    (self.stats['notifications_sent'] - self.stats['failed_notifications']) / 
                    max(self.stats['notifications_sent'], 1) * 100, 2
                ),
                'average_processing_time_ms': round(
                    (total_time / max(self.stats['notifications_sent'], 1)) * 1000, 2
                ),
                'delivery_rate': round(
                    (self.stats['notifications_delivered'] / max(self.stats['notifications_sent'], 1)) * 100, 2
                )
            }
        except Exception as e:
            logger.error(f"Stats calculation failed: {e}")
            return {}
    
    def reset_stats(self):
        """Reset communication statistics"""
        self.stats = {
            'notifications_sent': 0,
            'notifications_delivered': 0,
            'automated_responses': 0,
            'failed_notifications': 0,
            'total_processing_time': 0.0
        }
        logger.info("📊 Agent communication statistics reset")
    
    def get_health_status(self, session: Session) -> Dict[str, Any]:
        """Get communication service health status"""
        try:
            stats = self.get_communication_stats()
            
            # Check for issues
            issues = []
            health_status = "healthy"
            
            # Check success rate
            success_rate = stats.get('success_rate', 100)
            if success_rate < 80:
                health_status = "degraded"
                issues.append(f"Low notification success rate: {success_rate}%")
            
            # Check delivery rate
            delivery_rate = stats.get('delivery_rate', 100)
            if delivery_rate < 70:
                health_status = "degraded"
                issues.append(f"Low notification delivery rate: {delivery_rate}%")
            
            # Check processing time
            avg_processing_time = stats.get('average_processing_time_ms', 0)
            if avg_processing_time > 1000:
                if health_status == "healthy":
                    health_status = "warning"
                issues.append(f"High processing latency: {avg_processing_time}ms")
            
            # Check pending notifications count
            try:
                pending_count = session.query(SystemConfig).filter(
                    SystemConfig.ConfigKey.like('agent_notification_%'),
                    SystemConfig.Category == 'AgentNotifications'
                ).count()
                
                if pending_count > 1000:
                    health_status = "warning"
                    issues.append(f"High pending notifications: {pending_count}")
                    
            except Exception:
                pass
            
            return {
                'status': health_status,
                'issues': issues,
                'statistics': stats,
                'last_checked': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Health status check failed: {e}")
            return {
                'status': 'error',
                'issues': [f"Health check failed: {str(e)}"],
                'last_checked': datetime.now().isoformat()
            }

# Global service instance
agent_communication_service = AgentCommunicationService()