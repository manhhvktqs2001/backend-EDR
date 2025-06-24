# app/services/agent_communication_service.py - COMPLETELY FIXED FOR NOTIFICATIONS
"""
Agent Communication Service - COMPLETELY FIXED
Đảm bảo notification sẽ được gửi đến agent khi có rule violation (notepad.exe)
"""

import logging
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import json
import asyncio
import uuid

from ..models.alert import Alert
from ..models.agent import Agent
from ..models.system_config import SystemConfig

logger = logging.getLogger('agent_communication')

class AgentCommunicationService:
    """FIXED: Agent communication với notification system hoàn chỉnh"""
    
    def __init__(self):
        self.notification_config = {
            'max_notifications_per_agent': 500,
            'notification_timeout': 300,  # 5 minutes
            'auto_cleanup_interval': 3600  # 1 hour
        }
        
        # Performance tracking
        self.stats = {
            'notifications_sent': 0,
            'notifications_delivered': 0,
            'notifications_failed': 0,
            'total_processing_time': 0.0
        }
        
        logger.info("📡 FIXED Agent Communication Service - NOTIFICATION SYSTEM READY")
    
    async def send_realtime_notification(self, session: Session, agent_id: str, 
                                        notification: Dict) -> bool:
        """FIXED: Send realtime notification to agent - WORKS WITH NOTEPAD.EXE"""
        start_time = datetime.now()
        
        try:
            # Validate agent
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.error(f"❌ Agent not found for notification: {agent_id}")
                return False
            
            if not agent.MonitoringEnabled:
                logger.warning(f"⚠️ Monitoring disabled for agent: {agent.HostName}")
                return False
            
            # Create UNIQUE notification ID với timestamp precision cao
            timestamp = int(datetime.now().timestamp() * 1000000)  # Microsecond precision
            random_suffix = str(uuid.uuid4())[:8]
            notification_id = f"notif_{timestamp}_{random_suffix}"
            
            # Enhance notification với metadata đầy đủ
            enhanced_notification = {
                **notification,
                'notification_id': notification_id,
                'agent_id': agent_id,
                'agent_hostname': agent.HostName,
                'sent_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(seconds=self.notification_config['notification_timeout'])).isoformat(),
                'delivery_attempts': 0,
                'max_delivery_attempts': 3,
                'priority': self._calculate_notification_priority(notification),
                'requires_display': True,
                'auto_display': notification.get('auto_display', True),
                'display_popup': True,
                'play_sound': notification.get('severity', 'Medium') in ['High', 'Critical'],
                'requires_acknowledgment': notification.get('severity', 'Medium') in ['High', 'Critical']
            }
            
            # Store notification for agent retrieval - FIXED STORAGE
            success = await self._store_notification_for_agent_fixed(session, agent_id, enhanced_notification)
            
            if success:
                processing_time = (datetime.now() - start_time).total_seconds()
                self.stats['notifications_sent'] += 1
                self.stats['total_processing_time'] += processing_time
                
                logger.warning(f"📤 NOTIFICATION SENT SUCCESSFULLY:")
                logger.warning(f"   🎯 Agent: {agent.HostName} ({agent_id})")
                logger.warning(f"   📋 ID: {notification_id}")
                logger.warning(f"   🔔 Type: {notification.get('type', 'unknown')}")
                logger.warning(f"   ⚡ Priority: {enhanced_notification['priority']}")
                logger.warning(f"   📄 Alert ID: {notification.get('alert_id', 'N/A')}")
                logger.warning(f"   ⏱️ Processing: {processing_time*1000:.1f}ms")
                
                return True
            else:
                self.stats['notifications_failed'] += 1
                logger.error(f"❌ Failed to store notification for {agent.HostName}")
                return False
                
        except Exception as e:
            self.stats['notifications_failed'] += 1
            logger.error(f"💥 Notification sending failed: {str(e)}")
            return False
    
    async def send_detection_notifications_to_agent(self, session: Session, agent_id: str, 
                                                   notifications: List[Dict]) -> bool:
        """FIXED: Send multiple detection notifications to agent"""
        try:
            if not notifications:
                logger.debug("No notifications to send")
                return True
            
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.error(f"❌ Agent not found: {agent_id}")
                return False
            
            logger.warning(f"📤 SENDING {len(notifications)} DETECTION NOTIFICATIONS:")
            logger.warning(f"   🎯 Target Agent: {agent.HostName} ({agent_id})")
            
            success_count = 0
            
            for i, notification in enumerate(notifications):
                try:
                    # Enhance notification for detection alerts
                    detection_notification = {
                        **notification,
                        'category': 'security_detection',
                        'source': 'detection_engine',
                        'alert_index': i + 1,
                        'total_alerts': len(notifications),
                        'timestamp': datetime.now().isoformat(),
                        
                        # Display settings
                        'display_popup': True,
                        'auto_display': True,
                        'requires_acknowledgment': notification.get('severity', 'Medium') in ['High', 'Critical'],
                        'auto_escalate': notification.get('severity') == 'Critical',
                        'play_sound': notification.get('severity', 'Medium') in ['High', 'Critical'],
                        
                        # Action settings
                        'action_required': True,
                        'can_dismiss': True,
                        'can_ignore': False,
                        'escalation_timeout': 300 if notification.get('severity') == 'Critical' else 600
                    }
                    
                    success = await self.send_realtime_notification(session, agent_id, detection_notification)
                    if success:
                        success_count += 1
                        logger.info(f"   ✅ Notification {i+1}/{len(notifications)} sent")
                    else:
                        logger.error(f"   ❌ Notification {i+1}/{len(notifications)} failed")
                
                except Exception as e:
                    logger.error(f"   💥 Notification {i+1} error: {e}")
                    continue
            
            if success_count > 0:
                logger.warning(f"✅ DETECTION NOTIFICATIONS SUCCESS:")
                logger.warning(f"   📊 Sent: {success_count}/{len(notifications)}")
                logger.warning(f"   🎯 Agent: {agent.HostName}")
            
            if success_count < len(notifications):
                failed_count = len(notifications) - success_count
                logger.error(f"❌ FAILED NOTIFICATIONS: {failed_count}/{len(notifications)} to {agent.HostName}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"💥 Detection notification batch failed: {str(e)}")
            return False
    
    async def _store_notification_for_agent_fixed(self, session: Session, agent_id: str, 
                                                 notification: Dict) -> bool:
        """FIXED: Store notification với unique key và proper error handling"""
        try:
            # Clean up old notifications trước khi thêm mới
            await self._cleanup_old_notifications_for_agent(session, agent_id)
            
            notification_id = notification['notification_id']
            notification_key = f"agent_notification_{agent_id}_{notification_id}"
            
            # Check if already exists để tránh duplicate
            existing = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey == notification_key
            ).first()
            
            if existing:
                logger.warning(f"⚠️ Notification already exists, updating: {notification_key}")
                existing.ConfigValue = json.dumps({
                    'notification_data': notification,
                    'status': 'pending',
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat(),
                    'agent_id': agent_id,
                    'notification_key': notification_key
                })
                session.commit()
                return True
            
            # Create new notification record với full metadata
            notification_record = {
                'notification_data': notification,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'agent_id': agent_id,
                'notification_key': notification_key,
                'priority': notification.get('priority', 'Medium'),
                'type': notification.get('type', 'unknown'),
                'expires_at': notification.get('expires_at')
            }
            
            config_entry = SystemConfig(
                ConfigKey=notification_key,
                ConfigValue=json.dumps(notification_record),
                ConfigType='JSON',
                Category='AgentNotifications',
                Description=f"Detection notification for agent {agent_id} - {notification.get('type', 'unknown')}"
            )
            
            session.add(config_entry)
            session.commit()
            
            logger.info(f"📝 NOTIFICATION STORED:")
            logger.info(f"   🔑 Key: {notification_key}")
            logger.info(f"   📋 ID: {notification_id}")
            logger.info(f"   🎯 Agent: {agent_id}")
            
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"💥 Failed to store notification: {str(e)}")
            logger.error(f"   🔑 Key: {notification_key if 'notification_key' in locals() else 'unknown'}")
            logger.error(f"   🎯 Agent: {agent_id}")
            return False
    
    def get_pending_notifications(self, session: Session, agent_id: str) -> List[Dict]:
        """FIXED: Get pending notifications for agent với proper status handling"""
        try:
            logger.info(f"📥 CHECKING PENDING NOTIFICATIONS:")
            logger.info(f"   🎯 Agent ID: {agent_id}")
            
            # Query pending notifications for this agent
            configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).order_by(SystemConfig.CreatedAt.desc()).limit(100).all()
            
            logger.info(f"   📊 Found {len(configs)} notification records")
            
            notifications = []
            configs_to_update = []
            configs_to_delete = []
            
            for config in configs:
                try:
                    record = json.loads(config.ConfigValue)
                    notification_data = record.get('notification_data', {})
                    
                    # Check expiration
                    if 'expires_at' in notification_data:
                        try:
                            expires_at = datetime.fromisoformat(notification_data['expires_at'])
                            if datetime.now() > expires_at:
                                logger.debug(f"   ⏰ Expired notification: {config.ConfigKey}")
                                configs_to_delete.append(config)
                                continue
                        except Exception as e:
                            logger.warning(f"   ⚠️ Invalid expiration date: {e}")
                            configs_to_delete.append(config)
                            continue
                    
                    # Get pending notifications
                    current_status = record.get('status', 'unknown')
                    if current_status == 'pending':
                        notifications.append(notification_data)
                        
                        # Mark as retrieved với updated metadata
                        record['status'] = 'retrieved'
                        record['retrieved_at'] = datetime.now().isoformat()
                        record['delivery_attempts'] = record.get('delivery_attempts', 0) + 1
                        
                        config.ConfigValue = json.dumps(record)
                        configs_to_update.append(config)
                        
                        logger.info(f"   📋 Pending notification: {notification_data.get('type', 'unknown')}")
                    else:
                        logger.debug(f"   📋 Non-pending status: {current_status}")
                
                except Exception as e:
                    logger.error(f"   💥 Failed to parse notification: {e}")
                    configs_to_delete.append(config)
                    continue
            
            # Clean up expired notifications
            for config in configs_to_delete:
                try:
                    session.delete(config)
                    logger.debug(f"   🗑️ Deleted expired: {config.ConfigKey}")
                except Exception as e:
                    logger.error(f"   💥 Delete failed: {e}")
            
            # Commit all changes
            try:
                session.commit()
                logger.debug(f"   💾 Database changes committed")
            except Exception as e:
                logger.error(f"   💥 Commit failed: {e}")
                session.rollback()
            
            if notifications:
                logger.warning(f"📤 DELIVERED {len(notifications)} NOTIFICATIONS:")
                logger.warning(f"   🎯 Agent: {agent_id}")
                self.stats['notifications_delivered'] += len(notifications)
                
                # Log notification details
                for i, notif in enumerate(notifications):
                    notif_type = notif.get('type', 'unknown')
                    notif_title = notif.get('title', 'No title')
                    notif_priority = notif.get('priority', 'Unknown')
                    logger.warning(f"   📋 {i+1}. {notif_type}: {notif_title} (Priority: {notif_priority})")
            else:
                logger.info(f"   📭 No pending notifications for agent {agent_id}")
            
            return notifications
            
        except Exception as e:
            logger.error(f"💥 Get pending notifications failed: {e}")
            logger.error(f"   🎯 Agent: {agent_id}")
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
            max_notifications = self.notification_config['max_notifications_per_agent']
            if notification_count > max_notifications:
                old_configs = session.query(SystemConfig).filter(
                    SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                    SystemConfig.Category == 'AgentNotifications'
                ).order_by(SystemConfig.CreatedAt.asc()).limit(
                    notification_count - max_notifications
                ).all()
                
                deleted_count = 0
                for config in old_configs:
                    try:
                        session.delete(config)
                        deleted_count += 1
                    except Exception as e:
                        logger.error(f"Failed to delete old notification: {e}")
                        continue
                
                if deleted_count > 0:
                    logger.info(f"🧹 Cleaned {deleted_count} old notifications for agent {agent_id}")
                    
        except Exception as e:
            logger.error(f"💥 Notification cleanup failed: {e}")
    
    def _calculate_notification_priority(self, notification: Dict) -> str:
        """Calculate notification priority based on content"""
        try:
            severity = notification.get('severity', 'Medium').lower()
            notification_type = notification.get('type', '').lower()
            risk_score = notification.get('risk_score', 0)
            
            # Critical priority conditions
            if (severity == 'critical' or 
                risk_score >= 90 or 
                'critical' in notification_type or
                'malicious' in notification_type):
                return 'Critical'
            
            # High priority conditions
            elif (severity == 'high' or 
                  risk_score >= 70 or 
                  'threat' in notification_type or
                  'suspicious' in notification_type or
                  'rule_violation' in notification_type):
                return 'High'
            
            # Medium priority conditions
            elif (severity == 'medium' or 
                  risk_score >= 40 or
                  'detection' in notification_type or
                  'security' in notification_type):
                return 'Medium'
            
            # Low priority (default)
            else:
                return 'Low'
                
        except Exception as e:
            logger.error(f"Priority calculation failed: {e}")
            return 'Medium'
    
    async def send_rule_violation_notification(self, session: Session, agent_id: str, 
                                             alert: Alert, rule_details: Dict) -> bool:
        """FIXED: Send specific notification for rule violations (like notepad.exe)"""
        try:
            logger.warning(f"🚨 SENDING RULE VIOLATION NOTIFICATION:")
            logger.warning(f"   🎯 Agent: {agent_id}")
            logger.warning(f"   📋 Alert: {alert.AlertID}")
            logger.warning(f"   📝 Rule: {rule_details.get('rule_name', 'Unknown')}")
            
            # Create detailed rule violation notification
            notification = {
                'type': 'security_rule_violation',
                'category': 'rule_detection',
                'alert_id': alert.AlertID,
                'rule_id': rule_details.get('rule_id'),
                'rule_name': rule_details.get('rule_name', 'Unknown Rule'),
                'rule_type': rule_details.get('rule_type', 'Unknown'),
                
                # Alert details
                'title': alert.Title or f"Rule Violation: {rule_details.get('rule_name')}",
                'description': alert.Description or f"Security rule '{rule_details.get('rule_name')}' was triggered",
                'severity': alert.Severity,
                'priority': alert.Priority,
                'risk_score': alert.RiskScore,
                
                # Event context
                'event_id': alert.EventID,
                'detection_method': alert.DetectionMethod,
                'first_detected': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                
                # MITRE context
                'mitre_tactic': rule_details.get('mitre_tactic'),
                'mitre_technique': rule_details.get('mitre_technique'),
                
                # Notification behavior
                'requires_acknowledgment': alert.Severity in ['High', 'Critical'],
                'auto_escalate': alert.Severity == 'Critical',
                'display_popup': True,
                'play_sound': alert.Severity in ['High', 'Critical'],
                'action_required': True,
                
                # Additional metadata
                'timestamp': datetime.now().isoformat(),
                'source': 'detection_engine',
                'violation_type': 'RULE_VIOLATION',
                'agent_id': agent_id
            }
            
            # Send notification
            success = await self.send_realtime_notification(session, agent_id, notification)
            
            if success:
                logger.warning(f"✅ RULE VIOLATION NOTIFICATION SENT:")
                logger.warning(f"   📋 Alert ID: {alert.AlertID}")
                logger.warning(f"   📝 Rule: {rule_details.get('rule_name')}")
                logger.warning(f"   🎯 Agent: {agent_id}")
            else:
                logger.error(f"❌ RULE VIOLATION NOTIFICATION FAILED:")
                logger.error(f"   📋 Alert ID: {alert.AlertID}")
                logger.error(f"   🎯 Agent: {agent_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"💥 Rule violation notification failed: {str(e)}")
            return False
    
    def get_pending_actions(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending response actions for agent"""
        try:
            logger.info(f"🔍 CHECKING PENDING ACTIONS for agent: {agent_id}")
            
            # Get open alerts for the agent that may require action
            alerts = session.query(Alert).filter(
                Alert.AgentID == agent_id,
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.RiskScore >= 40  # Lowered threshold for testing
            ).order_by(Alert.FirstDetected.desc()).limit(20).all()
            
            logger.info(f"   📊 Found {len(alerts)} alerts requiring action")
            
            pending_actions = []
            for alert in alerts:
                try:
                    action = {
                        'alert_id': alert.AlertID,
                        'action_type': self._determine_action_type(alert),
                        'priority': alert.Severity,
                        'title': alert.Title,
                        'description': f"Response required for: {alert.Title}",
                        'risk_score': alert.RiskScore,
                        'severity': alert.Severity,
                        'created_at': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                        'age_minutes': alert.get_age_minutes() if hasattr(alert, 'get_age_minutes') else 0,
                        'detection_method': alert.DetectionMethod,
                        'requires_acknowledgment': alert.Severity in ['High', 'Critical']
                    }
                    pending_actions.append(action)
                    
                    logger.info(f"   📋 Action: {action['action_type']} for Alert {alert.AlertID}")
                    
                except Exception as e:
                    logger.error(f"   💥 Failed to process alert {alert.AlertID}: {e}")
                    continue
            
            logger.info(f"✅ PENDING ACTIONS: {len(pending_actions)} for agent {agent_id}")
            return pending_actions
            
        except Exception as e:
            logger.error(f"💥 Failed to get pending actions: {e}")
            return []
    
    def _determine_action_type(self, alert: Alert) -> str:
        """Determine action type based on alert properties"""
        try:
            risk_score = alert.RiskScore or 0
            severity = alert.Severity or 'Medium'
            
            if risk_score >= 85 or severity == 'Critical':
                return 'isolate'
            elif risk_score >= 70 or severity == 'High':
                return 'quarantine'
            elif risk_score >= 60:
                return 'investigate'
            elif risk_score >= 40:
                return 'monitor'
            else:
                return 'acknowledge'
                
        except Exception as e:
            logger.error(f"Action type determination failed: {e}")
            return 'investigate'
    
    def record_action_response(self, session: Session, agent_id: str, alert_id: int, 
                             action_type: str, success: bool, details: str) -> bool:
        """Record agent's response to an action"""
        try:
            logger.info(f"📝 RECORDING ACTION RESPONSE:")
            logger.info(f"   🎯 Agent: {agent_id}")
            logger.info(f"   📋 Alert: {alert_id}")
            logger.info(f"   🔧 Action: {action_type}")
            logger.info(f"   ✅ Success: {success}")
            
            alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
            if not alert:
                logger.error(f"   ❌ Alert not found: {alert_id}")
                return False
            
            # Create response record
            response_text = f"Agent Response ({action_type}): {'SUCCESS' if success else 'FAILED'}"
            if details:
                response_text += f" - {details}"
            response_text += f" at {datetime.now().isoformat()}"
            
            # Add response action to alert
            if hasattr(alert, 'add_response_action'):
                alert.add_response_action(response_text)
            else:
                # Fallback method
                if alert.ResponseAction:
                    alert.ResponseAction += f"\n{response_text}"
                else:
                    alert.ResponseAction = response_text
            
            # Update alert status based on response
            if success:
                if action_type in ['isolate', 'quarantine']:
                    alert.Status = "Investigating"
                elif action_type == 'investigate':
                    alert.Status = "Investigating"
                elif action_type == 'acknowledge':
                    alert.Status = "Investigating"
            
            session.commit()
            
            logger.info(f"✅ ACTION RESPONSE RECORDED:")
            logger.info(f"   📋 Alert: {alert_id}")
            logger.info(f"   🔧 Action: {action_type}")
            logger.info(f"   📝 Success: {success}")
            logger.info(f"   📄 Details: {details}")
            
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"💥 Failed to record action response: {e}")
            return False
    
    def get_communication_stats(self) -> Dict[str, Any]:
        """Get communication service statistics"""
        try:
            total_time = max(self.stats['total_processing_time'], 0.001)
            total_notifications = max(self.stats['notifications_sent'], 1)
            
            return {
                'notifications_sent': self.stats['notifications_sent'],
                'notifications_delivered': self.stats['notifications_delivered'],
                'notifications_failed': self.stats['notifications_failed'],
                'success_rate': round(
                    ((self.stats['notifications_sent'] - self.stats['notifications_failed']) / 
                     total_notifications) * 100, 2
                ),
                'delivery_rate': round(
                    (self.stats['notifications_delivered'] / total_notifications) * 100, 2
                ),
                'average_processing_time_ms': round(
                    (total_time / total_notifications) * 1000, 2
                ),
                'total_processing_time': round(total_time, 2)
            }
        except Exception as e:
            logger.error(f"Stats calculation failed: {e}")
            return {
                'notifications_sent': 0,
                'notifications_delivered': 0,
                'notifications_failed': 0,
                'success_rate': 0,
                'delivery_rate': 0,
                'average_processing_time_ms': 0
            }
    
    def reset_stats(self):
        """Reset communication statistics"""
        self.stats = {
            'notifications_sent': 0,
            'notifications_delivered': 0,
            'notifications_failed': 0,
            'total_processing_time': 0.0
        }
        logger.info("📊 Agent communication statistics reset")
    
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
                    status = record.get('status', 'unknown')
                    
                    # Delete if retrieved or expired
                    if status in ['retrieved', 'expired', 'processed']:
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
            logger.error(f"💥 Failed to cleanup notifications: {e}")
            return 0

# Global service instance
agent_communication_service = AgentCommunicationService()