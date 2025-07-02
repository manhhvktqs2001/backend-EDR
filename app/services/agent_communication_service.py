# app/services/agent_communication_service.py - ENHANCED NOTIFICATION SYSTEM
"""
Agent Communication Service - ENHANCED VERSION
Đảm bảo tất cả dữ liệu DetectionRules được gửi đầy đủ đến agent
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
    """Enhanced Agent communication service with complete DetectionRules data mapping"""
    
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
            'total_processing_time': 0.0,
            'rule_violations_sent': 0,
            'complete_data_notifications': 0
        }
        
        logger.info("📡 Enhanced Agent Communication Service - Complete DetectionRules Data Mapping")
    
    async def send_enhanced_rule_violation_notification(self, session: Session, agent_id: str, 
                                                       alert: Alert, complete_rule_data: Dict) -> bool:
        """
        ENHANCED: Send rule violation notification with COMPLETE DetectionRules data
        """
        try:
            logger.warning(f"🚨 SENDING ENHANCED RULE VIOLATION NOTIFICATION:")
            logger.warning(f"   🎯 Agent: {agent_id}")
            logger.warning(f"   📋 Alert: {alert.AlertID}")
            logger.warning(f"   📝 Rule: {complete_rule_data.get('rule_name', 'Unknown')}")
            logger.warning(f"   📊 Complete Fields: {len(complete_rule_data)}")
            
            # Create ENHANCED notification with ALL DetectionRules data
            enhanced_notification = self._build_enhanced_notification(alert, complete_rule_data, agent_id)
            
            # Send enhanced notification
            success = await self.send_realtime_notification(session, agent_id, enhanced_notification)
            
            if success:
                self.stats['rule_violations_sent'] += 1
                self.stats['complete_data_notifications'] += 1
                
                logger.warning(f"✅ ENHANCED RULE VIOLATION NOTIFICATION SENT:")
                logger.warning(f"   📋 Alert ID: {alert.AlertID}")
                logger.warning(f"   📝 Rule: {complete_rule_data.get('rule_name')}")
                logger.warning(f"   🎯 Agent: {agent_id}")
                logger.warning(f"   📊 Data Fields: {len(enhanced_notification)}")
            else:
                logger.error(f"❌ ENHANCED RULE VIOLATION NOTIFICATION FAILED:")
                logger.error(f"   📋 Alert ID: {alert.AlertID}")
                logger.error(f"   🎯 Agent: {agent_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"💥 Enhanced rule violation notification failed: {str(e)}")
            return False
    
    def _build_enhanced_notification(self, alert: Alert, complete_rule_data: Dict, agent_id: str) -> Dict:
        """
        Build enhanced notification with COMPLETE DetectionRules data
        """
        try:
            # Generate unique notification ID
            timestamp = int(datetime.now().timestamp() * 1000000)
            random_suffix = str(uuid.uuid4())[:8]
            notification_id = f"enhanced_notif_{timestamp}_{random_suffix}"
            
            enhanced_notification = {
                # ===== NOTIFICATION METADATA =====
                'notification_id': notification_id,
                'agent_id': agent_id,
                'sent_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(seconds=self.notification_config['notification_timeout'])).isoformat(),
                'type': 'enhanced_security_rule_violation',
                'category': 'rule_detection',
                'source': 'detection_engine',
                'priority': self._determine_notification_priority_enhanced(complete_rule_data, alert),
                'notification_version': '2.0',  # Enhanced version
                
                # ===== COMPLETE DETECTION RULE DATA =====
                'rule_data': {
                    # Core Rule Information (từ DetectionRules table)
                    'rule_id': complete_rule_data.get('rule_id'),                    # DetectionRules.RuleID
                    'rule_name': complete_rule_data.get('rule_name'),                # DetectionRules.RuleName
                    'rule_type': complete_rule_data.get('rule_type'),                # DetectionRules.RuleType
                    'rule_category': complete_rule_data.get('rule_category'),        # DetectionRules.RuleCategory
                    'rule_condition': complete_rule_data.get('rule_condition'),      # DetectionRules.RuleCondition (JSON)
                    
                    # Rule Metadata
                    'platform': complete_rule_data.get('platform'),                 # DetectionRules.Platform
                    'priority': complete_rule_data.get('priority'),                 # DetectionRules.Priority
                    'is_active': complete_rule_data.get('is_active'),               # DetectionRules.IsActive
                    'test_mode': complete_rule_data.get('test_mode'),               # DetectionRules.TestMode
                    
                    # Timestamps
                    'rule_created_at': complete_rule_data.get('created_at'),         # DetectionRules.CreatedAt
                    'rule_updated_at': complete_rule_data.get('updated_at'),         # DetectionRules.UpdatedAt
                    
                    # Condition Analysis
                    'condition_summary': complete_rule_data.get('condition_summary'),
                    'rule_confidence': complete_rule_data.get('confidence', 0.8)
                },
                
                # ===== ALERT CONFIGURATION DATA =====
                'alert_data': {
                    # Alert Content (từ DetectionRules table)
                    'alert_title': complete_rule_data.get('alert_title'),            # DetectionRules.AlertTitle
                    'alert_description': complete_rule_data.get('alert_description'), # DetectionRules.AlertDescription
                    'alert_severity': complete_rule_data.get('alert_severity'),      # DetectionRules.AlertSeverity
                    'alert_type': complete_rule_data.get('alert_type'),              # DetectionRules.AlertType
                    
                    # Calculated Alert Data
                    'risk_score': complete_rule_data.get('risk_score', alert.RiskScore),
                    'confidence': complete_rule_data.get('confidence', 0.8),
                    
                    # Alert Instance Data
                    'alert_id': alert.AlertID,
                    'event_id': alert.EventID,
                    'detection_method': alert.DetectionMethod,
                    'first_detected': alert.FirstDetected.isoformat() if alert.FirstDetected else None,
                    'event_count': alert.EventCount or 1
                },
                
                # ===== MITRE ATT&CK DATA =====
                'mitre_data': {
                    'tactic': complete_rule_data.get('mitre_tactic'),               # DetectionRules.MitreTactic
                    'technique': complete_rule_data.get('mitre_technique'),         # DetectionRules.MitreTechnique
                    'has_mitre_mapping': bool(complete_rule_data.get('mitre_tactic') or complete_rule_data.get('mitre_technique'))
                },
                
                # ===== DISPLAY CONFIGURATION =====
                'display_config': complete_rule_data.get('display_config', {
                    'show_popup': True,
                    'auto_display': True,
                    'play_sound': complete_rule_data.get('alert_severity', 'Medium') in ['High', 'Critical'],
                    'require_acknowledgment': complete_rule_data.get('alert_severity', 'Medium') in ['High', 'Critical'],
                    'highlight_color': self._get_severity_color(complete_rule_data.get('alert_severity', 'Medium')),
                    'icon_type': self._get_severity_icon(complete_rule_data.get('alert_severity', 'Medium')),
                    'show_details': True,
                    'show_mitre_info': bool(complete_rule_data.get('mitre_tactic') or complete_rule_data.get('mitre_technique'))
                }),
                
                # ===== RESPONSE CONFIGURATION =====
                'response_config': complete_rule_data.get('response_config', {
                    'available_actions': self._get_available_actions(complete_rule_data.get('alert_severity', 'Medium')),
                    'default_action': self._get_default_action(complete_rule_data.get('alert_severity', 'Medium')),
                    'timeout_seconds': 300 if complete_rule_data.get('alert_severity') == 'Critical' else 600,
                    'require_justification': complete_rule_data.get('alert_severity', 'Medium') in ['High', 'Critical'],
                    'escalation_enabled': complete_rule_data.get('alert_severity') == 'Critical'
                }),
                
                # ===== ENHANCED METADATA =====
                'enhanced_metadata': {
                    'detection_timestamp': complete_rule_data.get('detection_timestamp'),
                    'rule_matched': True,
                    'data_completeness': 'full',  # Indicates complete DetectionRules data
                    'notification_enhanced': True,
                    'total_data_fields': len(complete_rule_data),
                    'processing_mode': 'realtime_enhanced'
                },
                
                # ===== AGENT INTERACTION DATA =====
                'interaction_data': {
                    'requires_acknowledgment': complete_rule_data.get('alert_severity', 'Medium') in ['High', 'Critical'],
                    'auto_escalate': complete_rule_data.get('alert_severity') == 'Critical',
                    'escalation_timeout': 300 if complete_rule_data.get('alert_severity') == 'Critical' else 600,
                    'can_dismiss': complete_rule_data.get('alert_severity', 'Medium') not in ['Critical'],
                    'bulk_action_allowed': True,
                    'feedback_enabled': True
                },
                
                # ===== LEGACY COMPATIBILITY =====
                'title': complete_rule_data.get('alert_title', alert.Title),
                'description': complete_rule_data.get('alert_description', alert.Description),
                'severity': complete_rule_data.get('alert_severity', alert.Severity),
                'rule_id': complete_rule_data.get('rule_id'),
                'rule_name': complete_rule_data.get('rule_name'),
                'mitre_tactic': complete_rule_data.get('mitre_tactic'),
                'mitre_technique': complete_rule_data.get('mitre_technique'),
                
                # ===== TIMESTAMPS =====
                'timestamp': datetime.now().isoformat(),
                'violation_type': 'ENHANCED_RULE_VIOLATION'
            }
            
            logger.info(f"📦 Enhanced notification built with {len(enhanced_notification)} top-level fields")
            logger.info(f"   📋 Rule data: {len(enhanced_notification['rule_data'])} fields")
            logger.info(f"   📄 Alert data: {len(enhanced_notification['alert_data'])} fields")
            logger.info(f"   🎯 MITRE data: {len(enhanced_notification['mitre_data'])} fields")
            
            return enhanced_notification
            
        except Exception as e:
            logger.error(f"💥 Failed to build enhanced notification: {e}")
            # Return minimal notification as fallback
            return self._build_minimal_notification_fallback(alert, complete_rule_data, agent_id)
    
    def _build_minimal_notification_fallback(self, alert: Alert, rule_data: Dict, agent_id: str) -> Dict:
        """Build minimal notification as fallback"""
        return {
            'notification_id': f"fallback_{int(datetime.now().timestamp())}",
            'agent_id': agent_id,
            'type': 'security_rule_violation',
            'title': rule_data.get('alert_title', alert.Title or 'Security Alert'),
            'description': rule_data.get('alert_description', alert.Description or 'Rule violation detected'),
            'severity': rule_data.get('alert_severity', alert.Severity or 'Medium'),
            'rule_id': rule_data.get('rule_id'),
            'rule_name': rule_data.get('rule_name', 'Unknown Rule'),
            'alert_id': alert.AlertID,
            'timestamp': datetime.now().isoformat(),
            'fallback_mode': True
        }
    
    def _determine_notification_priority_enhanced(self, rule_data: Dict, alert: Alert) -> str:
        """Determine enhanced notification priority"""
        try:
            severity = rule_data.get('alert_severity', alert.Severity or 'Medium')
            rule_priority = rule_data.get('priority', 50)
            risk_score = rule_data.get('risk_score', alert.RiskScore or 0)
            test_mode = rule_data.get('test_mode', False)
            
            # Calculate priority based on multiple factors
            if test_mode:
                return 'Low'  # Test mode rules get lower priority
            
            if severity == 'Critical' or risk_score >= 90 or rule_priority >= 90:
                return 'Critical'
            elif severity == 'High' or risk_score >= 70 or rule_priority >= 75:
                return 'High'
            elif severity == 'Medium' or risk_score >= 50 or rule_priority >= 50:
                return 'Medium'
            else:
                return 'Low'
                
        except Exception as e:
            logger.error(f"Priority calculation failed: {e}")
            return 'Medium'
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity"""
        colors = {
            'Critical': '#FF0000',  # Red
            'High': '#FF6600',      # Orange
            'Medium': '#FFFF00',    # Yellow
            'Low': '#00FF00',       # Green
            'Info': '#0099FF'       # Blue
        }
        return colors.get(severity, '#FFFF00')
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get icon type for severity"""
        icons = {
            'Critical': 'critical_alert',
            'High': 'warning',
            'Medium': 'info',
            'Low': 'notification',
            'Info': 'info'
        }
        return icons.get(severity, 'info')
    
    def _get_available_actions(self, severity: str) -> List[str]:
        """Get available actions based on severity"""
        base_actions = ['acknowledge', 'investigate']
        
        if severity in ['High', 'Critical']:
            base_actions.extend(['isolate', 'quarantine'])
        
        if severity not in ['Critical']:
            base_actions.append('dismiss')
        
        if severity == 'Critical':
            base_actions.append('escalate')
        
        return base_actions
    
    def _get_default_action(self, severity: str) -> str:
        """Get default action based on severity"""
        if severity in ['High', 'Critical']:
            return 'investigate'
        else:
            return 'acknowledge'
    
    async def send_realtime_notification(self, session: Session, agent_id: str, 
                                        notification: Dict) -> bool:
        """Send realtime notification to agent with enhanced error handling"""
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
            
            # Enhance notification with agent metadata
            enhanced_notification = {
                **notification,
                'agent_hostname': agent.HostName,
                'agent_os': agent.OperatingSystem,
                'delivery_attempts': 0,
                'max_delivery_attempts': 3,
                'auto_display': True,
                'delivery_metadata': {
                    'agent_last_heartbeat': agent.LastHeartbeat.isoformat() if agent.LastHeartbeat else None,
                    'agent_status': agent.Status,
                    'agent_monitoring': agent.MonitoringEnabled
                }
            }
            
            # Store notification for agent retrieval
            success = await self._store_enhanced_notification(session, agent_id, enhanced_notification)
            
            if success:
                processing_time = (datetime.now() - start_time).total_seconds()
                self.stats['notifications_sent'] += 1
                self.stats['total_processing_time'] += processing_time
                
                logger.warning(f"📤 ENHANCED NOTIFICATION SENT SUCCESSFULLY:")
                logger.warning(f"   🎯 Agent: {agent.HostName} ({agent_id})")
                logger.warning(f"   📋 ID: {enhanced_notification.get('notification_id')}")
                logger.warning(f"   🔔 Type: {enhanced_notification.get('type')}")
                logger.warning(f"   ⚡ Priority: {enhanced_notification.get('priority')}")
                logger.warning(f"   📊 Data Fields: {len(enhanced_notification)}")
                logger.warning(f"   ⏱️ Processing: {processing_time*1000:.1f}ms")
                
                return True
            else:
                self.stats['notifications_failed'] += 1
                logger.error(f"❌ Failed to store enhanced notification for {agent.HostName}")
                return False
                
        except Exception as e:
            self.stats['notifications_failed'] += 1
            logger.error(f"💥 Enhanced notification sending failed: {str(e)}")
            return False
    
    async def _store_enhanced_notification(self, session: Session, agent_id: str, 
                                         notification: Dict) -> bool:
        """Store enhanced notification with additional metadata"""
        try:
            # Clean up old notifications first
            await self._cleanup_old_notifications_for_agent(session, agent_id)
            
            notification_id = notification.get('notification_id', f"notif_{int(datetime.now().timestamp())}")
            notification_key = f"enhanced_agent_notification_{agent_id}_{notification_id}"
            
            # Check if already exists
            existing = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey == notification_key
            ).first()
            
            if existing:
                logger.warning(f"⚠️ Enhanced notification already exists, updating: {notification_key}")
                existing.ConfigValue = json.dumps({
                    'notification_data': notification,
                    'status': 'pending',
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat(),
                    'agent_id': agent_id,
                    'notification_key': notification_key,
                    'enhanced_version': True,
                    'data_completeness': 'full'
                })
                session.commit()
                return True
            
            # Create new enhanced notification record
            notification_record = {
                'notification_data': notification,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'agent_id': agent_id,
                'notification_key': notification_key,
                'enhanced_version': True,
                'data_completeness': 'full',
                'priority': notification.get('priority', 'Medium'),
                'type': notification.get('type', 'unknown'),
                'expires_at': notification.get('expires_at'),
                'rule_id': notification.get('rule_data', {}).get('rule_id'),
                'alert_id': notification.get('alert_data', {}).get('alert_id')
            }
            
            config_entry = SystemConfig(
                ConfigKey=notification_key,
                ConfigValue=json.dumps(notification_record),
                ConfigType='JSON',
                Category='EnhancedAgentNotifications',
                Description=f"Enhanced DetectionRules notification for agent {agent_id} - {notification.get('type', 'unknown')}"
            )
            
            session.add(config_entry)
            session.commit()
            
            logger.info(f"📝 ENHANCED NOTIFICATION STORED:")
            logger.info(f"   🔑 Key: {notification_key}")
            logger.info(f"   📋 ID: {notification_id}")
            logger.info(f"   🎯 Agent: {agent_id}")
            logger.info(f"   📊 Data Size: {len(json.dumps(notification_record))} chars")
            
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"💥 Failed to store enhanced notification: {str(e)}")
            return False
    
    def get_pending_notifications(self, session: Session, agent_id: str) -> List[Dict]:
        """Get pending notifications with enhanced data extraction"""
        try:
            logger.info(f"📥 CHECKING ENHANCED PENDING NOTIFICATIONS:")
            logger.info(f"   🎯 Agent ID: {agent_id}")
            
            # Query both regular and enhanced notifications
            regular_configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).order_by(SystemConfig.CreatedAt.desc()).limit(50).all()
            
            enhanced_configs = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'enhanced_agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'EnhancedAgentNotifications'
            ).order_by(SystemConfig.CreatedAt.desc()).limit(50).all()
            
            all_configs = regular_configs + enhanced_configs
            
            logger.info(f"   📊 Found {len(regular_configs)} regular + {len(enhanced_configs)} enhanced notifications")
            
            notifications = []
            configs_to_update = []
            configs_to_delete = []
            
            for config in all_configs:
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
                        # Mark enhanced notifications
                        if record.get('enhanced_version'):
                            notification_data['_enhanced'] = True
                            notification_data['_data_completeness'] = record.get('data_completeness', 'partial')
                        
                        notifications.append(notification_data)
                        
                        # Mark as retrieved
                        record['status'] = 'retrieved'
                        record['retrieved_at'] = datetime.now().isoformat()
                        record['delivery_attempts'] = record.get('delivery_attempts', 0) + 1
                        
                        config.ConfigValue = json.dumps(record)
                        configs_to_update.append(config)
                        
                        logger.info(f"   📋 Pending notification: {notification_data.get('type', 'unknown')} ({'Enhanced' if record.get('enhanced_version') else 'Regular'})")
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
                enhanced_count = sum(1 for n in notifications if n.get('_enhanced'))
                regular_count = len(notifications) - enhanced_count
                
                logger.warning(f"📤 DELIVERED {len(notifications)} NOTIFICATIONS:")
                logger.warning(f"   🎯 Agent: {agent_id}")
                logger.warning(f"   📊 Enhanced: {enhanced_count}, Regular: {regular_count}")
                self.stats['notifications_delivered'] += len(notifications)
                
                # Log notification details
                for i, notif in enumerate(notifications):
                    notif_type = notif.get('type', 'unknown')
                    notif_title = notif.get('title', 'No title')
                    notif_priority = notif.get('priority', 'Unknown')
                    enhanced = "Enhanced" if notif.get('_enhanced') else "Regular"
                    logger.warning(f"   📋 {i+1}. {enhanced}: {notif_type} - {notif_title} (Priority: {notif_priority})")
            else:
                logger.info(f"   📭 No pending notifications for agent {agent_id}")
            
            return notifications
            
        except Exception as e:
            logger.error(f"💥 Get enhanced pending notifications failed: {e}")
            logger.error(f"   🎯 Agent: {agent_id}")
            return []
    
    async def _cleanup_old_notifications_for_agent(self, session: Session, agent_id: str):
        """Clean up old notifications for specific agent"""
        try:
            # Get notification count for both regular and enhanced
            regular_count = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'AgentNotifications'
            ).count()
            
            enhanced_count = session.query(SystemConfig).filter(
                SystemConfig.ConfigKey.like(f'enhanced_agent_notification_{agent_id}_%'),
                SystemConfig.Category == 'EnhancedAgentNotifications'
            ).count()
            
            total_count = regular_count + enhanced_count
            max_notifications = self.notification_config['max_notifications_per_agent']
            
            if total_count > max_notifications:
                # Clean up old regular notifications first
                old_regular = session.query(SystemConfig).filter(
                    SystemConfig.ConfigKey.like(f'agent_notification_{agent_id}_%'),
                    SystemConfig.Category == 'AgentNotifications'
                ).order_by(SystemConfig.CreatedAt.asc()).limit(
                    max(0, regular_count - (max_notifications // 2))
                ).all()
                
                # Then clean up old enhanced notifications if needed
                old_enhanced = session.query(SystemConfig).filter(
                    SystemConfig.ConfigKey.like(f'enhanced_agent_notification_{agent_id}_%'),
                    SystemConfig.Category == 'EnhancedAgentNotifications'
                ).order_by(SystemConfig.CreatedAt.asc()).limit(
                    max(0, enhanced_count - (max_notifications // 2))
                ).all()
                
                deleted_count = 0
                for config in old_regular + old_enhanced:
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
    
    def get_communication_stats(self) -> Dict[str, Any]:
        """Get enhanced communication service statistics"""
        try:
            total_time = max(self.stats['total_processing_time'], 0.001)
            total_notifications = max(self.stats['notifications_sent'], 1)
            
            return {
                'notifications_sent': self.stats['notifications_sent'],
                'notifications_delivered': self.stats['notifications_delivered'],
                'notifications_failed': self.stats['notifications_failed'],
                'rule_violations_sent': self.stats['rule_violations_sent'],
                'complete_data_notifications': self.stats['complete_data_notifications'],
                'success_rate': round(
                    ((self.stats['notifications_sent'] - self.stats['notifications_failed']) / 
                     total_notifications) * 100, 2
                ),
                'delivery_rate': round(
                    (self.stats['notifications_delivered'] / total_notifications) * 100, 2
                ),
                'enhancement_rate': round(
                    (self.stats['complete_data_notifications'] / total_notifications) * 100, 2
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
                'enhancement_rate': 0
            }
    
    # Legacy method for backward compatibility
    async def send_rule_violation_notification(self, session: Session, agent_id: str, 
                                             alert: Alert, rule_details: Dict) -> bool:
        """Legacy method - redirects to enhanced version"""
        return await self.send_enhanced_rule_violation_notification(session, agent_id, alert, rule_details)

# Global service instance
agent_communication_service = AgentCommunicationService()