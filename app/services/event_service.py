# app/services/event_service.py - MODIFIED (No auto alert creation)
"""
Event Processing Service - MODIFIED
Server chỉ phát hiện và gửi thông báo cho Agent, KHÔNG tự động tạo alerts
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

# FIXED: Import all required models
from ..models.event import Event
from ..models.agent import Agent

# FIXED: Import with try-catch for missing models
try:
    from ..models.detection_rule import DetectionRule
    from ..models.threat import Threat
    DETECTION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Detection models not available: {e}")
    DetectionRule = None
    Threat = None
    DETECTION_AVAILABLE = False

from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse
)
from ..config import config

logger = logging.getLogger('event_processing')

class EventService:
    """Service for processing and managing events - MODIFIED: No auto alert creation"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        self.detection_enabled = (DETECTION_AVAILABLE and 
                                self.detection_config.get('rules_enabled', False))
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                    client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """Submit single event for processing - MODIFIED: Only detection, no alert creation"""
        try:
            # Validate agent exists
            agent = Agent.get_by_id(session, event_data.agent_id)
            if not agent:
                error_msg = f"Agent not found: {event_data.agent_id}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # Validate agent is monitoring enabled
            if not agent.MonitoringEnabled:
                error_msg = f"Monitoring disabled for agent: {agent.HostName}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # Create and validate event
            event = self._create_event_from_request(event_data)
            if not event:
                error_msg = "Failed to create event from request data"
                logger.error(error_msg)
                return False, None, error_msg
            
            # Store event in database
            session.add(event)
            session.flush()  # Get event ID without committing
            
            # MODIFIED: Only run detection analysis, NO alert creation
            threat_detected = False
            risk_score = 0
            detection_notifications = []  # Notifications to send to agent
            
            if self.detection_enabled:
                try:
                    # Run detection analysis (WITHOUT creating alerts)
                    detection_results = self._run_detection_analysis_only(session, event)
                    if detection_results:
                        threat_detected = detection_results.get('threat_detected', False)
                        risk_score = detection_results.get('risk_score', 0)
                        detection_notifications = detection_results.get('notifications', [])
                        
                        # Update event with detection results
                        event.update_analysis(
                            threat_level=detection_results.get('threat_level', 'None'),
                            risk_score=risk_score
                        )
                        
                        # MODIFIED: Send detection notifications to agent (not alerts)
                        if threat_detected and detection_notifications:
                            await self._send_detection_notifications_to_agent(
                                session, event_data.agent_id, detection_notifications
                            )
                            logger.warning(f"🚨 Threat detected, notifications sent to agent {agent.HostName}: "
                                         f"Risk={risk_score}, Notifications={len(detection_notifications)}")
                        
                except Exception as e:
                    logger.error(f"Detection engine error for event {event.EventID}: {str(e)}")
                    # Continue processing even if detection fails
            else:
                # Set basic analysis if detection not available
                event.update_analysis(threat_level='None', risk_score=0)
            
            session.commit()
            
            logger.debug(f"Event processed: ID={event.EventID}, Type={event.EventType}, Agent={agent.HostName}")
            
            response = EventSubmissionResponse(
                success=True,
                message="Event processed successfully",
                event_id=event.EventID,
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=[]  # MODIFIED: No alerts generated automatically
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            error_msg = f"Event submission failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    async def submit_event_batch(self, session: Session, batch_data: EventBatchRequest,
                          client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """Submit batch of events - MODIFIED: No auto alert creation"""
        try:
            # Validate batch size
            if len(batch_data.events) > self.max_batch_size:
                error_msg = f"Batch size {len(batch_data.events)} exceeds maximum {self.max_batch_size}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # Validate agent exists
            logger.info(f"[EVENT_BATCH] Received batch from AgentID: {batch_data.agent_id}")
            agent = Agent.get_by_id(session, batch_data.agent_id)
            if not agent:
                error_msg = f"Agent not found: {batch_data.agent_id}"
                logger.warning(error_msg)
                return False, None, error_msg
            logger.info(f"[EVENT_BATCH] Agent found: {agent.HostName} | AgentID: {agent.AgentID}")
            
            # Process events in batch
            processed_events = 0
            failed_events = 0
            detection_notifications = []  # MODIFIED: Collect notifications instead of alerts
            errors = []
            total_risk_score = 0
            threats_detected = 0
            
            for event_data in batch_data.events:
                try:
                    # Ensure agent_id matches batch agent_id
                    event_data.agent_id = batch_data.agent_id
                    
                    # Create event
                    event = self._create_event_from_request(event_data)
                    if not event:
                        failed_events += 1
                        errors.append(f"Failed to create event from data")
                        continue
                    
                    # Store event
                    session.add(event)
                    session.flush()
                    
                    # MODIFIED: Run detection but don't create alerts
                    if self.detection_enabled:
                        try:
                            detection_results = self._run_detection_analysis_only(session, event)
                            if detection_results:
                                if detection_results.get('notifications'):
                                    detection_notifications.extend(detection_results['notifications'])
                                
                                if detection_results.get('threat_detected'):
                                    threats_detected += 1
                                
                                risk_score = detection_results.get('risk_score', 0)
                                total_risk_score += risk_score
                                
                                # Update event with detection results
                                event.update_analysis(
                                    threat_level=detection_results.get('threat_level', 'None'),
                                    risk_score=risk_score
                                )
                                
                                if risk_score > 50:  # Log significant detections
                                    logger.warning(f"Threat detected in event {event.EventID}: "
                                                 f"Risk={risk_score}, Level={detection_results.get('threat_level')}")
                        except Exception as e:
                            logger.error(f"Detection failed for event in batch: {str(e)}")
                    else:
                        # Set basic analysis if detection not available
                        event.update_analysis(threat_level='None', risk_score=0)
                    
                    processed_events += 1
                    
                except Exception as e:
                    failed_events += 1
                    errors.append(f"Event processing error: {str(e)}")
                    logger.error(f"Failed to process event in batch: {str(e)}")
            
            session.commit()
            
            # Enhanced logging
            avg_risk = total_risk_score / processed_events if processed_events > 0 else 0
            logger.info(f"Batch processed: {processed_events} success, {failed_events} failed from agent {agent.HostName}")
            if threats_detected > 0:
                logger.warning(f"🚨 Threats detected: {threats_detected}/{processed_events} events, "
                             f"Avg risk: {avg_risk:.1f}, Notifications: {len(detection_notifications)}")
            
            # MODIFIED: Send detection notifications to agent (not alerts)
            if detection_notifications:
                try:
                    await self._send_detection_notifications_to_agent(
                        session, batch_data.agent_id, detection_notifications
                    )
                    logger.info(f"📤 Sent {len(detection_notifications)} detection notifications to agent {agent.HostName}")
                except Exception as e:
                    logger.error(f"Failed to send notifications to agent: {str(e)}")

            response = EventBatchResponse(
                success=True,
                message=f"Batch processed: {processed_events} events",
                total_events=len(batch_data.events),
                processed_events=processed_events,
                failed_events=failed_events,
                alerts_generated=[],  # MODIFIED: No auto alerts
                errors=errors
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            error_msg = f"Event batch submission failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def _run_detection_analysis_only(self, session: Session, event: Event) -> Optional[Dict]:
        """
        MODIFIED: Run detection analysis but DON'T create alerts
        Only prepare notifications to send to agent
        """
        try:
            if not DETECTION_AVAILABLE:
                logger.debug("Detection models not available")
                return None
            
            detection_results = {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'notifications': [],  # MODIFIED: Notifications instead of alerts
                'detection_methods': ['Detection Analysis'],
                'matched_rules': [],
                'matched_threats': [],
                'rule_details': [],
                'threat_details': []
            }
            
            # Check against active detection rules
            if DetectionRule:
                try:
                    active_rules = session.query(DetectionRule).filter(
                        DetectionRule.IsActive == True
                    ).all()
                    
                    for rule in active_rules:
                        if self._evaluate_simple_rule(event, rule):
                            detection_results['matched_rules'].append(rule.RuleID)
                            detection_results['risk_score'] += self._get_rule_risk_score(rule)
                            detection_results['detection_methods'].append(f"Rule: {rule.RuleName}")
                            
                            # MODIFIED: Create notification instead of alert
                            notification = self._create_rule_notification(event, rule)
                            detection_results['notifications'].append(notification)
                            
                            logger.info(f"🔍 Rule matched: {rule.RuleName} for event {event.EventID}")
                            
                except Exception as e:
                    logger.error(f"Rule checking failed: {e}")
            
            # Check threat intelligence
            if Threat:
                try:
                    threat_matches = self._check_simple_threats(session, event)
                    if threat_matches:
                        detection_results['matched_threats'].extend(threat_matches)
                        detection_results['risk_score'] += len(threat_matches) * 20
                        detection_results['detection_methods'].append('Threat Intelligence')
                        
                        # MODIFIED: Create threat notifications
                        for threat_id in threat_matches:
                            threat = session.query(Threat).filter(Threat.ThreatID == threat_id).first()
                            if threat:
                                notification = self._create_threat_notification(event, threat)
                                detection_results['notifications'].append(notification)
                                
                except Exception as e:
                    logger.error(f"Threat checking failed: {e}")
            
            # Determine threat level based on risk score
            risk_score = min(detection_results['risk_score'], 100)
            detection_results['risk_score'] = risk_score
            
            if risk_score >= 80:
                detection_results['threat_level'] = 'Malicious'
            elif risk_score >= 50:
                detection_results['threat_level'] = 'Suspicious'
            else:
                detection_results['threat_level'] = 'None'
            
            # Mark as threat detected if significant risk
            risk_threshold = self.detection_config.get('risk_score_threshold', 70)
            if risk_score >= risk_threshold:
                detection_results['threat_detected'] = True
            
            if detection_results['threat_detected']:
                logger.warning(f"🚨 Threat detected in event {event.EventID}: "
                             f"Risk={risk_score}, Level={detection_results['threat_level']}, "
                             f"Rules={len(detection_results['matched_rules'])}, "
                             f"Threats={len(detection_results['matched_threats'])}")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"Detection analysis failed: {str(e)}")
            return None
    
    def _create_rule_notification(self, event: Event, rule) -> Dict:
        """MODIFIED: Create notification for rule match (not alert)"""
        try:
            return {
                'type': 'rule_detection',
                'event_id': event.EventID,
                'rule_id': getattr(rule, 'RuleID', None),
                'rule_name': getattr(rule, 'RuleName', 'Unknown Rule'),
                'alert_type': getattr(rule, 'AlertType', 'Rule Detection'),
                'title': getattr(rule, 'AlertTitle', f"Rule Detection: {getattr(rule, 'RuleName', 'Unknown')}"),
                'description': getattr(rule, 'AlertDescription', f"Rule '{getattr(rule, 'RuleName', 'Unknown')}' triggered"),
                'severity': getattr(rule, 'AlertSeverity', 'Medium'),
                'mitre_tactic': getattr(rule, 'MitreTactic', None),
                'mitre_technique': getattr(rule, 'MitreTechnique', None),
                'detected_at': datetime.now().isoformat(),
                'risk_score': self._get_rule_risk_score(rule),
                'confidence': 0.8,
                'recommendations': [
                    f"Review rule: {getattr(rule, 'RuleName', 'Unknown')}",
                    "Investigate suspicious activity",
                    "Consider additional monitoring"
                ]
            }
        except Exception as e:
            logger.error(f"Rule notification creation failed: {str(e)}")
            return {
                'type': 'rule_detection',
                'title': 'Rule Detection Error',
                'severity': 'Medium',
                'detected_at': datetime.now().isoformat()
            }
    
    def _create_threat_notification(self, event: Event, threat) -> Dict:
        """MODIFIED: Create notification for threat match (not alert)"""
        try:
            return {
                'type': 'threat_intelligence',
                'event_id': event.EventID,
                'threat_id': threat.ThreatID,
                'threat_name': threat.ThreatName,
                'threat_type': threat.ThreatType,
                'title': f"Threat Detected: {threat.ThreatName}",
                'description': f"Threat intelligence match: {threat.ThreatName} - {threat.Description or 'No description'}",
                'severity': threat.Severity,
                'category': getattr(threat, 'ThreatCategory', 'Unknown'),
                'mitre_tactic': getattr(threat, 'MitreTactic', None),
                'mitre_technique': getattr(threat, 'MitreTechnique', None),
                'detected_at': datetime.now().isoformat(),
                'confidence': float(threat.Confidence) if threat.Confidence else 0.7,
                'source': getattr(threat, 'ThreatSource', 'Internal'),
                'recommendations': [
                    "Immediate investigation required",
                    "Consider endpoint isolation",
                    "Review threat intelligence data",
                    "Check for lateral movement"
                ]
            }
        except Exception as e:
            logger.error(f"Threat notification creation failed: {str(e)}")
            return {
                'type': 'threat_intelligence',
                'title': 'Threat Detection Error',
                'severity': 'High',
                'detected_at': datetime.now().isoformat()
            }
    
    async def _send_detection_notifications_to_agent(self, session: Session, agent_id: str, notifications: List[Dict]) -> bool:
        """MODIFIED: Send detection notifications to agent (not alerts)"""
        try:
            if not notifications:
                return True
            
            # Get agent information
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.warning(f"Agent not found for notification: {agent_id}")
                return False
            
            # Store notifications in system config for agent to retrieve
            from ..models.system_config import SystemConfig
            import json
            
            for notification in notifications:
                try:
                    # Create notification record
                    notification_record = {
                        'agent_id': agent_id,
                        'notification_type': notification.get('type', 'detection'),
                        'notification_data': notification,
                        'sent_at': datetime.now().isoformat(),
                        'status': 'pending'
                    }
                    
                    # Store in system config as temporary notification
                    config_key = f"agent_notification_{agent_id}_{notification.get('type', 'det')}_{int(datetime.now().timestamp())}"
                    config_value = json.dumps(notification_record)
                    
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
    
    # Keep existing helper methods unchanged
    def _evaluate_simple_rule(self, event: Event, rule) -> bool:
        """Simple rule evaluation without complex conditions"""
        try:
            if not hasattr(rule, 'get_rule_condition'):
                return False
                
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                return False
            
            # Simple rule evaluation
            if isinstance(rule_condition, dict):
                for field, expected_value in rule_condition.items():
                    if field in ['logic', 'description']:
                        continue
                    
                    # Map rule field to event field
                    event_field = self._map_rule_field_to_event(field)
                    event_value = getattr(event, event_field, None)
                    
                    if event_value and self._check_value_match(event_value, expected_value):
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Simple rule evaluation failed: {str(e)}")
            return False
    
    def _map_rule_field_to_event(self, rule_field: str) -> str:
        """Map rule field names to event model fields"""
        field_mapping = {
            'process_name': 'ProcessName',
            'command_line': 'CommandLine',
            'file_name': 'FileName',
            'file_path': 'FilePath',
            'file_hash': 'FileHash',
            'process_hash': 'ProcessHash',
            'destination_ip': 'DestinationIP',
            'source_ip': 'SourceIP',
            'destination_port': 'DestinationPort',
            'registry_key': 'RegistryKey',
            'login_user': 'LoginUser'
        }
        return field_mapping.get(rule_field, rule_field)
    
    def _check_value_match(self, event_value: str, expected_value) -> bool:
        """Check if event value matches expected value"""
        try:
            if isinstance(expected_value, list):
                return any(str(val).lower() in str(event_value).lower() for val in expected_value)
            else:
                return str(expected_value).lower() in str(event_value).lower()
        except:
            return False
    
    def _get_rule_risk_score(self, rule) -> int:
        """Get risk score for rule"""
        try:
            severity_scores = {
                'Low': 15,
                'Medium': 30,
                'High': 60,
                'Critical': 85
            }
            severity = getattr(rule, 'AlertSeverity', 'Medium')
            base_score = severity_scores.get(severity, 30)
            priority = getattr(rule, 'Priority', 50) or 50
            priority_multiplier = priority / 100
            return int(base_score * priority_multiplier)
        except:
            return 30
    
    def _check_simple_threats(self, session: Session, event: Event) -> List[int]:
        """Simple threat intelligence check"""
        try:
            if not Threat:
                return []
                
            threat_matches = []
            
            # Check file hashes
            if hasattr(event, 'FileHash') and event.FileHash:
                threat = Threat.check_hash(session, event.FileHash)
                if threat:
                    threat_matches.append(threat.ThreatID)
                    logger.info(f"🚨 Threat hash match: {event.FileHash} -> {threat.ThreatName}")
            
            if hasattr(event, 'ProcessHash') and event.ProcessHash:
                threat = Threat.check_hash(session, event.ProcessHash)
                if threat:
                    threat_matches.append(threat.ThreatID)
                    logger.info(f"🚨 Threat process hash match: {event.ProcessHash} -> {threat.ThreatName}")
            
            # Check IPs
            if hasattr(event, 'DestinationIP') and event.DestinationIP:
                threat = Threat.check_ip(session, event.DestinationIP)
                if threat:
                    threat_matches.append(threat.ThreatID)
                    logger.info(f"🚨 Threat IP match: {event.DestinationIP} -> {threat.ThreatName}")
            
            return threat_matches
            
        except Exception as e:
            logger.error(f"Threat check failed: {str(e)}")
            return []
    
    def _create_event_from_request(self, event_data: EventSubmissionRequest) -> Optional[Event]:
        """Create Event model instance from request data"""
        try:
            # Create base event
            event = Event.create_event(
                agent_id=event_data.agent_id,
                event_type=event_data.event_type.value,
                event_action=event_data.event_action,
                event_timestamp=event_data.event_timestamp,
                Severity=event_data.severity.value
            )
            
            # Set event-specific fields based on type
            if event_data.event_type.value == 'Process':
                event.ProcessID = event_data.process_id
                event.ProcessName = event_data.process_name
                event.ProcessPath = event_data.process_path
                event.CommandLine = event_data.command_line
                event.ParentPID = event_data.parent_pid
                event.ParentProcessName = event_data.parent_process_name
                event.ProcessUser = event_data.process_user
                event.ProcessHash = event_data.process_hash
            
            elif event_data.event_type.value == 'File':
                event.FilePath = event_data.file_path
                event.FileName = event_data.file_name
                event.FileSize = event_data.file_size
                event.FileHash = event_data.file_hash
                event.FileExtension = event_data.file_extension
                event.FileOperation = event_data.file_operation
            
            elif event_data.event_type.value == 'Network':
                event.SourceIP = event_data.source_ip
                event.DestinationIP = event_data.destination_ip
                event.SourcePort = event_data.source_port
                event.DestinationPort = event_data.destination_port
                event.Protocol = event_data.protocol
                event.Direction = event_data.direction
            
            elif event_data.event_type.value == 'Registry':
                event.RegistryKey = event_data.registry_key
                event.RegistryValueName = event_data.registry_value_name
                event.RegistryValueData = event_data.registry_value_data
                event.RegistryOperation = event_data.registry_operation
            
            elif event_data.event_type.value == 'Authentication':
                event.LoginUser = event_data.login_user
                event.LoginType = event_data.login_type
                event.LoginResult = event_data.login_result
            
            # Set raw event data if provided
            if event_data.raw_event_data:
                event.set_raw_data(event_data.raw_event_data)
            
            return event
            
        except Exception as e:
            logger.error(f"Failed to create event from request: {str(e)}")
            return None
    
    # Keep existing methods for backward compatibility
    def get_events_by_agent(self, session: Session, agent_id: str, 
                           hours: int = 24, limit: int = 100) -> List[Event]:
        """Get events for specific agent"""
        try:
            return Event.get_by_agent(session, agent_id, limit)
        except Exception as e:
            logger.error(f"Failed to get events for agent {agent_id}: {str(e)}")
            return []
    
    def get_recent_events(self, session: Session, hours: int = 24, 
                         limit: int = 1000) -> List[Event]:
        """Get recent events across all agents"""
        try:
            return Event.get_recent_events(session, hours, limit)
        except Exception as e:
            logger.error(f"Failed to get recent events: {str(e)}")
            return []
    
    def get_suspicious_events(self, session: Session, hours: int = 24) -> List[Event]:
        """Get events marked as suspicious or malicious"""
        try:
            return Event.get_suspicious_events(session, hours)
        except Exception as e:
            logger.error(f"Failed to get suspicious events: {str(e)}")
            return []
    
    def get_event_statistics(self, session: Session, hours: int = 24) -> Dict:
        """Get comprehensive event statistics"""
        try:
            return Event.get_events_summary(session, hours)
        except Exception as e:
            logger.error(f"Failed to get event statistics: {str(e)}")
            return {}
    
    def get_events_timeline(self, session: Session, hours: int = 24) -> List[Dict]:
        """Get events timeline for dashboard"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            timeline_data = session.query(
                func.date_part('hour', Event.EventTimestamp).label('hour'),
                Event.EventType,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(
                func.date_part('hour', Event.EventTimestamp),
                Event.EventType
            ).order_by('hour').all()
            
            timeline = []
            for hour, event_type, count in timeline_data:
                timeline.append({
                    'hour': int(hour),
                    'event_type': event_type,
                    'count': count
                })
            
            return timeline
            
        except Exception as e:
            logger.error(f"Events timeline failed: {str(e)}")
            return []
    
    def analyze_event_patterns(self, session: Session, agent_id: Optional[str] = None, 
                              hours: int = 24) -> Dict:
        """Analyze event patterns for anomaly detection"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            query = session.query(Event).filter(Event.EventTimestamp >= cutoff_time)
            
            if agent_id:
                query = query.filter(Event.AgentID == agent_id)
            
            events = query.all()
            
            patterns = {
                'total_events': len(events),
                'event_types': {},
                'time_distribution': {},
                'suspicious_patterns': []
            }
            
            # Analyze event types
            for event in events:
                event_type = event.EventType
                patterns['event_types'][event_type] = patterns['event_types'].get(event_type, 0) + 1
            
            # Analyze time patterns
            for event in events:
                hour = event.EventTimestamp.hour
                patterns['time_distribution'][hour] = patterns['time_distribution'].get(hour, 0) + 1
            
            # Look for suspicious patterns
            if patterns['event_types'].get('Process', 0) > 1000:
                patterns['suspicious_patterns'].append('High process activity detected')
            
            if patterns['event_types'].get('Network', 0) > 500:
                patterns['suspicious_patterns'].append('High network activity detected')
            
            return patterns
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {str(e)}")
            return {}
    
    def cleanup_old_events(self, session: Session, retention_days: int = 365) -> Tuple[int, str]:
        """Clean up old events based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # Count events to be deleted
            old_events_count = session.query(Event).filter(
                Event.EventTimestamp < cutoff_date
            ).count()
            
            if old_events_count == 0:
                return 0, "No old events to clean up"
            
            # Delete old events
            deleted_count = session.query(Event).filter(
                Event.EventTimestamp < cutoff_date
            ).delete()
            
            session.commit()
            
            message = f"Cleaned up {deleted_count:,} events older than {retention_days} days"
            logger.info(message)
            
            return deleted_count, message
            
        except Exception as e:
            session.rollback()
            error_msg = f"Event cleanup failed: {str(e)}"
            logger.error(error_msg)
            return 0, error_msg

# Global service instance
event_service = EventService()