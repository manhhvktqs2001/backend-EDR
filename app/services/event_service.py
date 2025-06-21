# app/services/event_service.py - FIXED IMPORTS VERSION
"""
Event Processing Service - FIXED imports and detection integration
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
from ..models.alert import Alert

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
    """Service for processing and managing events - FIXED"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        self.detection_enabled = (DETECTION_AVAILABLE and 
                                self.detection_config.get('rules_enabled', False))
    
    def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                    client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """Submit single event for processing - FIXED"""
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
            
            # FIXED: Process event through detection engine if available
            alerts_generated = []
            threat_detected = False
            risk_score = 0
            
            if self.detection_enabled:
                try:
                    # FIXED: Use simple detection without async issues
                    detection_results = self._run_simple_detection(session, event)
                    if detection_results:
                        threat_detected = detection_results.get('threat_detected', False)
                        risk_score = detection_results.get('risk_score', 0)
                        alerts_generated = detection_results.get('alerts_generated', [])
                        
                        # Update event with detection results
                        event.update_analysis(
                            threat_level=detection_results.get('threat_level', 'None'),
                            risk_score=risk_score
                        )
                        
                        if threat_detected:
                            logger.warning(f"⚠️ Threat detected in event {event.EventID}: "
                                         f"Risk={risk_score}, Level={detection_results.get('threat_level')}")
                        
                except Exception as e:
                    logger.error(f"Detection engine error for event {event.EventID}: {str(e)}")
                    # Continue processing even if detection fails
            else:
                # Set basic analysis if detection not available
                event.update_analysis(threat_level='None', risk_score=0)
            
            session.commit()
            
            logger.debug(f"Event processed: ID={event.EventID}, Type={event.EventType}, Agent={agent.HostName}")
            
            # FIXED: Clean alert IDs for response
            alert_ids = []
            if detection_results and detection_results.get('alerts_generated'):
                alert_ids = [
                    alert.get('alert_id') for alert in detection_results['alerts_generated'] 
                    if alert and alert.get('alert_id') is not None
                ]

            response = EventSubmissionResponse(
                success=True,
                message="Event processed successfully",
                event_id=event.EventID,
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=alert_ids  # Use the cleaned list
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            error_msg = f"Event submission failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    async def submit_event_batch(self, session: Session, batch_data: EventBatchRequest,
                          client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """Submit batch of events for processing - FIXED"""
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
            alerts_generated = []
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
                    
                    # FIXED: Run detection if enabled and available
                    if self.detection_enabled:
                        try:
                            detection_results = self._run_simple_detection(session, event)
                            if detection_results:
                                if detection_results.get('alerts_generated'):
                                    alerts_generated.extend(detection_results['alerts_generated'])
                                
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
                logger.warning(f"⚠️ Threats detected: {threats_detected}/{processed_events} events, "
                             f"Avg risk: {avg_risk:.1f}, Alerts: {len(alerts_generated)}")
            
            # FIXED: Clean all alert IDs for batch response
            all_alert_ids = []
            for alert_list in alerts_generated:
                if isinstance(alert_list, list):
                    for alert in alert_list:
                        if alert and alert.get('alert_id') is not None:
                            all_alert_ids.append(alert['alert_id'])

            # NEW: Send alerts to agent if threats detected
            if all_alert_ids:
                try:
                    await self._send_alerts_to_agent(session, batch_data.agent_id, alerts_generated)
                except Exception as e:
                    logger.error(f"Failed to send alerts to agent: {str(e)}")

            response = EventBatchResponse(
                success=True,
                message=f"Batch processed: {processed_events} events",
                total_events=len(batch_data.events),
                processed_events=processed_events,
                failed_events=failed_events,
                alerts_generated=all_alert_ids,  # Use the cleaned list
                errors=errors
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            error_msg = f"Event batch submission failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def _run_simple_detection(self, session: Session, event: Event) -> Optional[Dict]:
        """
        FIXED: Simple detection without async complications
        """
        try:
            if not DETECTION_AVAILABLE:
                logger.debug("Detection models not available")
                return None
            
            detection_results = {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'alerts_generated': [],
                'detection_methods': ['Simple Detection'],
                'matched_rules': [],
                'matched_threats': []
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
                            
                            logger.info(f"🔍 Rule matched: {rule.RuleName} for event {event.EventID}")
                            
                            # Create alert for matched rule
                            try:
                                alert = self._create_simple_alert(session, event, rule)
                                if alert:
                                    detection_results['alerts_generated'].append(alert.AlertID)
                                    session.add(alert)
                            except Exception as e:
                                logger.error(f"Failed to create alert for rule {rule.RuleID}: {e}")
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
                except Exception as e:
                    logger.error(f"Threat checking failed: {e}")
            
            # Determine threat level
            risk_score = min(detection_results['risk_score'], 100)
            detection_results['risk_score'] = risk_score
            
            if risk_score >= 80:
                detection_results['threat_level'] = 'Critical'
            elif risk_score >= 60:
                detection_results['threat_level'] = 'High'
            elif risk_score >= 40:
                detection_results['threat_level'] = 'Medium'
            elif risk_score >= 20:
                detection_results['threat_level'] = 'Low'
            else:
                detection_results['threat_level'] = 'None'
            
            # Mark as threat detected if significant risk
            risk_threshold = self.detection_config.get('risk_score_threshold', 70)
            if risk_score >= risk_threshold:
                detection_results['threat_detected'] = True
            
            if detection_results['threat_detected']:
                logger.warning(f"⚠️ Threat detected in event {event.EventID}: "
                             f"Risk={risk_score}, Level={detection_results['threat_level']}, "
                             f"Rules={len(detection_results['matched_rules'])}, "
                             f"Threats={len(detection_results['matched_threats'])}")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"Simple detection failed: {str(e)}")
            return None
    
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
    
    def _create_simple_alert(self, session: Session, event: Event, rule):
        """Create simple alert for matched rule"""
        try:
            alert = Alert(
                EventID=event.EventID,
                AgentID=event.AgentID,
                RuleID=getattr(rule, 'RuleID', None),
                AlertType=getattr(rule, 'AlertType', 'Rule Detection'),
                Title=getattr(rule, 'AlertTitle', f"Rule Detection: {getattr(rule, 'RuleName', 'Unknown')}"),
                Description=getattr(rule, 'AlertDescription', f"Rule '{getattr(rule, 'RuleName', 'Unknown')}' triggered"),
                Severity=getattr(rule, 'AlertSeverity', 'Medium'),
                Priority=getattr(rule, 'AlertSeverity', 'Medium'),
                DetectionMethod='Rule Engine',
                MitreTactic=getattr(rule, 'MitreTactic', None),
                MitreTechnique=getattr(rule, 'MitreTechnique', None),
                Status='Open',
                FirstDetected=datetime.now(),
                LastDetected=datetime.now(),
                EventCount=1,
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            logger.info(f"🚨 Alert created: {getattr(rule, 'RuleName', 'Unknown')} -> {getattr(rule, 'AlertSeverity', 'Medium')}")
            return alert
            
        except Exception as e:
            logger.error(f"Simple alert creation failed: {str(e)}")
            return None
    
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
    
    # Rest of the methods remain unchanged...
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

    def _run_detection_engine_sync(self, session: Session, event: Event) -> Optional[Dict]:
        """
        Run detection engine synchronously - FIXED
        """
        try:
            from ..services.detection_engine import detection_engine
            
            # Create a new event loop if needed
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            
            if loop is None:
                # No running loop, create one
                return asyncio.run(detection_engine.analyze_event(session, event))
            else:
                # Running in async context, use thread pool
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        lambda: asyncio.run(detection_engine.analyze_event(session, event))
                    )
                    return future.result(timeout=30)  # 30 second timeout
                    
        except Exception as e:
            logger.error(f"Detection engine execution failed: {str(e)}")
            # Return minimal response instead of None
            return {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'alerts_generated': [],
                'detection_methods': [],
                'analysis_error': str(e)
            }

    async def _process_automated_responses(self, session: Session, event: Event, detection_results: Dict):
        """Process automated responses for detected threats - NEW"""
        try:
            if not detection_results.get('threat_detected'):
                return
            
            # Import agent communication service
            from ..services.agent_communication_service import agent_communication_service
            
            # Get all alerts generated
            alerts = detection_results.get('alerts_generated', [])
            
            for alert_data in alerts:
                if not alert_data or not alert_data.get('alert_id'):
                    continue
                
                # Get the actual alert from database
                alert = session.query(Alert).filter(Alert.AlertID == alert_data['alert_id']).first()
                if not alert:
                    continue
                
                # Execute automated response
                response_actions = await agent_communication_service.execute_automated_response(session, alert)
                
                # Log response actions
                if response_actions:
                    alert.add_response_action(f"Automated responses: {', '.join(response_actions)}")
                    logger.info(f"🤖 Automated responses executed for Alert {alert.AlertID}: {len(response_actions)} actions")
            
            session.commit()
            
        except Exception as e:
            logger.error(f"Automated response processing failed: {str(e)}")

    async def _send_alerts_to_agent(self, session: Session, agent_id: str, alerts: List[Dict]) -> bool:
        """Send alerts back to the agent for display - NEW"""
        try:
            if not alerts:
                return True
            
            # Get agent information
            agent = Agent.get_by_id(session, agent_id)
            if not agent:
                logger.warning(f"Agent not found for alert notification: {agent_id}")
                return False
            
            # Prepare alert data for agent
            alert_notifications = []
            for alert_data in alerts:
                if not alert_data or not alert_data.get('alert_id'):
                    continue
                
                # Get full alert details from database
                alert = session.query(Alert).filter(Alert.AlertID == alert_data['alert_id']).first()
                if not alert:
                    continue
                
                # Create notification payload
                notification = {
                    'alert_id': alert.AlertID,
                    'rule_name': getattr(alert, 'RuleName', 'Unknown Rule'),
                    'alert_type': alert.AlertType,
                    'title': alert.Title,
                    'description': alert.Description,
                    'severity': alert.Severity,
                    'risk_score': alert.RiskScore,
                    'detection_method': alert.DetectionMethod,
                    'mitre_tactic': alert.MitreTactic,
                    'mitre_technique': alert.MitreTechnique,
                    'timestamp': alert.CreatedAt.isoformat() if alert.CreatedAt else datetime.now().isoformat(),
                    'event_id': alert.EventID,
                    'priority': alert.Priority,
                    'confidence': float(alert.Confidence) if alert.Confidence else 0.5
                }
                alert_notifications.append(notification)
            
            if not alert_notifications:
                return True
            
            # Send to agent via agent communication service
            from ..services.agent_communication_service import agent_communication_service
            
            success = await agent_communication_service.send_alerts_to_agent(
                session, agent_id, alert_notifications
            )
            
            if success:
                logger.info(f"📤 Sent {len(alert_notifications)} alerts to agent {agent.HostName}")
            else:
                logger.warning(f"⚠️ Failed to send alerts to agent {agent.HostName}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to send alerts to agent: {str(e)}")
            return False

# Global service instance
event_service = EventService()