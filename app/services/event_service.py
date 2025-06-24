# app/services/event_service.py - FIXED VERSION (Only create alerts for REAL rule/threat matches)
"""
Event Processing Service - FIXED VERSION
Only create alerts when there are ACTUAL rule violations or threat intelligence matches
NO MORE false positive behavioral alerts
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, DataError
import time
import json
import uuid
import re
import ipaddress

from ..models.event import Event
from ..models.agent import Agent
from ..models.alert import Alert
from ..models.detection_rule import DetectionRule  # ADDED: For real rule checking
from ..models.threat import Threat  # ADDED: For real threat checking
from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse
)
from ..config import config

logger = logging.getLogger('event_processing')

class EventService:
    """Event processing service - FIXED: Only create alerts for REAL rule/threat matches"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        
        # Performance counters
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'rule_matches': 0,  # ADDED: Track real rule matches
            'threat_matches': 0,  # ADDED: Track real threat matches
            'alerts_created': 0,
            'behavioral_detections': 0,  # ADDED: Track behavioral (but no alert)
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        
        # Agent cache for ultra-fast lookups
        self.agent_cache = {}
        self.cache_timeout = 300
        
        # Validation cache
        self.validation_cache = {}
        
        # REMOVED: Alert deduplication cache (since we only create for real matches)
        
        logger.info("🛡️ FIXED Event Service - Only REAL rule/threat violations create alerts")
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                          client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """FIXED: Only create alerts for REAL rule/threat matches"""
        start_time = time.time()
        
        try:
            # 1. ULTRA-FAST validation
            if not self._validate_event_ultrafast(event_data):
                return False, None, "Validation failed"
            
            # 2. FAST agent lookup with caching
            agent = self._get_agent_ultrafast(session, event_data.agent_id)
            if not agent or not agent.MonitoringEnabled:
                return False, None, "Agent not found or monitoring disabled"
            
            # 3. IMMEDIATE event creation
            event = self._create_event_ultrafast(event_data, agent)
            if not event:
                return False, None, "Event creation failed"
            
            # 4. IMMEDIATE database storage
            try:
                session.add(event)
                session.flush()  # Get ID immediately
                event_id = event.EventID
                
                logger.info(f"💾 DATABASE INSERT SUCCESS:")
                logger.info(f"   Event ID: {event_id}")
                logger.info(f"   Type: {event.EventType}")
                logger.info(f"   Action: {event.EventAction}")
                logger.info(f"   Agent: {agent.HostName} ({agent.AgentID})")
                logger.info(f"   Severity: {event.Severity}")
                logger.info(f"   Client IP: {client_ip}")
                
                if event.EventType == 'Process' and event.ProcessName:
                    logger.info(f"   Process: {event.ProcessName} (PID: {event.ProcessID})")
                
            except Exception as e:
                session.rollback()
                return False, None, f"Database error: {str(e)}"
            
            # 5. FIXED: REAL detection with database rule/threat checking
            threat_detected = False
            risk_score = 0
            alerts_generated = []
            
            try:
                # FIXED: Check REAL rules and threats from database
                detection_result = await self._check_real_rules_and_threats(session, event, agent)
                threat_detected = detection_result['threat_detected']
                risk_score = detection_result['risk_score']
                
                # Update event with detection results
                event.ThreatLevel = detection_result['threat_level']
                event.RiskScore = risk_score
                event.Analyzed = True
                event.AnalyzedAt = datetime.now()
                
                # FIXED: Only create alert if REAL rule/threat match
                if threat_detected and (detection_result.get('matched_rules') or detection_result.get('matched_threats')):
                    alert = self._create_alert_for_real_violation(session, event, agent, detection_result)
                    if alert:
                        alerts_generated.append({
                            'id': alert.AlertID,
                            'title': alert.Title,
                            'description': alert.Description,
                            'severity': alert.Severity,
                            'risk_score': alert.RiskScore,
                            'timestamp': alert.FirstDetected.isoformat(),
                            'detection_method': alert.DetectionMethod,
                            'rule_ids': detection_result.get('matched_rules', []),
                            'threat_ids': detection_result.get('matched_threats', [])
                        })
                        self.stats['alerts_created'] += 1
                        
                        # Send immediate notification to agent for REAL violations
                        asyncio.create_task(
                            self._send_real_alert_to_agent(session, agent, alert, detection_result)
                        )
                        
                        logger.warning(f"🚨 REAL VIOLATION ALERT: ID={alert.AlertID} for Event {event_id}")
                        logger.warning(f"   Rules: {detection_result.get('matched_rules', [])}")
                        logger.warning(f"   Threats: {detection_result.get('matched_threats', [])}")
                elif detection_result.get('behavioral_indicators'):
                    # Log behavioral detection but DON'T create alert
                    self.stats['behavioral_detections'] += 1
                    logger.info(f"📊 BEHAVIORAL DETECTION (no alert): {event.ProcessName} - {detection_result.get('behavioral_indicators', [])}")
                
            except Exception as e:
                logger.error(f"Detection error: {e}")
                # Continue processing even if detection fails
                event.Analyzed = False
            
            # 6. COMMIT everything
            try:
                session.commit()
                logger.info(f"✅ EVENT COMMITTED: ID={event_id}")
            except Exception as e:
                session.rollback()
                return False, None, f"Commit failed: {str(e)}"
            
            # Update stats
            processing_time = time.time() - start_time
            self.stats['events_processed'] += 1
            self.stats['events_stored'] += 1
            self.stats['processing_time_total'] += processing_time
            
            if threat_detected:
                logger.warning(f"🚨 REAL THREAT EVENT: ID={event_id}, Risk={risk_score}, Rules={len(detection_result.get('matched_rules', []))}, Threats={len(detection_result.get('matched_threats', []))}")
            else:
                logger.info(f"📝 Clean event: ID={event_id}, Type={event.EventType}, Time={processing_time:.3f}s")
            
            response = EventSubmissionResponse(
                success=True,
                message=f"Event processed in {processing_time:.3f}s",
                event_id=event_id,
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=alerts_generated
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Event submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    async def _check_real_rules_and_threats(self, session: Session, event: Event, agent: Agent) -> Dict[str, Any]:
        """FIXED: Check REAL rules and threats from database - NO behavioral alerts"""
        try:
            logger.info(f"🔍 CHECKING REAL RULES AND THREATS:")
            logger.info(f"   Event: {event.EventType} - {event.ProcessName}")
            logger.info(f"   Agent: {agent.HostName}")
            
            detection_result = {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'matched_threats': [],
                'rule_details': [],
                'threat_details': [],
                'behavioral_indicators': []  # Still track but don't create alerts
            }
            
            # 1. CHECK REAL DETECTION RULES from database
            active_rules = session.query(DetectionRule).filter(
                DetectionRule.IsActive == True
            ).all()
            
            logger.info(f"🔍 Checking {len(active_rules)} active detection rules...")
            
            for rule in active_rules:
                try:
                    if self._evaluate_rule_against_event(event, rule):
                        rule_risk = self._get_rule_risk_score(rule)
                        
                        detection_result['matched_rules'].append(rule.RuleID)
                        detection_result['risk_score'] += rule_risk
                        detection_result['detection_methods'].append('Database Rule Match')
                        detection_result['rule_details'].append({
                            'rule_id': rule.RuleID,
                            'rule_name': rule.RuleName,
                            'rule_type': rule.RuleType,
                            'severity': rule.AlertSeverity,
                            'alert_title': rule.AlertTitle,
                            'risk_score': rule_risk
                        })
                        
                        self.stats['rule_matches'] += 1
                        logger.warning(f"🎯 REAL RULE MATCH: {rule.RuleName} (ID: {rule.RuleID}, Risk: +{rule_risk})")
                        
                except Exception as e:
                    logger.error(f"Rule evaluation error for rule {rule.RuleID}: {e}")
                    continue
            
            # 2. CHECK REAL THREAT INTELLIGENCE from database
            threat_matches = 0
            
            # Check file hashes
            if event.ProcessHash:
                threat = Threat.check_hash(session, event.ProcessHash)
                if threat:
                    threat_risk = self._get_threat_risk_score(threat)
                    detection_result['matched_threats'].append(threat.ThreatID)
                    detection_result['risk_score'] += threat_risk
                    detection_result['detection_methods'].append('Threat Intelligence')
                    detection_result['threat_details'].append({
                        'threat_id': threat.ThreatID,
                        'threat_name': threat.ThreatName,
                        'threat_type': threat.ThreatType,
                        'severity': threat.Severity,
                        'risk_score': threat_risk,
                        'matched_field': 'ProcessHash'
                    })
                    threat_matches += 1
                    self.stats['threat_matches'] += 1
                    logger.warning(f"🚨 THREAT HASH MATCH: {threat.ThreatName} (ID: {threat.ThreatID})")
            
            if event.FileHash:
                threat = Threat.check_hash(session, event.FileHash)
                if threat:
                    threat_risk = self._get_threat_risk_score(threat)
                    detection_result['matched_threats'].append(threat.ThreatID)
                    detection_result['risk_score'] += threat_risk
                    detection_result['detection_methods'].append('Threat Intelligence')
                    detection_result['threat_details'].append({
                        'threat_id': threat.ThreatID,
                        'threat_name': threat.ThreatName,
                        'threat_type': threat.ThreatType,
                        'severity': threat.Severity,
                        'risk_score': threat_risk,
                        'matched_field': 'FileHash'
                    })
                    threat_matches += 1
                    self.stats['threat_matches'] += 1
                    logger.warning(f"🚨 THREAT FILE HASH: {threat.ThreatName} (ID: {threat.ThreatID})")
            
            # Check IP addresses
            for ip_field in ['SourceIP', 'DestinationIP']:
                ip_value = getattr(event, ip_field, None)
                if ip_value and not self._is_private_ip(ip_value):
                    threat = Threat.check_ip(session, ip_value)
                    if threat:
                        threat_risk = self._get_threat_risk_score(threat)
                        detection_result['matched_threats'].append(threat.ThreatID)
                        detection_result['risk_score'] += threat_risk
                        detection_result['detection_methods'].append('Threat Intelligence')
                        detection_result['threat_details'].append({
                            'threat_id': threat.ThreatID,
                            'threat_name': threat.ThreatName,
                            'threat_type': threat.ThreatType,
                            'severity': threat.Severity,
                            'risk_score': threat_risk,
                            'matched_field': ip_field
                        })
                        threat_matches += 1
                        self.stats['threat_matches'] += 1
                        logger.warning(f"🚨 MALICIOUS IP: {ip_value} -> {threat.ThreatName}")
            
            # 3. BEHAVIORAL ANALYSIS (for logging only, NO alerts)
            behavioral_indicators = self._analyze_behavior_no_alerts(event)
            if behavioral_indicators:
                detection_result['behavioral_indicators'] = behavioral_indicators
                detection_result['detection_methods'].append('Behavioral Analysis')
                logger.info(f"📊 BEHAVIORAL INDICATORS: {behavioral_indicators} (NO ALERT)")
            
            # 4. DETERMINE FINAL RESULT - ONLY create alert if REAL matches
            rule_matches = len(detection_result['matched_rules'])
            threat_matches = len(detection_result['matched_threats'])
            
            if rule_matches > 0 or threat_matches > 0:
                detection_result['threat_detected'] = True
                
                # Determine threat level based on risk score
                if detection_result['risk_score'] >= 80:
                    detection_result['threat_level'] = 'Malicious'
                elif detection_result['risk_score'] >= 60:
                    detection_result['threat_level'] = 'High'
                elif detection_result['risk_score'] >= 40:
                    detection_result['threat_level'] = 'Medium'
                else:
                    detection_result['threat_level'] = 'Suspicious'
                
                logger.warning(f"🚨 REAL THREAT DETECTED:")
                logger.warning(f"   Rule Matches: {rule_matches}")
                logger.warning(f"   Threat Matches: {threat_matches}")
                logger.warning(f"   Total Risk Score: {detection_result['risk_score']}")
                logger.warning(f"   Threat Level: {detection_result['threat_level']}")
            else:
                # No real rule/threat matches - just behavioral indicators
                detection_result['threat_detected'] = False
                detection_result['threat_level'] = 'None'
                logger.info(f"✅ NO REAL VIOLATIONS - Clean event (behavioral indicators logged)")
            
            return detection_result
            
        except Exception as e:
            logger.error(f"Real threat detection failed: {str(e)}")
            return {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'matched_threats': [],
                'rule_details': [],
                'threat_details': [],
                'behavioral_indicators': []
            }
    
    def _evaluate_rule_against_event(self, event: Event, rule: DetectionRule) -> bool:
        """Evaluate detection rule against event using actual rule conditions"""
        try:
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                return False
            
            logger.debug(f"Evaluating rule {rule.RuleName}: {rule_condition}")
            
            # Check if rule applies to this event type
            if rule_condition.get('event_type') and rule_condition['event_type'] != event.EventType:
                return False
            
            # Evaluate rule conditions
            if 'conditions' in rule_condition:
                return self._evaluate_rule_conditions(event, rule_condition['conditions'], rule_condition.get('logic', 'AND'))
            else:
                # Legacy format
                return self._evaluate_legacy_conditions(event, rule_condition)
                
        except Exception as e:
            logger.error(f"Rule evaluation failed for rule {rule.RuleID}: {e}")
            return False
    
    def _evaluate_rule_conditions(self, event: Event, conditions: List[Dict], logic: str) -> bool:
        """Evaluate rule conditions array"""
        try:
            matches = []
            
            for condition in conditions:
                field = condition.get('field')
                operator = condition.get('operator', 'equals')
                value = condition.get('value')
                
                if not field:
                    continue
                
                # Map field to event attribute
                event_value = getattr(event, self._map_field_name(field), None)
                
                # Apply operator
                match = self._apply_operator(event_value, operator, value)
                matches.append(match)
                
                logger.debug(f"Condition: {field}({event_value}) {operator} {value} = {match}")
            
            if not matches:
                return False
            
            # Apply logic
            if logic.upper() == 'OR':
                return any(matches)
            else:  # AND
                return all(matches)
                
        except Exception as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False
    
    def _evaluate_legacy_conditions(self, event: Event, rule_condition: Dict) -> bool:
        """Evaluate legacy rule format"""
        try:
            # Legacy format direct field checks
            for field, expected_value in rule_condition.items():
                if field == 'event_type':
                    continue
                
                event_value = getattr(event, self._map_field_name(field), None)
                if not self._apply_operator(event_value, 'equals', expected_value):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Legacy condition evaluation failed: {e}")
            return False
    
    def _apply_operator(self, event_value: Any, operator: str, expected_value: Any) -> bool:
        """Apply operator to compare event value with expected value"""
        try:
            if event_value is None:
                return False
            
            event_str = str(event_value).lower()
            expected_str = str(expected_value).lower()
            
            if operator == 'equals':
                return event_str == expected_str
            elif operator == 'contains':
                return expected_str in event_str
            elif operator == 'starts_with':
                return event_str.startswith(expected_str)
            elif operator == 'ends_with':
                return event_str.endswith(expected_str)
            elif operator == 'regex':
                return bool(re.search(expected_str, event_str, re.IGNORECASE))
            elif operator == 'in':
                if isinstance(expected_value, list):
                    return event_str in [str(v).lower() for v in expected_value]
                else:
                    return event_str == expected_str
            else:
                # Default to equals
                return event_str == expected_str
                
        except Exception as e:
            logger.error(f"Operator application failed: {e}")
            return False
    
    def _map_field_name(self, field: str) -> str:
        """Map rule field to event attribute"""
        mapping = {
            'process_name': 'ProcessName',
            'process_path': 'ProcessPath', 
            'command_line': 'CommandLine',
            'file_name': 'FileName',
            'file_path': 'FilePath',
            'source_ip': 'SourceIP',
            'destination_ip': 'DestinationIP',
            'registry_key': 'RegistryKey',
            'event_type': 'EventType',
            'event_action': 'EventAction'
        }
        return mapping.get(field, field)
    
    def _get_rule_risk_score(self, rule: DetectionRule) -> int:
        """Get risk score for rule based on severity"""
        severity_mapping = {
            'Critical': 100,
            'High': 80,
            'Medium': 60,
            'Low': 40,
            'Info': 20
        }
        return severity_mapping.get(rule.AlertSeverity, 40)
    
    def _get_threat_risk_score(self, threat: Threat) -> int:
        """Get risk score for threat based on severity"""
        severity_mapping = {
            'Critical': 100,
            'High': 80,
            'Medium': 60,
            'Low': 40,
            'Info': 20
        }
        return severity_mapping.get(threat.Severity, 40)
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
            
        except ValueError:
            return True  # Invalid IP, treat as private
    
    def _analyze_behavior_no_alerts(self, event: Event) -> List[str]:
        """Analyze behavior for logging only - NO alerts created"""
        indicators = []
        
        try:
            if event.EventType == 'Process' and event.ProcessName:
                process_name = event.ProcessName.lower()
                
                # High-risk processes (for logging)
                if process_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']:
                    indicators.append(f"High-risk process: {process_name}")
                
                # Common processes (for logging)
                elif process_name in ['notepad.exe', 'calc.exe', 'python.exe']:
                    indicators.append(f"Common process: {process_name}")
                
                # Command line analysis (for logging)
                if event.CommandLine:
                    cmd_lower = event.CommandLine.lower()
                    if any(pattern in cmd_lower for pattern in ['base64', 'invoke-expression', 'downloadstring']):
                        indicators.append("Suspicious command pattern")
            
            # Log behavioral indicators but don't create alerts
            if indicators:
                logger.info(f"📊 BEHAVIORAL ANALYSIS: {indicators}")
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
        
        return indicators
    
    def _create_alert_for_real_violation(self, session: Session, event: Event, agent: Agent, detection_result: Dict) -> Optional[Alert]:
        """Create alert only for REAL rule/threat violations"""
        try:
            rule_details = detection_result.get('rule_details', [])
            threat_details = detection_result.get('threat_details', [])
            
            # Determine alert title and description based on matches
            if rule_details:
                primary_rule = rule_details[0]
                title = primary_rule['alert_title'] or f"Rule Violation: {primary_rule['rule_name']}"
                description = f"Detection rule '{primary_rule['rule_name']}' triggered for process {event.ProcessName or 'Unknown'}"
                detection_method = f"Rule: {primary_rule['rule_name']}"
                severity = primary_rule['severity']
            elif threat_details:
                primary_threat = threat_details[0]
                title = f"Threat Detected: {primary_threat['threat_name']}"
                description = f"Known threat '{primary_threat['threat_name']}' detected in {primary_threat['matched_field']}"
                detection_method = f"Threat Intel: {primary_threat['threat_name']}"
                severity = primary_threat['severity']
            else:
                # Should not happen but safety check
                return None
            
            # Add additional context
            if len(rule_details) > 1:
                description += f" (+ {len(rule_details) - 1} more rules)"
            if len(threat_details) > 1:
                description += f" (+ {len(threat_details) - 1} more threats)"
            
            alert = Alert(
                AgentID=agent.AgentID,
                EventID=event.EventID,
                RuleID=rule_details[0]['rule_id'] if rule_details else None,
                ThreatID=threat_details[0]['threat_id'] if threat_details else None,
                AlertType='Security Violation',
                Title=title,
                Description=description,
                Severity=severity,
                Priority=severity,  # Map severity to priority
                DetectionMethod=detection_method,
                RiskScore=detection_result['risk_score'],
                Status='Open',
                FirstDetected=datetime.now(),
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            session.add(alert)
            session.flush()
            
            logger.warning(f"✅ REAL VIOLATION ALERT CREATED:")
            logger.warning(f"   Alert ID: {alert.AlertID}")
            logger.warning(f"   Title: {title}")
            logger.warning(f"   Severity: {severity}")
            logger.warning(f"   Rules: {len(rule_details)}")
            logger.warning(f"   Threats: {len(threat_details)}")
            
            return alert
            
        except Exception as e:
            logger.error(f"Real violation alert creation failed: {e}")
            return None
    
    async def _send_real_alert_to_agent(self, session: Session, agent: Agent, alert: Alert, detection_result: Dict):
        """Send alert notification for REAL violations only"""
        try:
            # Import here to avoid circular imports
            from ..services.agent_communication_service import agent_communication_service
            from ..database import db_manager
            
            # Create detailed notification for REAL violation
            notification = {
                'type': 'security_rule_violation',
                'alert_id': alert.AlertID,
                'title': alert.Title,
                'description': alert.Description,
                'severity': alert.Severity,
                'risk_score': alert.RiskScore,
                'agent_id': str(alert.AgentID),
                'timestamp': datetime.now().isoformat(),
                'violation_type': 'REAL_RULE_VIOLATION' if detection_result.get('matched_rules') else 'THREAT_INTELLIGENCE',
                'rule_count': len(detection_result.get('matched_rules', [])),
                'threat_count': len(detection_result.get('matched_threats', [])),
                'rule_details': detection_result.get('rule_details', []),
                'threat_details': detection_result.get('threat_details', []),
                'action_required': True,
                'priority': 'HIGH'
            }
            
            # Use new session to avoid conflicts
            try:
                with db_manager.get_realtime_session() as new_session:
                    success = await agent_communication_service.send_detection_notifications_to_agent(
                        new_session, str(alert.AgentID), [notification]
                    )
                    
                    if success:
                        logger.warning(f"📤 REAL VIOLATION NOTIFICATION sent to {agent.HostName}: Alert {alert.AlertID}")
                    else:
                        logger.error(f"Failed to send real violation notification to {agent.HostName}")
                        
            except Exception as session_error:
                logger.error(f"Session error in real violation notification: {session_error}")
                
        except Exception as e:
            logger.error(f"Real violation notification failed: {e}")
    
    # Helper methods (unchanged from original)
    def _validate_event_ultrafast(self, event_data: EventSubmissionRequest) -> bool:
        """Ultra-fast validation with caching"""
        try:
            cache_key = f"{event_data.event_type}_{event_data.severity}"
            if cache_key in self.validation_cache:
                return True
            
            if not event_data.agent_id or not event_data.event_type or not event_data.event_action:
                return False
            
            try:
                uuid.UUID(event_data.agent_id)
            except ValueError:
                return False
            
            self.validation_cache[cache_key] = True
            return True
            
        except Exception:
            return False
    
    def _get_agent_ultrafast(self, session: Session, agent_id: str) -> Optional[Agent]:
        """Ultra-fast agent lookup with aggressive caching"""
        cache_key = f"agent_{agent_id}"
        current_time = time.time()
        
        if cache_key in self.agent_cache:
            cached_agent, cache_time = self.agent_cache[cache_key]
            if current_time - cache_time < self.cache_timeout:
                return cached_agent
        
        agent = Agent.get_by_id(session, agent_id)
        if agent:
            self.agent_cache[cache_key] = (agent, current_time)
        
        return agent
    
    def _create_event_ultrafast(self, event_data: EventSubmissionRequest, agent: Agent) -> Optional[Event]:
        """Ultra-fast event creation with minimal validation"""
        try:
            event_type = event_data.event_type.value if hasattr(event_data.event_type, 'value') else str(event_data.event_type)
            severity = event_data.severity.value if hasattr(event_data.severity, 'value') else str(event_data.severity)
            
            event = Event.create_event(
                agent_id=str(agent.AgentID),
                event_type=event_type,
                event_action=event_data.event_action[:50],
                event_timestamp=event_data.event_timestamp,
                Severity=severity
            )
            
            # Set event-specific fields based on type
            if event_type == 'Process':
                event.ProcessID = event_data.process_id
                event.ProcessName = event_data.process_name[:255] if event_data.process_name else None
                event.ProcessPath = event_data.process_path[:500] if event_data.process_path else None
                event.CommandLine = event_data.command_line
                event.ParentPID = event_data.parent_pid
                event.ProcessUser = event_data.process_user[:100] if event_data.process_user else None
                event.ProcessHash = event_data.process_hash[:128] if event_data.process_hash else None
            
            elif event_type == 'File':
                event.FilePath = event_data.file_path[:500] if event_data.file_path else None
                event.FileName = event_data.file_name[:255] if event_data.file_name else None
                event.FileSize = event_data.file_size
                event.FileHash = event_data.file_hash[:128] if event_data.file_hash else None
            
            elif event_type == 'Network':
                event.SourceIP = event_data.source_ip[:45] if event_data.source_ip else None
                event.DestinationIP = event_data.destination_ip[:45] if event_data.destination_ip else None
                event.SourcePort = event_data.source_port
                event.DestinationPort = event_data.destination_port
                event.Protocol = event_data.protocol[:10] if event_data.protocol else None
            
            elif event_type == 'Registry':
                event.RegistryKey = event_data.registry_key[:500] if event_data.registry_key else None
                event.RegistryValue = event_data.registry_value_name[:255] if event_data.registry_value_name else None
                event.RegistryData = event_data.registry_value_data
            
            # Additional fields that apply to multiple event types
            event.UserName = event_data.process_user[:100] if event_data.process_user else None
            event.EventDetails = str(event_data.raw_event_data) if event_data.raw_event_data else None
            
            return event
            
        except Exception as e:
            logger.error(f"Event creation failed: {e}")
            return None
    
    async def submit_batch_events(self, session: Session, batch_data: EventBatchRequest,
                                 client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """Process batch of events - FIXED: Only create alerts for REAL violations"""
        start_time = time.time()
        batch_size = len(batch_data.events)
        
        if batch_size > self.max_batch_size:
            return False, None, f"Batch size {batch_size} exceeds maximum {self.max_batch_size}"
        
        logger.info(f"🚀 PROCESSING BATCH: {batch_size} events from {client_ip}")
        
        results = []
        alerts_generated = []
        errors = []
        
        try:
            for i, event_data in enumerate(batch_data.events):
                try:
                    success, response, error = await self.submit_event(session, event_data, client_ip)
                    
                    if success:
                        results.append({
                            'index': i,
                            'success': True,
                            'event_id': response.event_id,
                            'threat_detected': response.threat_detected,
                            'risk_score': response.risk_score
                        })
                        
                        # Collect all alerts from this event
                        if response.alerts_generated:
                            alerts_generated.extend(response.alerts_generated)
                            
                    else:
                        results.append({
                            'index': i,
                            'success': False,
                            'error': error
                        })
                        errors.append(f"Event {i}: {error}")
                        
                except Exception as e:
                    error_msg = f"Event {i} processing failed: {str(e)}"
                    results.append({
                        'index': i,
                        'success': False,
                        'error': error_msg
                    })
                    errors.append(error_msg)
                    logger.error(f"❌ {error_msg}")
            
            # Calculate batch statistics
            successful_events = sum(1 for r in results if r['success'])
            failed_events = len(results) - successful_events
            total_risk_score = sum(r.get('risk_score', 0) for r in results if r['success'])
            threats_detected = sum(1 for r in results if r.get('threat_detected', False))
            
            processing_time = time.time() - start_time
            
            logger.info(f"✅ BATCH COMPLETED:")
            logger.info(f"   Total Events: {batch_size}")
            logger.info(f"   Successful: {successful_events}")
            logger.info(f"   Failed: {failed_events}")
            logger.info(f"   Threats Detected: {threats_detected}")
            logger.info(f"   Alerts Generated: {len(alerts_generated)}")
            logger.info(f"   Processing Time: {processing_time:.3f}s")
            logger.info(f"   Events/sec: {batch_size/processing_time:.1f}")
            
            # Create batch response
            batch_response = EventBatchResponse(
                success=failed_events == 0,
                message=f"Batch processed: {successful_events}/{batch_size} events successful",
                total_events=batch_size,
                successful_events=successful_events,
                failed_events=failed_events,
                threats_detected=threats_detected,
                total_risk_score=total_risk_score,
                alerts_generated=alerts_generated,
                processing_time=processing_time,
                events_per_second=batch_size/processing_time if processing_time > 0 else 0,
                results=results,
                errors=errors if errors else None
            )
            
            return True, batch_response, None
                
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Batch processing failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        current_time = datetime.now()
        uptime = (current_time - self.stats['last_reset']).total_seconds()
        
        stats = self.stats.copy()
        stats.update({
            'uptime_seconds': uptime,
            'events_per_second': stats['events_processed'] / uptime if uptime > 0 else 0,
            'avg_processing_time': stats['processing_time_total'] / stats['events_processed'] if stats['events_processed'] > 0 else 0,
            'rule_match_rate': stats['rule_matches'] / stats['events_processed'] if stats['events_processed'] > 0 else 0,
            'threat_match_rate': stats['threat_matches'] / stats['events_processed'] if stats['events_processed'] > 0 else 0,
            'alert_rate': stats['alerts_created'] / stats['events_processed'] if stats['events_processed'] > 0 else 0,
            'behavioral_detection_rate': stats['behavioral_detections'] / stats['events_processed'] if stats['events_processed'] > 0 else 0,
            'cache_size': len(self.agent_cache),
            'validation_cache_size': len(self.validation_cache)
        })
        
        return stats
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'rule_matches': 0,
            'threat_matches': 0,
            'alerts_created': 0,
            'behavioral_detections': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        logger.info("📊 Statistics reset")
    
    def clear_caches(self):
        """Clear all caches"""
        self.agent_cache.clear()
        self.validation_cache.clear()
        logger.info("🧹 Caches cleared")

    # Additional helper methods for backward compatibility
    def get_events_by_agent(self, session: Session, agent_id: str, hours: int = 24, limit: int = 100) -> List[Event]:
        """Get events for specific agent with optimized query"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            return session.query(Event).filter(
                Event.AgentID == agent_id,
                Event.EventTimestamp >= cutoff_time
            ).order_by(Event.EventTimestamp.desc()).limit(limit).all()
        except Exception as e:
            logger.error(f"Get events by agent failed: {e}")
            return []
    
    def get_suspicious_events(self, session: Session, hours: int = 24) -> List[Event]:
        """Get suspicious events with optimized query"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            return session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
            ).order_by(Event.RiskScore.desc()).all()
        except Exception as e:
            logger.error(f"Get suspicious events failed: {e}")
            return []
    
    def get_events_timeline(self, session: Session, hours: int = 24) -> List[Dict]:
        """Get events timeline for dashboard"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Use SQL Server's DATEPART for better performance
            from sqlalchemy import text
            timeline_data = session.execute(text("""
                SELECT 
                    DATEPART(hour, EventTimestamp) as hour,
                    EventType,
                    Severity,
                    COUNT(*) as event_count
                FROM Events 
                WHERE EventTimestamp >= :cutoff_time
                GROUP BY DATEPART(hour, EventTimestamp), EventType, Severity
                ORDER BY hour
            """), {'cutoff_time': cutoff_time}).fetchall()
            
            return [
                {
                    'hour': row.hour,
                    'event_type': row.EventType,
                    'severity': row.Severity,
                    'count': row.event_count
                }
                for row in timeline_data
            ]
        except Exception as e:
            logger.error(f"Timeline query failed: {e}")
            return []
    
    def get_event_statistics(self, session: Session, hours: int = 24) -> Optional[Dict]:
        """Get comprehensive event statistics"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Basic counts
            total_events = session.query(Event).filter(Event.EventTimestamp >= cutoff_time).count()
            analyzed_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.Analyzed == True
            ).count()
            suspicious_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
            ).count()
            
            # Event type breakdown
            type_breakdown = session.query(
                Event.EventType,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(Event.EventType).all()
            
            # Severity breakdown
            severity_breakdown = session.query(
                Event.Severity,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(Event.Severity).all()
            
            return {
                'total_events': total_events,
                'analyzed_events': analyzed_events,
                'suspicious_events': suspicious_events,
                'analysis_rate': round((analyzed_events / total_events * 100) if total_events > 0 else 0, 2),
                'threat_detection_rate': round((suspicious_events / total_events * 100) if total_events > 0 else 0, 2),
                'events_per_hour': total_events // hours if hours > 0 else 0,
                'type_breakdown': {event_type: count for event_type, count in type_breakdown},
                'severity_breakdown': {severity: count for severity, count in severity_breakdown},
                'time_range_hours': hours
            }
            
        except Exception as e:
            logger.error(f"Statistics calculation failed: {e}")
            return None
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get service performance statistics"""
        try:
            uptime = datetime.now() - self.stats['last_reset']
            avg_processing_time = (self.stats['processing_time_total'] / 
                                 max(self.stats['events_processed'], 1))
            
            return {
                'events_processed': self.stats['events_processed'],
                'events_stored': self.stats['events_stored'],
                'alerts_created': self.stats['alerts_created'],
                'rule_matches': self.stats['rule_matches'],
                'threat_matches': self.stats['threat_matches'],
                'behavioral_detections': self.stats['behavioral_detections'],
                'average_processing_time_ms': round(avg_processing_time * 1000, 2),
                'events_per_second': round(self.stats['events_processed'] / max(uptime.total_seconds(), 1), 2),
                'alert_creation_rate': round((self.stats['alerts_created'] / max(self.stats['events_processed'], 1)) * 100, 2),
                'uptime_seconds': int(uptime.total_seconds()),
                'cache_size': len(self.agent_cache)
            }
        except Exception as e:
            logger.error(f"Performance stats failed: {e}")
            return {}
    

def get_event_service() -> EventService:
    """Get the global event service instance"""
    return event_service

# Create global service instance
event_service = EventService()