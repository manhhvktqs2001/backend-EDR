# app/services/detection_engine.py - COMPLETELY FIXED
"""
Detection Engine - COMPLETELY FIXED FOR NOTEPAD.EXE RULE
Fixed rule matching logic, operators, and field mapping
"""

import logging
import json
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func
import asyncio

from ..models.agent import Agent
from ..models.event import Event
from ..models.threat import Threat
from ..models.detection_rule import DetectionRule
from ..models.alert import Alert
from ..config import config

logger = logging.getLogger('detection_engine')

class DetectionEngine:
    """FIXED Detection engine for rule matching and alert creation"""
    
    def __init__(self):
        self.detection_config = config['detection']
        self.alert_config = config['alert']
        
        # FIXED: Complete operator implementations
        self.supported_operators = {
            'equals': self._op_equals,
            'iequals': self._op_iequals,  # Case insensitive equals
            'contains': self._op_contains,
            'icontains': self._op_icontains,  # Case insensitive contains
            'not_equals': self._op_not_equals,
            'not_contains': self._op_not_contains,
            'starts_with': self._op_starts_with,
            'ends_with': self._op_ends_with,
            'regex': self._op_regex,
            'in': self._op_in,
            'not_in': self._op_not_in,
            'exists': self._op_exists,
            'not_exists': self._op_not_exists
        }
        
        # Performance stats
        self.stats = {
            'events_analyzed': 0,
            'rules_matched': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'total_processing_time': 0.0
        }
        
        logger.info("🔍 FIXED Detection Engine - Ready for rule matching")
    
    # =============================================================================
    # FIXED OPERATOR IMPLEMENTATIONS
    # =============================================================================
    
    def _op_equals(self, event_value: Any, expected_value: Any) -> bool:
        """Exact match (case sensitive)"""
        if event_value is None:
            return expected_value is None
        return str(event_value) == str(expected_value)
    
    def _op_iequals(self, event_value: Any, expected_value: Any) -> bool:
        """Case insensitive exact match - PERFECT for notepad.exe"""
        if event_value is None:
            return expected_value is None
        return str(event_value).lower() == str(expected_value).lower()
    
    def _op_contains(self, event_value: Any, expected_value: Any) -> bool:
        """Contains comparison (case sensitive)"""
        if event_value is None:
            return False
        return str(expected_value) in str(event_value)
    
    def _op_icontains(self, event_value: Any, expected_value: Any) -> bool:
        """Case insensitive contains"""
        if event_value is None:
            return False
        return str(expected_value).lower() in str(event_value).lower()
    
    def _op_not_equals(self, event_value: Any, expected_value: Any) -> bool:
        """Not equals"""
        return not self._op_equals(event_value, expected_value)
    
    def _op_not_contains(self, event_value: Any, expected_value: Any) -> bool:
        """Not contains"""
        return not self._op_contains(event_value, expected_value)
    
    def _op_starts_with(self, event_value: Any, expected_value: Any) -> bool:
        """Starts with"""
        if event_value is None:
            return False
        return str(event_value).startswith(str(expected_value))
    
    def _op_ends_with(self, event_value: Any, expected_value: Any) -> bool:
        """Ends with"""
        if event_value is None:
            return False
        return str(event_value).endswith(str(expected_value))
    
    def _op_regex(self, event_value: Any, expected_value: Any) -> bool:
        """Regex match"""
        if event_value is None:
            return False
        try:
            return bool(re.search(str(expected_value), str(event_value), re.IGNORECASE))
        except re.error:
            return False
    
    def _op_in(self, event_value: Any, expected_value: List) -> bool:
        """In list"""
        if event_value is None:
            return None in expected_value
        if not isinstance(expected_value, list):
            expected_value = [expected_value]
        return str(event_value) in [str(v) for v in expected_value]
    
    def _op_not_in(self, event_value: Any, expected_value: List) -> bool:
        """Not in list"""
        return not self._op_in(event_value, expected_value)
    
    def _op_exists(self, event_value: Any, expected_value: Any) -> bool:
        """Field exists"""
        return event_value is not None and str(event_value).strip() != ""
    
    def _op_not_exists(self, event_value: Any, expected_value: Any) -> bool:
        """Field not exists"""
        return not self._op_exists(event_value, expected_value)
    
    # =============================================================================
    # MAIN DETECTION METHOD - FIXED
    # =============================================================================
    
    async def analyze_event_and_create_alerts(self, session: Session, event: Event) -> Dict[str, Any]:
        """FIXED: Main analysis method with proper rule matching"""
        start_time = datetime.now()
        
        try:
            logger.info(f"🔍 ANALYZING EVENT {event.EventID}:")
            logger.info(f"   Type: {event.EventType}")
            logger.info(f"   Action: {event.EventAction}")
            
            if event.EventType == 'Process' and event.ProcessName:
                logger.info(f"   Process: {event.ProcessName}")
                logger.info(f"   Path: {event.ProcessPath}")
                logger.info(f"   Command: {event.CommandLine}")
                
                # Special logging for notepad.exe
                if 'notepad.exe' in event.ProcessName.lower():
                    logger.warning(f"🎯 NOTEPAD.EXE DETECTED IN EVENT {event.EventID}:")
                    logger.warning(f"   Process: {event.ProcessName}")
                    logger.warning(f"   Path: {event.ProcessPath}")
                    logger.warning(f"   This should trigger rule detection!")
            
            self.stats['events_analyzed'] += 1
            
            detection_results = {
                'event_id': event.EventID,
                'agent_id': str(event.AgentID),
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'matched_threats': [],
                'alerts_created': [],
                'notifications_sent': [],
                'rule_details': [],
                'threat_details': [],
                'behavioral_indicators': [],
                # Add process information for agent notification
                'event_type': event.EventType,
                'process_name': event.ProcessName,
                'process_path': event.ProcessPath,
                'command_line': event.CommandLine,
                'process_id': event.ProcessID
            }
            
            # Get agent
            agent = session.query(Agent).filter(Agent.AgentID == event.AgentID).first()
            if not agent:
                logger.warning(f"Agent not found for event {event.EventID}")
                return detection_results
            
            # STEP 1: Check detection rules - FIXED
            rules_results = await self._check_detection_rules_fixed(session, event, agent)
            if rules_results:
                detection_results = self._merge_results(detection_results, rules_results)
                self.stats['rules_matched'] += len(rules_results.get('matched_rules', []))
            
            # STEP 2: Check threat intelligence
            threat_results = await self._check_threat_intelligence(session, event)
            if threat_results:
                detection_results = self._merge_results(detection_results, threat_results)
            
            # STEP 3: Calculate final risk score
            detection_results['risk_score'] = self._calculate_risk_score(detection_results)
            detection_results['threat_level'] = self._determine_threat_level(detection_results['risk_score'])
            
            # STEP 4: Create alerts and send notifications
            if detection_results['matched_rules'] or detection_results['matched_threats']:
                detection_results['threat_detected'] = True
                
                # CREATE ALERT
                alert = await self._create_alert_for_detection(session, event, agent, detection_results)
                if alert:
                    detection_results['alerts_created'].append({
                        'alert_id': alert.AlertID,
                        'title': alert.Title,
                        'description': alert.Description or 'Alert generated by detection engine',
                        'severity': alert.Severity,
                        'detection_method': alert.DetectionMethod
                    })
                    self.stats['alerts_created'] += 1
                    
                    logger.warning(f"🚨 ALERT CREATED: {alert.AlertID} - {alert.Title}")
                    
                    # SEND NOTIFICATION TO AGENT
                    notification_sent = await self._send_notification_to_agent(session, agent, alert, detection_results)
                    if notification_sent:
                        detection_results['notifications_sent'].append(notification_sent)
                        self.stats['notifications_sent'] += 1
                        logger.warning(f"📤 NOTIFICATION SENT to {agent.HostName}")
            
            # STEP 5: Update event with results
            event.RiskScore = detection_results['risk_score']
            event.Analyzed = True
            event.AnalyzedAt = datetime.now()
            
            # Set ThreatLevel to None to avoid constraint error
            event.ThreatLevel = None
            
            processing_time = (datetime.now() - start_time).total_seconds()
            self.stats['total_processing_time'] += processing_time
            
            logger.info(f"✅ ANALYSIS COMPLETE: Event {event.EventID} (Risk: {detection_results['risk_score']}, Time: {processing_time:.3f}s)")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"💥 Detection analysis failed: {str(e)}")
            return detection_results
    
    async def _check_detection_rules_fixed(self, session: Session, event: Event, agent: Agent) -> Optional[Dict]:
        """FIXED: Detection rules check with proper rule evaluation"""
        try:
            if not self.detection_config.get('rules_enabled', False):
                logger.debug("Rules detection disabled")
                return None
            
            # Get active rules
            active_rules = session.query(DetectionRule).filter(
                DetectionRule.IsActive == True
            ).all()
            
            logger.info(f"🔍 Checking {len(active_rules)} active rules...")
            
            # OPTIMIZATION: Only check notepad.exe rule for Process events with process_name
            if event.EventType == 'Process' and event.ProcessName:
                logger.info(f"🎯 PROCESS EVENT DETECTED: {event.ProcessName}")
                
                # Special logging for notepad.exe
                if 'notepad.exe' in event.ProcessName.lower():
                    logger.warning(f"🚨 NOTEPAD.EXE PROCESS DETECTED!")
                    logger.warning(f"   Event ID: {event.EventID}")
                    logger.warning(f"   Process: {event.ProcessName}")
                    logger.warning(f"   Path: {event.ProcessPath}")
                    logger.warning(f"   Command: {event.CommandLine}")
                    logger.warning(f"   This should trigger rule detection!")
            
            results = {
                'detection_methods': ['Rule Engine'],
                'matched_rules': [],
                'rule_details': [],
                'risk_score': 0
            }
            
            for rule in active_rules:
                try:
                    logger.debug(f"🧪 Testing rule: {rule.RuleName} (ID: {rule.RuleID})")
                    
                    # OPTIMIZATION: Skip notepad.exe rule for non-Process events
                    if (rule.RuleName == 'Notepad Execution Test' and 
                        event.EventType != 'Process'):
                        logger.debug(f"⏭️ Skipping notepad rule for {event.EventType} event")
                        continue
                    
                    # FIXED: Enhanced rule evaluation
                    if self._evaluate_rule_fixed(event, rule):
                        rule_risk = self._get_rule_risk_score(rule)
                        
                        results['matched_rules'].append(rule.RuleID)
                        results['risk_score'] += rule_risk
                        results['rule_details'].append({
                            'rule_id': rule.RuleID,
                            'rule_name': rule.RuleName,
                            'rule_type': rule.RuleType,
                            'severity': rule.AlertSeverity,
                            'alert_title': rule.AlertTitle,
                            'alert_description': rule.AlertDescription,
                            'risk_score': rule_risk,
                            'mitre_tactic': rule.MitreTactic,
                            'mitre_technique': rule.MitreTechnique
                        })
                        
                        logger.warning(f"🎯 RULE MATCHED: {rule.RuleName} (Risk: +{rule_risk})")
                        
                        # Special logging for notepad.exe rule match
                        if rule.RuleName == 'Notepad Execution Test':
                            logger.warning(f"🚨 NOTEPAD.EXE RULE MATCHED!")
                            logger.warning(f"   Event ID: {event.EventID}")
                            logger.warning(f"   Process: {event.ProcessName}")
                            logger.warning(f"   Risk Score: {rule_risk}")
                            logger.warning(f"   Alert: {rule.AlertTitle}")
                        
                except Exception as e:
                    logger.error(f"Rule evaluation error for rule {rule.RuleID}: {e}")
                    continue
            
            if results['matched_rules']:
                logger.warning(f"✅ {len(results['matched_rules'])} RULES MATCHED!")
                return results
            else:
                logger.info("❌ No rules matched")
                return None
                
        except Exception as e:
            logger.error(f"Detection rules check failed: {str(e)}")
            return None
    
    def _evaluate_rule_fixed(self, event: Event, rule: DetectionRule) -> bool:
        """FIXED: Rule evaluation with proper condition parsing"""
        try:
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                logger.debug(f"Rule {rule.RuleID} has no condition")
                return False
            
            logger.debug(f"Rule condition for {rule.RuleName}: {rule_condition}")
            
            # FIXED: Handle both new and legacy formats
            if isinstance(rule_condition, dict):
                # Check if it's the legacy simple format (like notepad.exe rule)
                if 'process_name' in rule_condition and 'logic' in rule_condition:
                    return self._evaluate_legacy_rule_fixed(event, rule_condition)
                # Or new format with conditions array
                elif 'conditions' in rule_condition:
                    return self._evaluate_new_format_rule(event, rule_condition)
                # Direct field matching
                else:
                    return self._evaluate_direct_fields(event, rule_condition)
            
            return False
            
        except Exception as e:
            logger.error(f"Rule evaluation failed for rule {rule.RuleID}: {str(e)}")
            return False
    
    def _evaluate_legacy_rule_fixed(self, event: Event, rule_condition: Dict) -> bool:
        """FIXED: Evaluate legacy rule format (notepad.exe style)"""
        try:
            logic = rule_condition.get('logic', 'AND').upper()
            
            matches = []
            
            # Check each condition field
            for field, expected_value in rule_condition.items():
                if field == 'logic':
                    continue
                
                # FIXED: Map rule field to event attribute
                event_field = self._map_rule_field_fixed(field)
                event_value = getattr(event, event_field, None)
                
                logger.debug(f"Checking: {field} -> {event_field}")
                logger.debug(f"Event value: {event_value}")
                logger.debug(f"Expected: {expected_value}")
                
                # Special logging for notepad.exe rule only
                if field == 'process_name' and 'notepad.exe' in str(expected_value).lower():
                    logger.warning(f"🎯 NOTEPAD.EXE RULE CHECK:")
                    logger.warning(f"   Field: {field} -> {event_field}")
                    logger.warning(f"   Event value: {event_value}")
                    logger.warning(f"   Expected: {expected_value}")
                
                # FIXED: Use case-insensitive equals for process names
                if field == 'process_name':
                    match = self._op_iequals(event_value, expected_value)
                else:
                    match = self._op_equals(event_value, expected_value)
                
                matches.append(match)
                
                # Special logging for notepad.exe match result only
                if field == 'process_name' and 'notepad.exe' in str(expected_value).lower():
                    logger.warning(f"   Match result: {match}")
                    if match:
                        logger.warning(f"   ✅ NOTEPAD.EXE MATCHED!")
                
                logger.debug(f"Match result: {match}")
            
            if not matches:
                return False
            
            # Apply logic
            if logic == 'OR':
                result = any(matches)
            else:  # AND
                result = all(matches)
            
            logger.debug(f"Final rule result ({logic}): {result}")
            return result
            
        except Exception as e:
            logger.error(f"Legacy rule evaluation failed: {str(e)}")
            return False
    
    def _evaluate_new_format_rule(self, event: Event, rule_condition: Dict) -> bool:
        """Evaluate new format rule with conditions array"""
        try:
            conditions = rule_condition.get('conditions', [])
            logic = rule_condition.get('logic', 'AND').upper()
            
            matches = []
            
            for condition in conditions:
                field = condition.get('field')
                operator = condition.get('operator', 'equals')
                value = condition.get('value')
                
                if not field:
                    continue
                
                event_field = self._map_rule_field_fixed(field)
                event_value = getattr(event, event_field, None)
                
                if operator in self.supported_operators:
                    match = self.supported_operators[operator](event_value, value)
                    matches.append(match)
                    logger.debug(f"Condition: {field}({event_value}) {operator} {value} = {match}")
            
            if not matches:
                return False
            
            if logic == 'OR':
                return any(matches)
            else:
                return all(matches)
                
        except Exception as e:
            logger.error(f"New format rule evaluation failed: {str(e)}")
            return False
    
    def _evaluate_direct_fields(self, event: Event, rule_condition: Dict) -> bool:
        """Evaluate direct field matching"""
        try:
            for field, expected_value in rule_condition.items():
                event_field = self._map_rule_field_fixed(field)
                event_value = getattr(event, event_field, None)
                
                if not self._op_iequals(event_value, expected_value):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Direct field evaluation failed: {str(e)}")
            return False
    
    def _map_rule_field_fixed(self, field: str) -> str:
        """FIXED: Map rule field to event model field"""
        mapping = {
            # Process fields - FIXED
            'process_name': 'ProcessName',
            'process_path': 'ProcessPath',
            'command_line': 'CommandLine',
            'process_id': 'ProcessID',
            'parent_pid': 'ParentPID',
            'parent_process_name': 'ParentProcessName',
            'process_user': 'ProcessUser',
            'process_hash': 'ProcessHash',
            
            # File fields
            'file_name': 'FileName',
            'file_path': 'FilePath',
            'file_hash': 'FileHash',
            'file_size': 'FileSize',
            'file_extension': 'FileExtension',
            'file_operation': 'FileOperation',
            
            # Network fields
            'source_ip': 'SourceIP',
            'destination_ip': 'DestinationIP',
            'source_port': 'SourcePort',
            'destination_port': 'DestinationPort',
            'protocol': 'Protocol',
            'direction': 'Direction',
            
            # Registry fields
            'registry_key': 'RegistryKey',
            'registry_value_name': 'RegistryValueName',
            'registry_value_data': 'RegistryValueData',
            'registry_operation': 'RegistryOperation',
            
            # Authentication fields
            'login_user': 'LoginUser',
            'login_type': 'LoginType',
            'login_result': 'LoginResult',
            
            # Event metadata
            'event_type': 'EventType',
            'event_action': 'EventAction',
            'severity': 'Severity'
        }
        return mapping.get(field, field)
    
    async def _check_threat_intelligence(self, session: Session, event: Event) -> Optional[Dict]:
        """Check threat intelligence (simplified)"""
        try:
            if not self.detection_config.get('threat_intel_enabled', False):
                return None
            
            results = {
                'detection_methods': ['Threat Intelligence'],
                'matched_threats': [],
                'threat_details': [],
                'risk_score': 0
            }
            
            # Check file hashes
            if event.ProcessHash:
                threat = Threat.check_hash(session, event.ProcessHash)
                if threat:
                    threat_risk = self._get_threat_risk_score(threat)
                    results['matched_threats'].append(threat.ThreatID)
                    results['risk_score'] += threat_risk
                    results['threat_details'].append({
                        'threat_id': threat.ThreatID,
                        'threat_name': threat.ThreatName,
                        'threat_type': threat.ThreatType,
                        'severity': threat.Severity,
                        'risk_score': threat_risk
                    })
                    logger.warning(f"🚨 THREAT HASH: {threat.ThreatName}")
            
            return results if results['matched_threats'] else None
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed: {str(e)}")
            return None
    
    async def _create_alert_for_detection(self, session: Session, event: Event, 
                                        agent: Agent, detection_results: Dict) -> Optional[Alert]:
        """FIXED: Create alert for detection"""
        try:
            rule_details = detection_results.get('rule_details', [])
            threat_details = detection_results.get('threat_details', [])
            
            # Determine alert properties
            if rule_details:
                primary_rule = rule_details[0]
                title = primary_rule.get('alert_title', f"Rule Match: {primary_rule['rule_name']}")
                description = primary_rule.get('alert_description', f"Detection rule '{primary_rule['rule_name']}' matched")
                severity = primary_rule.get('severity', 'Medium')
                detection_method = f"Rule: {primary_rule['rule_name']}"
                rule_id = primary_rule.get('rule_id')
                threat_id = None
            elif threat_details:
                primary_threat = threat_details[0]
                title = f"Threat Detected: {primary_threat['threat_name']}"
                description = f"Known threat '{primary_threat['threat_name']}' detected"
                severity = primary_threat.get('severity', 'High')
                detection_method = f"Threat Intel: {primary_threat['threat_name']}"
                rule_id = None
                threat_id = primary_threat.get('threat_id')
            else:
                return None
            
            # Add process context to description
            if event.ProcessName:
                description += f" - Process: {event.ProcessName}"
                if event.ProcessPath:
                    description += f" ({event.ProcessPath})"
            
            # Create alert
            alert = Alert(
                AgentID=agent.AgentID,
                EventID=event.EventID,
                RuleID=rule_id,
                ThreatID=threat_id,
                AlertType='Security Detection',
                Title=title,
                Description=description,
                Severity=severity,
                Priority=severity,
                DetectionMethod=detection_method,
                RiskScore=detection_results['risk_score'],
                Status='Open',
                FirstDetected=datetime.now(),
                LastDetected=datetime.now(),
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            # Add MITRE mapping if available
            if rule_details:
                alert.MitreTactic = rule_details[0].get('mitre_tactic')
                alert.MitreTechnique = rule_details[0].get('mitre_technique')
            
            session.add(alert)
            session.flush()
            
            logger.warning(f"✅ ALERT CREATED: {alert.AlertID} - {title}")
            return alert
            
        except Exception as e:
            logger.error(f"Alert creation failed: {str(e)}")
            return None
    
    async def _send_notification_to_agent(self, session: Session, agent: Agent, 
                                        alert: Alert, detection_results: Dict) -> Optional[str]:
        """FIXED: Send notification to agent"""
        try:
            # Import here to avoid circular imports
            from ..services.agent_communication_service import agent_communication_service
            
            # Create notification
            notification = {
                'type': 'security_detection',
                'alert_id': alert.AlertID,
                'title': alert.Title,
                'description': alert.Description,
                'severity': alert.Severity,
                'risk_score': alert.RiskScore,
                'detection_method': alert.DetectionMethod,
                'agent_id': str(alert.AgentID),
                'agent_hostname': agent.HostName,
                'timestamp': datetime.now().isoformat(),
                'requires_acknowledgment': alert.Severity in ['High', 'Critical'],
                'auto_display': True,
                'notification_type': 'popup',
                'priority': 'HIGH' if alert.Severity in ['High', 'Critical'] else 'MEDIUM'
            }
            
            # Add rule/threat details
            if detection_results.get('rule_details'):
                notification['rule_matched'] = detection_results['rule_details'][0]['rule_name']
            
            if detection_results.get('threat_details'):
                notification['threat_detected'] = detection_results['threat_details'][0]['threat_name']
            
            # Send notification
            success = await agent_communication_service.send_realtime_notification(
                session, str(alert.AgentID), notification
            )
            
            if success:
                notification_id = f"notif_{alert.AlertID}_{int(datetime.now().timestamp())}"
                logger.warning(f"📤 NOTIFICATION SENT: {notification_id} to {agent.HostName}")
                return notification_id
            else:
                logger.error(f"Failed to send notification to {agent.HostName}")
                return None
                
        except Exception as e:
            logger.error(f"Notification sending failed: {str(e)}")
            return None
    
    # =============================================================================
    # UTILITY METHODS
    # =============================================================================
    
    def _get_rule_risk_score(self, rule: DetectionRule) -> int:
        """Get risk score based on rule severity"""
        severity_scores = {
            'Critical': 100,
            'High': 80,
            'Medium': 60,
            'Low': 40,
            'Info': 20
        }
        return severity_scores.get(rule.AlertSeverity, 50)
    
    def _get_threat_risk_score(self, threat: Threat) -> int:
        """Get risk score based on threat severity"""
        severity_scores = {
            'Critical': 100,
            'High': 80,
            'Medium': 60,
            'Low': 40,
            'Info': 20
        }
        return severity_scores.get(threat.Severity, 50)
    
    def _calculate_risk_score(self, detection_results: Dict) -> int:
        """Calculate final risk score"""
        base_score = detection_results.get('risk_score', 0)
        
        # Apply multipliers
        methods_count = len(detection_results.get('detection_methods', []))
        if methods_count > 1:
            base_score = int(base_score * 1.2)
        
        return min(base_score, 100)
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score"""
        if risk_score >= 90:
            return 'Critical'
        elif risk_score >= 70:
            return 'High'
        elif risk_score >= 50:
            return 'Medium'
        elif risk_score >= 30:
            return 'Low'
        else:
            return 'None'
    
    def _merge_results(self, base_results: Dict, new_results: Dict) -> Dict:
        """Merge detection results"""
        for key, value in new_results.items():
            if key in ['detection_methods', 'matched_rules', 'matched_threats', 
                      'rule_details', 'threat_details', 'behavioral_indicators']:
                if key not in base_results:
                    base_results[key] = []
                if isinstance(value, list):
                    base_results[key].extend(value)
                else:
                    base_results[key].append(value)
            elif key == 'risk_score':
                base_results[key] = base_results.get(key, 0) + value
            else:
                base_results[key] = value
        
        return base_results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics"""
        avg_processing_time = 0
        if self.stats['events_analyzed'] > 0:
            avg_processing_time = self.stats['total_processing_time'] / self.stats['events_analyzed']
        
        return {
            'events_analyzed': self.stats['events_analyzed'],
            'rules_matched': self.stats['rules_matched'],
            'alerts_created': self.stats['alerts_created'],
            'notifications_sent': self.stats['notifications_sent'],
            'rule_match_rate': round((self.stats['rules_matched'] / max(self.stats['events_analyzed'], 1)) * 100, 2),
            'alert_creation_rate': round((self.stats['alerts_created'] / max(self.stats['events_analyzed'], 1)) * 100, 2),
            'avg_processing_time_ms': round(avg_processing_time * 1000, 2),
            'supported_operators': list(self.supported_operators.keys())
        }
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'events_analyzed': 0,
            'rules_matched': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'total_processing_time': 0.0
        }
        logger.info("📊 Detection engine statistics reset")

# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

# Global instance
_detection_engine_instance = None

def get_detection_service() -> DetectionEngine:
    """Get singleton detection engine instance"""
    global _detection_engine_instance
    if _detection_engine_instance is None:
        _detection_engine_instance = DetectionEngine()
        logger.info("🔍 Detection Engine singleton created")
    return _detection_engine_instance

# Also create the detection_engine instance for backward compatibility
detection_engine = get_detection_service()