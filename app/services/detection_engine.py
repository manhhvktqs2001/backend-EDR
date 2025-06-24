# app/services/detection_engine.py - COMPLETE FIXED VERSION với Rule Matching Chuẩn
"""
Detection Engine - COMPLETE FIXED VERSION
Core detection logic với rule matching chính xác và đầy đủ operators
Hỗ trợ detect notepad.exe và mọi rule khác một cách chính xác
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
    """Detection engine với rule matching chính xác và operators đầy đủ"""
    
    def __init__(self):
        self.detection_config = config['detection']
        self.alert_config = config['alert']
        self.rules_cache = {}
        self.cache_timestamp = None
        
        # Supported operators for rule matching - COMPLETE AND ACCURATE
        self.supported_operators = {
            'equals': self._op_equals,
            'not_equals': self._op_not_equals,
            'contains': self._op_contains,
            'not_contains': self._op_not_contains,
            'starts_with': self._op_starts_with,
            'ends_with': self._op_ends_with,
            'regex': self._op_regex,
            'in': self._op_in,
            'not_in': self._op_not_in,
            'greater_than': self._op_greater_than,
            'less_than': self._op_less_than,
            'greater_equal': self._op_greater_equal,
            'less_equal': self._op_less_equal,
            'exists': self._op_exists,
            'not_exists': self._op_not_exists,
            'iequals': self._op_iequals,  # Case insensitive equals
            'icontains': self._op_icontains,  # Case insensitive contains
        }
        
        # Performance counters
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'rules_matched': 0,
            'total_processing_time': 0.0
        }
        
        logger.info("🔍 Detection Engine - COMPLETE FIXED: Chính xác rule matching với đầy đủ operators")
    
    # =============================================================================
    # OPERATOR IMPLEMENTATIONS - COMPLETE AND ACCURATE
    # =============================================================================
    
    def _op_equals(self, event_value: Any, expected_value: Any) -> bool:
        """Exact match comparison (case sensitive)"""
        if event_value is None:
            return expected_value is None
        return str(event_value) == str(expected_value)
    
    def _op_iequals(self, event_value: Any, expected_value: Any) -> bool:
        """Case insensitive exact match - PERFECT for notepad.exe"""
        if event_value is None:
            return expected_value is None
        return str(event_value).lower() == str(expected_value).lower()
    
    def _op_not_equals(self, event_value: Any, expected_value: Any) -> bool:
        """Not equals comparison"""
        return not self._op_equals(event_value, expected_value)
    
    def _op_contains(self, event_value: Any, expected_value: Any) -> bool:
        """Contains comparison (case sensitive)"""
        if event_value is None:
            return False
        return str(expected_value) in str(event_value)
    
    def _op_icontains(self, event_value: Any, expected_value: Any) -> bool:
        """Case insensitive contains comparison"""
        if event_value is None:
            return False
        return str(expected_value).lower() in str(event_value).lower()
    
    def _op_not_contains(self, event_value: Any, expected_value: Any) -> bool:
        """Not contains comparison"""
        return not self._op_contains(event_value, expected_value)
    
    def _op_starts_with(self, event_value: Any, expected_value: Any) -> bool:
        """Starts with comparison"""
        if event_value is None:
            return False
        return str(event_value).startswith(str(expected_value))
    
    def _op_ends_with(self, event_value: Any, expected_value: Any) -> bool:
        """Ends with comparison"""
        if event_value is None:
            return False
        return str(event_value).endswith(str(expected_value))
    
    def _op_regex(self, event_value: Any, expected_value: Any) -> bool:
        """Regex match comparison"""
        if event_value is None:
            return False
        try:
            return bool(re.search(str(expected_value), str(event_value), re.IGNORECASE))
        except re.error:
            logger.error(f"Invalid regex pattern: {expected_value}")
            return False
    
    def _op_in(self, event_value: Any, expected_value: List) -> bool:
        """In list comparison"""
        if event_value is None:
            return None in expected_value
        if not isinstance(expected_value, list):
            expected_value = [expected_value]
        return str(event_value) in [str(v) for v in expected_value]
    
    def _op_not_in(self, event_value: Any, expected_value: List) -> bool:
        """Not in list comparison"""
        return not self._op_in(event_value, expected_value)
    
    def _op_greater_than(self, event_value: Any, expected_value: Any) -> bool:
        """Greater than comparison"""
        try:
            return float(event_value) > float(expected_value)
        except (ValueError, TypeError):
            return False
    
    def _op_less_than(self, event_value: Any, expected_value: Any) -> bool:
        """Less than comparison"""
        try:
            return float(event_value) < float(expected_value)
        except (ValueError, TypeError):
            return False
    
    def _op_greater_equal(self, event_value: Any, expected_value: Any) -> bool:
        """Greater than or equal comparison"""
        try:
            return float(event_value) >= float(expected_value)
        except (ValueError, TypeError):
            return False
    
    def _op_less_equal(self, event_value: Any, expected_value: Any) -> bool:
        """Less than or equal comparison"""
        try:
            return float(event_value) <= float(expected_value)
        except (ValueError, TypeError):
            return False
    
    def _op_exists(self, event_value: Any, expected_value: Any) -> bool:
        """Field exists check"""
        return event_value is not None and str(event_value).strip() != ""
    
    def _op_not_exists(self, event_value: Any, expected_value: Any) -> bool:
        """Field not exists check"""
        return not self._op_exists(event_value, expected_value)
    
    # =============================================================================
    # MAIN DETECTION METHODS
    # =============================================================================
    
    async def analyze_event_and_create_alerts(self, session: Session, event: Event) -> Dict[str, Any]:
        """Main analysis method với enhanced rule matching"""
        start_time = datetime.now()
        
        try:
            logger.info(f"🔍 ANALYZING EVENT {event.EventID}: {event.EventType} - {event.EventAction}")
            
            # Log event details for debugging
            if event.EventType == 'Process' and event.ProcessName:
                logger.info(f"   Process Name: {event.ProcessName}")
                logger.info(f"   Process Path: {event.ProcessPath}")
                logger.info(f"   Command Line: {event.CommandLine}")
            
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
                'behavioral_indicators': [],
                'recommendations': [],
                'analysis_time': start_time.isoformat()
            }
            
            # Get agent for context
            agent = session.query(Agent).filter(Agent.AgentID == event.AgentID).first()
            if not agent:
                logger.warning(f"Agent not found for event {event.EventID}")
                return detection_results
            
            # Step 1: Check detection rules với enhanced matching
            rules_results = self._check_detection_rules_enhanced(session, event, agent)
            if rules_results:
                detection_results = self._merge_results(detection_results, rules_results)
                self.stats['rules_matched'] += len(rules_results.get('matched_rules', []))
            
            # Step 2: Check threat intelligence
            threat_results = await self._check_threat_intelligence_async(session, event)
            if threat_results:
                detection_results = self._merge_results(detection_results, threat_results)
                
            # Step 3: Behavioral analysis
            behavioral_results = self._analyze_behavioral_patterns(event)
            if behavioral_results:
                detection_results = self._merge_results(detection_results, behavioral_results)
            
            # Step 4: Calculate final risk score
            detection_results['risk_score'] = self._calculate_risk_score(detection_results)
            detection_results['threat_level'] = self._determine_threat_level(detection_results['risk_score'])
            
            # Step 5: Create alerts if threshold exceeded
            risk_threshold = self.detection_config.get('risk_score_threshold', 50)
            if detection_results['risk_score'] >= risk_threshold:
                detection_results['threat_detected'] = True
                
                # CREATE ALERTS
                alerts_created = await self._create_alerts_for_detections(
                    session, event, agent, detection_results
                )
                detection_results['alerts_created'] = alerts_created
                
                # SEND NOTIFICATIONS to agents
                notifications_sent = await self._send_notifications_to_agent(
                    session, agent, detection_results, alerts_created
                )
                detection_results['notifications_sent'] = notifications_sent
                
                self.stats['alerts_created'] += len(alerts_created)
                self.stats['notifications_sent'] += len(notifications_sent)
                self.stats['threats_detected'] += 1
                
                logger.warning(f"🚨 THREAT DETECTED & ALERTS CREATED:")
                logger.warning(f"   Event: {event.EventID} | Agent: {agent.HostName}")
                logger.warning(f"   Risk Score: {detection_results['risk_score']}")
                logger.warning(f"   Matched Rules: {len(detection_results.get('matched_rules', []))}")
                logger.warning(f"   Alerts Created: {len(alerts_created)}")
                logger.warning(f"   Notifications Sent: {len(notifications_sent)}")
            
            # Step 6: Update event with analysis results
            event.ThreatLevel = detection_results['threat_level']
            event.RiskScore = detection_results['risk_score']
            event.Analyzed = True
            event.AnalyzedAt = datetime.now()
            
            # Step 7: Generate recommendations
            detection_results['recommendations'] = self._generate_recommendations(detection_results)
            
            # Track performance
            processing_time = (datetime.now() - start_time).total_seconds()
            self.stats['total_processing_time'] += processing_time
            detection_results['processing_time_ms'] = round(processing_time * 1000, 2)
            
            logger.info(f"✅ ANALYSIS COMPLETE: Event {event.EventID} "
                       f"(Risk: {detection_results['risk_score']}, "
                       f"Time: {detection_results['processing_time_ms']}ms)")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"💥 Detection analysis failed for event {event.EventID}: {str(e)}")
            return detection_results
    
    def _check_detection_rules_enhanced(self, session: Session, event: Event, agent: Agent) -> Optional[Dict]:
        """ENHANCED detection rules check với chính xác operators"""
        try:
            if not self.detection_config.get('rules_enabled', False):
                logger.debug("Rules detection disabled")
                return None
            
            platform = self._get_platform_from_agent(agent)
            active_rules = self._get_active_rules(session, platform)
            
            logger.info(f"🔍 Checking {len(active_rules)} active rules for platform: {platform}")
            
            results = {
                'detection_methods': ['Enhanced Rules Engine'],
                'matched_rules': [],
                'rule_details': [],
                'risk_score': 0
            }
            
            for rule in active_rules:
                try:
                    logger.debug(f"🧪 Testing rule: {rule.RuleName} (ID: {rule.RuleID})")
                    
                    # Enhanced rule evaluation
                    if self._evaluate_rule_enhanced(event, rule):
                        rule_risk = self._get_rule_risk_score(rule)
                        
                        results['matched_rules'].append(rule.RuleID)
                        results['risk_score'] += rule_risk
                        results['rule_details'].append({
                            'rule_id': rule.RuleID,
                            'rule_name': rule.RuleName,
                            'rule_type': rule.RuleType,
                            'severity': rule.AlertSeverity,
                            'alert_title': rule.AlertTitle,
                            'alert_type': rule.AlertType,
                            'mitre_tactic': rule.MitreTactic,
                            'mitre_technique': rule.MitreTechnique,
                            'risk_score': rule_risk
                        })
                        
                        logger.warning(f"🎯 RULE MATCHED: {rule.RuleName} (Risk: +{rule_risk})")
                        
                        # Log chi tiết rule match
                        logger.info(f"   Rule ID: {rule.RuleID}")
                        logger.info(f"   Rule Type: {rule.RuleType}")
                        logger.info(f"   Alert Title: {rule.AlertTitle}")
                        logger.info(f"   Severity: {rule.AlertSeverity}")
                        
                except Exception as e:
                    logger.error(f"Rule evaluation error for rule {rule.RuleID}: {e}")
                    continue
            
            if results['matched_rules']:
                logger.info(f"✅ Rules matched: {len(results['matched_rules'])}")
            else:
                logger.debug("❌ No rules matched")
            
            return results if results['matched_rules'] else None
            
        except Exception as e:
            logger.error(f"Detection rules check failed: {str(e)}")
            return None
    
    def _evaluate_rule_enhanced(self, event: Event, rule: DetectionRule) -> bool:
        """ENHANCED rule evaluation với chính xác operators"""
        try:
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                logger.debug(f"Rule {rule.RuleID} has no condition")
                return False
            
            logger.debug(f"Rule condition: {rule_condition}")
            
            if isinstance(rule_condition, dict):
                return self._evaluate_rule_conditions_enhanced(event, rule_condition)
            
            return False
            
        except Exception as e:
            logger.error(f"Enhanced rule evaluation failed for rule {rule.RuleID}: {str(e)}")
            return False
    
    def _evaluate_rule_conditions_enhanced(self, event: Event, conditions: Dict) -> bool:
        """ENHANCED rule conditions evaluation với đầy đủ operators"""
        try:
            logic = conditions.get('logic', 'AND').upper()
            
            # Support new condition format
            if 'conditions' in conditions:
                # New format: {"logic": "AND", "conditions": [...]}
                return self._evaluate_conditions_array(event, conditions['conditions'], logic)
            else:
                # Legacy format: {"logic": "AND", "field1": "value1", ...}
                return self._evaluate_conditions_legacy(event, conditions, logic)
                
        except Exception as e:
            logger.error(f"Enhanced condition evaluation failed: {str(e)}")
            return False
    
    def _evaluate_conditions_array(self, event: Event, conditions: List[Dict], logic: str) -> bool:
        """Evaluate new conditions array format với chính xác operators"""
        try:
            matches = []
            
            logger.debug(f"Evaluating {len(conditions)} conditions with logic: {logic}")
            
            for i, condition in enumerate(conditions):
                field = condition.get('field')
                operator = condition.get('operator', 'equals')
                value = condition.get('value')
                
                if not field:
                    logger.warning(f"Condition {i}: Missing field")
                    continue
                
                if operator not in self.supported_operators:
                    logger.warning(f"Condition {i}: Unsupported operator '{operator}'. Supported: {list(self.supported_operators.keys())}")
                    continue
                
                # Map field to event attribute
                event_field = self._map_rule_field(field)
                event_value = getattr(event, event_field, None)
                
                # Execute operator
                operator_func = self.supported_operators[operator]
                match_result = operator_func(event_value, value)
                matches.append(match_result)
                
                logger.debug(f"Condition {i}: {field}({event_value}) {operator} {value} = {match_result}")
            
            if not matches:
                logger.debug("No valid conditions to evaluate")
                return False
            
            # Apply logic
            if logic == 'OR':
                result = any(matches)
            else:  # AND or default
                result = all(matches)
            
            logger.debug(f"Final rule result ({logic}): {result} (matches: {matches})")
            return result
            
        except Exception as e:
            logger.error(f"Conditions array evaluation failed: {str(e)}")
            return False
    
    def _evaluate_conditions_legacy(self, event: Event, conditions: Dict, logic: str) -> bool:
        """Evaluate legacy conditions format"""
        try:
            matches = []
            
            logger.debug(f"Evaluating legacy conditions with logic: {logic}")
            
            for field, expected_value in conditions.items():
                if field == 'logic':
                    continue
                
                # Map field to event attribute
                event_field = self._map_rule_field(field)
                event_value = getattr(event, event_field, None)
                
                # Use appropriate operator based on field type
                if isinstance(expected_value, list):
                    match_result = self._op_in(event_value, expected_value)
                    operator_used = "in"
                else:
                    # Default to case-insensitive equals for legacy compatibility
                    match_result = self._op_iequals(event_value, expected_value)
                    operator_used = "iequals"
                
                matches.append(match_result)
                
                logger.debug(f"Legacy condition: {field}({event_value}) {operator_used} {expected_value} -> {match_result}")
            
            if not matches:
                logger.debug("No valid legacy conditions")
                return False
            
            # Apply logic
            if logic == 'OR':
                result = any(matches)
            else:  # AND or default
                result = all(matches)
            
            logger.debug(f"Legacy rule result ({logic}): {result} (matches: {matches})")
            return result
            
        except Exception as e:
            logger.error(f"Legacy condition evaluation failed: {str(e)}")
            return False
    
    def _map_rule_field(self, field: str) -> str:
        """Map rule field to event model field - COMPLETE MAPPING"""
        mapping = {
            # Process fields
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
            'severity': 'Severity',
            'threat_level': 'ThreatLevel'
        }
        return mapping.get(field, field)
    
    # =============================================================================
    # THREAT INTELLIGENCE & BEHAVIORAL ANALYSIS
    # =============================================================================
    
    async def _check_threat_intelligence_async(self, session: Session, event: Event) -> Optional[Dict]:
        """Async threat intelligence check"""
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
            hash_fields = [
                ('ProcessHash', 'process_hash'),
                ('FileHash', 'file_hash')
            ]
            
            for field_name, field_type in hash_fields:
                hash_value = getattr(event, field_name, None)
                if hash_value:
                    local_threat = Threat.check_hash(session, hash_value)
                    if local_threat:
                        threat_risk = self._get_threat_risk_score(local_threat)
                        
                        results['matched_threats'].append(local_threat.ThreatID)
                        results['risk_score'] += threat_risk
                        results['threat_details'].append({
                            'threat_id': local_threat.ThreatID,
                            'threat_name': local_threat.ThreatName,
                            'threat_type': local_threat.ThreatType,
                            'severity': local_threat.Severity,
                            'field_type': field_type,
                            'field_value': hash_value,
                            'source': 'Local Database',
                            'risk_score': threat_risk
                        })
                        
                        logger.warning(f"🚨 THREAT HASH: {hash_value[:16]}... -> {local_threat.ThreatName} (Risk: +{threat_risk})")
            
            # Check IP addresses
            ip_fields = [
                ('SourceIP', 'source_ip'),
                ('DestinationIP', 'destination_ip')
            ]
            
            for field_name, field_type in ip_fields:
                ip_value = getattr(event, field_name, None)
                if ip_value and not self._is_private_ip(ip_value):
                    local_threat = Threat.check_ip(session, ip_value)
                    if local_threat:
                        threat_risk = self._get_threat_risk_score(local_threat)
                        
                        results['matched_threats'].append(local_threat.ThreatID)
                        results['risk_score'] += threat_risk
                        results['threat_details'].append({
                            'threat_id': local_threat.ThreatID,
                            'threat_name': local_threat.ThreatName,
                            'threat_type': local_threat.ThreatType,
                            'severity': local_threat.Severity,
                            'field_type': field_type,
                            'field_value': ip_value,
                            'source': 'Local Database',
                            'risk_score': threat_risk
                        })
                        
                        logger.warning(f"🚨 MALICIOUS IP: {ip_value} -> {local_threat.ThreatName} (Risk: +{threat_risk})")
            
            return results if results['matched_threats'] else None
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed: {str(e)}")
            return None
    
    def _analyze_behavioral_patterns(self, event: Event) -> Optional[Dict]:
        """Enhanced behavioral analysis"""
        try:
            results = {
                'detection_methods': ['Behavioral Analysis'],
                'behavioral_indicators': [],
                'risk_score': 0
            }
            
            # Process behavior analysis
            if event.EventType == 'Process':
                indicators = self._check_process_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 15
            
            # File behavior analysis
            elif event.EventType == 'File':
                indicators = self._check_file_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 12
            
            # Network behavior analysis
            elif event.EventType == 'Network':
                indicators = self._check_network_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 18
            
            # Registry behavior analysis
            elif event.EventType == 'Registry':
                indicators = self._check_registry_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 10
            
            if results['behavioral_indicators']:
                logger.info(f"🔍 BEHAVIORAL INDICATORS: {len(results['behavioral_indicators'])} found "
                          f"(Risk: +{results['risk_score']})")
            
            return results if results['behavioral_indicators'] else None
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {str(e)}")
            return None
    
    def _check_process_behavior(self, event: Event) -> List[str]:
        """Enhanced process behavior analysis"""
        indicators = []
        
        if not event.ProcessName:
            return indicators
        
        process_name = event.ProcessName.lower()
        command_line = (event.CommandLine or "").lower()
        
        # High-risk processes
        high_risk_processes = [
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'bitsadmin.exe',
            'certutil.exe', 'schtasks.exe', 'at.exe', 'wmic.exe'
        ]
        
        if process_name in high_risk_processes:
            indicators.append(f"High-risk process: {event.ProcessName}")
        
        # Suspicious command patterns
        suspicious_patterns = [
            (r'-encodedcommand', 'PowerShell encoded command'),
            (r'-windowstyle\s+hidden', 'Hidden window execution'),
            (r'-executionpolicy\s+bypass', 'Execution policy bypass'),
            (r'invoke-expression', 'Dynamic code execution'),
            (r'downloadstring', 'Web download in script'),
            (r'base64', 'Base64 encoding detected'),
            (r'certutil.*-urlcache', 'Certutil download'),
            (r'bitsadmin.*\/transfer', 'BITS transfer'),
            (r'net\s+(user|localgroup)', 'User/group manipulation'),
            (r'reg\s+(add|delete|query)', 'Registry manipulation'),
            (r'schtasks.*\/create', 'Scheduled task creation'),
            (r'wmic.*process.*call.*create', 'WMIC process creation')
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, command_line, re.IGNORECASE):
                indicators.append(f"Suspicious command: {description}")
        
        return indicators
    
    def _check_file_behavior(self, event: Event) -> List[str]:
        """Enhanced file behavior analysis"""
        indicators = []
        
        if not event.FilePath:
            return indicators
        
        file_path = event.FilePath.lower()
        file_name = (event.FileName or "").lower()
        
        # Suspicious locations
        suspicious_locations = [
            (r'\\temp\\', 'Temporary directory'),
            (r'\\users\\public\\', 'Public directory'),
            (r'\\appdata\\roaming\\', 'Roaming AppData'),
            (r'\\windows\\temp\\', 'Windows temp'),
            (r'\\programdata\\', 'ProgramData directory'),
            (r'\\startup\\', 'Startup directory'),
            (r'\\system32\\', 'System32 directory')
        ]
        
        for location_pattern, description in suspicious_locations:
            if re.search(location_pattern, file_path, re.IGNORECASE):
                indicators.append(f"Suspicious location: {description}")
        
        # Suspicious file extensions
        suspicious_extensions = [
            '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', 
            '.vbs', '.vbe', '.js', '.jar', '.ps1'
        ]
        
        if file_name:
            for ext in suspicious_extensions:
                if file_name.endswith(ext):
                    indicators.append(f"Executable file: {ext}")
                    break
        
        return indicators
    
    def _check_network_behavior(self, event: Event) -> List[str]:
        """Enhanced network behavior analysis"""
        indicators = []
        
        # Suspicious ports
        if event.DestinationPort:
            suspicious_ports = {
                22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS',
                445: 'SMB', 1433: 'SQL Server', 3389: 'RDP',
                4444: 'Metasploit', 5555: 'Android Debug Bridge',
                6666: 'IRC', 1337: 'Elite/Hacker port', 31337: 'Back Orifice'
            }
            
            if event.DestinationPort in suspicious_ports:
                service = suspicious_ports[event.DestinationPort]
                indicators.append(f"Suspicious port: {event.DestinationPort} ({service})")
        
        # Check for suspicious IPs
        if event.DestinationIP and not self._is_private_ip(event.DestinationIP):
            indicators.append(f"External connection: {event.DestinationIP}")
        
        return indicators
    
    def _check_registry_behavior(self, event: Event) -> List[str]:
        """Enhanced registry behavior analysis"""
        indicators = []
        
        if not event.RegistryKey:
            return indicators
        
        registry_key = event.RegistryKey.lower()
        
        # Suspicious registry locations
        suspicious_keys = [
            (r'\\software\\microsoft\\windows\\currentversion\\run', 'Startup persistence'),
            (r'\\software\\microsoft\\windows\\currentversion\\runonce', 'One-time startup'),
            (r'\\software\\policies\\microsoft\\windows\\system', 'System policies'),
            (r'\\software\\microsoft\\windows\\currentversion\\policies', 'User policies'),
            (r'\\system\\currentcontrolset\\services', 'Service modification'),
            (r'\\software\\microsoft\\windows nt\\currentversion\\winlogon', 'Logon modification'),
            (r'\\software\\classes\\exefile\\shell\\open\\command', 'File association hijack')
        ]
        
        for key_pattern, description in suspicious_keys:
            if re.search(key_pattern, registry_key, re.IGNORECASE):
                indicators.append(f"Suspicious registry: {description}")
        
        return indicators
    
    # =============================================================================
    # UTILITY METHODS
    # =============================================================================
    
    def _get_platform_from_agent(self, agent: Agent) -> str:
        """Get platform from agent"""
        if agent.Platform:
            return agent.Platform.lower()
        elif agent.OS:
            os_name = agent.OS.lower()
            if 'windows' in os_name:
                return 'windows'
            elif 'linux' in os_name:
                return 'linux'
            elif 'mac' in os_name or 'darwin' in os_name:
                return 'macos'
        return 'unknown'
    
    def _get_active_rules(self, session: Session, platform: str = None) -> List[DetectionRule]:
        """Get active detection rules for platform"""
        try:
            query = session.query(DetectionRule).filter(
                DetectionRule.Enabled == True
            )
            
            if platform and platform != 'unknown':
                query = query.filter(
                    (DetectionRule.Platform == platform) | 
                    (DetectionRule.Platform == 'all') |
                    (DetectionRule.Platform.is_(None))
                )
            
            rules = query.all()
            logger.debug(f"Retrieved {len(rules)} active rules for platform: {platform}")
            return rules
            
        except Exception as e:
            logger.error(f"Failed to get active rules: {str(e)}")
            return []
    
    def _get_rule_risk_score(self, rule: DetectionRule) -> int:
        """Get risk score for rule based on severity"""
        severity_scores = {
            'Critical': 80,
            'High': 60,
            'Medium': 40,
            'Low': 20,
            'Info': 10
        }
        return severity_scores.get(rule.AlertSeverity, 30)
    
    def _get_threat_risk_score(self, threat: Threat) -> int:
        """Get risk score for threat based on severity"""
        severity_scores = {
            'Critical': 90,
            'High': 70,
            'Medium': 50,
            'Low': 30,
            'Info': 15
        }
        return severity_scores.get(threat.Severity, 40)
    
    def _calculate_risk_score(self, detection_results: Dict) -> int:
        """Calculate final risk score"""
        base_score = detection_results.get('risk_score', 0)
        
        # Apply multipliers based on number of detection methods
        methods_count = len(detection_results.get('detection_methods', []))
        if methods_count > 1:
            base_score = int(base_score * 1.2)  # 20% bonus for multiple methods
        
        # Cap at 100
        return min(base_score, 100)
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level from risk score"""
        if risk_score >= 80:
            return 'Critical'
        elif risk_score >= 60:
            return 'High'
        elif risk_score >= 40:
            return 'Medium'
        elif risk_score >= 20:
            return 'Low'
        else:
            return 'Info'
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
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
    
    # =============================================================================
    # ALERT CREATION & NOTIFICATION METHODS
    # =============================================================================
    
    async def _create_alerts_for_detections(self, session: Session, event: Event, 
                                          agent: Agent, detection_results: Dict) -> List[str]:
        """Create alerts for detected threats"""
        alerts_created = []
        
        try:
            # Create alerts for matched rules
            for rule_detail in detection_results.get('rule_details', []):
                alert = Alert(
                    AgentID=agent.AgentID,
                    EventID=event.EventID,
                    RuleID=rule_detail.get('rule_id'),
                    AlertType=rule_detail.get('alert_type', 'Detection'),
                    AlertTitle=rule_detail.get('alert_title', 'Security Alert'),
                    AlertMessage=self._generate_alert_message(event, rule_detail, detection_results),
                    Severity=rule_detail.get('severity', 'Medium'),
                    RiskScore=detection_results['risk_score'],
                    Status='Open',
                    Source='Detection Engine',
                    CreatedAt=datetime.now(),
                    UpdatedAt=datetime.now()
                )
                
                session.add(alert)
                session.flush()  # Get the AlertID
                alerts_created.append(str(alert.AlertID))
                
                logger.info(f"✅ Alert created: {alert.AlertID} - {alert.AlertTitle}")
            
            # Create alerts for threat intelligence matches
            for threat_detail in detection_results.get('threat_details', []):
                alert = Alert(
                    AgentID=agent.AgentID,
                    EventID=event.EventID,
                    ThreatID=threat_detail.get('threat_id'),
                    AlertType='Threat Intelligence',
                    AlertTitle=f"Threat Detected: {threat_detail.get('threat_name', 'Unknown')}",
                    AlertMessage=self._generate_threat_alert_message(event, threat_detail),
                    Severity=threat_detail.get('severity', 'High'),
                    RiskScore=detection_results['risk_score'],
                    Status='Open',
                    Source='Threat Intelligence',
                    CreatedAt=datetime.now(),
                    UpdatedAt=datetime.now()
                )
                
                session.add(alert)
                session.flush()
                alerts_created.append(str(alert.AlertID))
                
                logger.info(f"✅ Threat alert created: {alert.AlertID}")
            
            # Commit all alerts
            session.commit()
            
            return alerts_created
            
        except Exception as e:
            logger.error(f"Alert creation failed: {str(e)}")
            session.rollback()
            return []
    
    async def _send_notifications_to_agent(self, session: Session, agent: Agent, 
                                         detection_results: Dict, alert_ids: List[str]) -> List[str]:
        """Send notifications to agent"""
        notifications_sent = []
        
        try:
            if not self.alert_config.get('notifications_enabled', True):
                logger.debug("Notifications disabled")
                return notifications_sent
            
            # Prepare notification data
            notification_data = {
                'agent_id': str(agent.AgentID),
                'agent_hostname': agent.HostName,
                'threat_level': detection_results['threat_level'],
                'risk_score': detection_results['risk_score'],
                'alert_count': len(alert_ids),
                'alert_ids': alert_ids,
                'detection_methods': detection_results.get('detection_methods', []),
                'matched_rules_count': len(detection_results.get('matched_rules', [])),
                'matched_threats_count': len(detection_results.get('matched_threats', [])),
                'behavioral_indicators_count': len(detection_results.get('behavioral_indicators', [])),
                'timestamp': datetime.now().isoformat(),
                'recommendations': detection_results.get('recommendations', [])
            }
            
            # Send to agent management system
            notification_id = await self._send_agent_notification(agent, notification_data)
            if notification_id:
                notifications_sent.append(notification_id)
                logger.info(f"✅ Agent notification sent: {notification_id}")
            
            # Send to SIEM/External systems if configured
            if self.alert_config.get('siem_integration_enabled', False):
                siem_notification_id = await self._send_siem_notification(notification_data)
                if siem_notification_id:
                    notifications_sent.append(siem_notification_id)
                    logger.info(f"✅ SIEM notification sent: {siem_notification_id}")
            
            # Send email notifications if configured
            if self.alert_config.get('email_notifications_enabled', False):
                email_notification_id = await self._send_email_notification(notification_data)
                if email_notification_id:
                    notifications_sent.append(email_notification_id)
                    logger.info(f"✅ Email notification sent: {email_notification_id}")
            
            return notifications_sent
            
        except Exception as e:
            logger.error(f"Notification sending failed: {str(e)}")
            return notifications_sent
    
    async def _send_agent_notification(self, agent: Agent, data: Dict) -> Optional[str]:
        """Send notification to agent management system"""
        try:
            # This would integrate with your agent management system
            # For now, just log the notification
            notification_id = f"agent_notif_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{agent.AgentID}"
            
            logger.info(f"📨 AGENT NOTIFICATION: {notification_id}")
            logger.info(f"   Agent: {agent.HostName} ({agent.AgentID})")
            logger.info(f"   Threat Level: {data['threat_level']}")
            logger.info(f"   Risk Score: {data['risk_score']}")
            logger.info(f"   Alerts: {data['alert_count']}")
            
            return notification_id
            
        except Exception as e:
            logger.error(f"Agent notification failed: {str(e)}")
            return None
    
    async def _send_siem_notification(self, data: Dict) -> Optional[str]:
        """Send notification to SIEM system"""
        try:
            # This would integrate with your SIEM system
            notification_id = f"siem_notif_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            logger.info(f"📡 SIEM NOTIFICATION: {notification_id}")
            
            return notification_id
            
        except Exception as e:
            logger.error(f"SIEM notification failed: {str(e)}")
            return None
    
    async def _send_email_notification(self, data: Dict) -> Optional[str]:
        """Send email notification"""
        try:
            # This would integrate with your email system
            notification_id = f"email_notif_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            logger.info(f"📧 EMAIL NOTIFICATION: {notification_id}")
            
            return notification_id
            
        except Exception as e:
            logger.error(f"Email notification failed: {str(e)}")
            return None
    
    # =============================================================================
    # MESSAGE GENERATION METHODS
    # =============================================================================
    
    def _generate_alert_message(self, event: Event, rule_detail: Dict, detection_results: Dict) -> str:
        """Generate alert message for rule detection"""
        message_parts = [
            f"Security rule '{rule_detail.get('rule_name', 'Unknown')}' triggered.",
            f"Event Type: {event.EventType}",
            f"Event Action: {event.EventAction}",
        ]
        
        if event.EventType == 'Process' and event.ProcessName:
            message_parts.append(f"Process: {event.ProcessName}")
            if event.CommandLine:
                message_parts.append(f"Command: {event.CommandLine}")
        
        if event.EventType == 'File' and event.FilePath:
            message_parts.append(f"File: {event.FilePath}")
        
        if event.EventType == 'Network':
            if event.DestinationIP:
                message_parts.append(f"Destination: {event.DestinationIP}:{event.DestinationPort or 'Unknown'}")
        
        message_parts.append(f"Risk Score: {detection_results['risk_score']}")
        
        if rule_detail.get('mitre_tactic'):
            message_parts.append(f"MITRE Tactic: {rule_detail['mitre_tactic']}")
        
        if rule_detail.get('mitre_technique'):
            message_parts.append(f"MITRE Technique: {rule_detail['mitre_technique']}")
        
        return " | ".join(message_parts)
    
    def _generate_threat_alert_message(self, event: Event, threat_detail: Dict) -> str:
        """Generate alert message for threat intelligence detection"""
        message_parts = [
            f"Known threat '{threat_detail.get('threat_name', 'Unknown')}' detected.",
            f"Threat Type: {threat_detail.get('threat_type', 'Unknown')}",
            f"Field: {threat_detail.get('field_type', 'Unknown')}",
            f"Value: {threat_detail.get('field_value', 'Unknown')}",
            f"Source: {threat_detail.get('source', 'Unknown')}"
        ]
        
        return " | ".join(message_parts)
    
    def _generate_recommendations(self, detection_results: Dict) -> List[str]:
        """Generate security recommendations based on detections"""
        recommendations = []
        
        threat_level = detection_results.get('threat_level', 'Low')
        
        if threat_level in ['Critical', 'High']:
            recommendations.extend([
                "Immediate investigation required",
                "Consider isolating the affected system",
                "Review and validate all recent activities",
                "Check for lateral movement indicators"
            ])
        elif threat_level == 'Medium':
            recommendations.extend([
                "Monitor system for additional suspicious activity",
                "Review security logs for related events",
                "Consider updating security policies"
            ])
        else:
            recommendations.extend([
                "Continue monitoring",
                "Document for trend analysis"
            ])
        
        # Add specific recommendations based on detection methods
        if 'Enhanced Rules Engine' in detection_results.get('detection_methods', []):
            recommendations.append("Review and tune detection rules if needed")
        
        if 'Threat Intelligence' in detection_results.get('detection_methods', []):
            recommendations.append("Update threat intelligence feeds")
        
        if 'Behavioral Analysis' in detection_results.get('detection_methods', []):
            recommendations.append("Review baseline behavioral patterns")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    # =============================================================================
    # STATISTICS & PERFORMANCE METHODS
    # =============================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics"""
        avg_processing_time = 0
        if self.stats['events_analyzed'] > 0:
            avg_processing_time = self.stats['total_processing_time'] / self.stats['events_analyzed']
        
        return {
            'events_analyzed': self.stats['events_analyzed'],
            'threats_detected': self.stats['threats_detected'],
            'alerts_created': self.stats['alerts_created'],
            'notifications_sent': self.stats['notifications_sent'],
            'rules_matched': self.stats['rules_matched'],
            'detection_rate': round(
                (self.stats['threats_detected'] / max(self.stats['events_analyzed'], 1)) * 100, 2
            ),
            'avg_processing_time_ms': round(avg_processing_time * 1000, 2),
            'total_processing_time': round(self.stats['total_processing_time'], 2),
            'supported_operators': list(self.supported_operators.keys()),
            'cache_status': {
                'rules_cached': len(self.rules_cache),
                'cache_timestamp': self.cache_timestamp.isoformat() if self.cache_timestamp else None
            }
        }
    
    def reset_stats(self):
        """Reset statistics counters"""
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'rules_matched': 0,
            'total_processing_time': 0.0
        }
        logger.info("🔄 Detection engine statistics reset")
    
    def clear_cache(self):
        """Clear rules cache"""
        self.rules_cache = {}
        self.cache_timestamp = None
        logger.info("🗑️ Detection engine cache cleared")


# Global detection engine instance
detection_engine = DetectionEngine()