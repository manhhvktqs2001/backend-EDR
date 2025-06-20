# app/services/detection_engine.py - COMPLETE VERSION
"""
Detection Engine Service
Core detection logic for analyzing events and generating alerts with auto-response
"""

import logging
import json
import re
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..models.agent import Agent
from ..models.event import Event
from ..models.alert import Alert
from ..models.threat import Threat
from ..models.detection_rule import DetectionRule
from ..config import config

logger = logging.getLogger('detection_engine')

class DetectionEngine:
    """Core detection engine for EDR system with threat intelligence and auto-response"""
    
    def __init__(self):
        self.detection_config = config['detection']
        self.alert_config = config['alert']
        self.threat_intel_config = config.get('threat_intel', {})
        self.rules_cache = {}
        self.threats_cache = {}
        self.cache_timestamp = None
        self.cache_ttl = self.detection_config.get('threat_intel_cache_ttl', 3600)
        
        # Performance counters
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'rules_matched': 0,
            'external_lookups': 0
        }
    
    async def analyze_event(self, session: Session, event: Event) -> Optional[Dict]:
        """
        Analyze event through detection engine with threat intelligence
        Returns detection results with alerts and risk scoring
        """
        try:
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
                'external_sources': [],
                'alerts_generated': [],
                'response_actions': [],
                'recommendations': [],
                'analysis_time': datetime.now().isoformat()
            }
            
            # Step 1: Enhanced Threat Intelligence Check (Local + External)
            threat_results = await self._check_threat_intelligence_enhanced(session, event)
            if threat_results:
                detection_results = self._merge_detection_results(detection_results, threat_results)
                self.stats['threats_detected'] += len(threat_results.get('matched_threats', []))
            
            # Step 2: Detection Rules Check
            rules_results = self._check_detection_rules(session, event)
            if rules_results:
                detection_results = self._merge_detection_results(detection_results, rules_results)
                self.stats['rules_matched'] += len(rules_results.get('matched_rules', []))
            
            # Step 3: Behavioral Analysis
            behavior_results = self._analyze_behavior_patterns(session, event)
            if behavior_results:
                detection_results = self._merge_detection_results(detection_results, behavior_results)
            
            # Step 4: Calculate overall risk score
            detection_results['risk_score'] = self._calculate_risk_score(detection_results)
            
            # Step 5: Determine threat level
            detection_results['threat_level'] = self._determine_threat_level(detection_results['risk_score'])
            
            # Step 6: Generate alerts and response actions if necessary
            risk_threshold = self.detection_config.get('risk_score_threshold', 70)
            if detection_results['risk_score'] >= risk_threshold:
                alerts_and_actions = await self._generate_alerts_and_responses(session, event, detection_results)
                detection_results['alerts_generated'] = alerts_and_actions.get('alerts', [])
                detection_results['response_actions'] = alerts_and_actions.get('actions', [])
                detection_results['threat_detected'] = True
                self.stats['alerts_generated'] += len(alerts_and_actions.get('alerts', []))
            
            # Step 7: Generate recommendations
            detection_results['recommendations'] = self._generate_recommendations(detection_results)
            
            # Update event analysis status
            event.update_analysis(
                threat_level=detection_results['threat_level'],
                risk_score=detection_results['risk_score']
            )
            
            logger.debug(f"Event {event.EventID} analyzed - Risk: {detection_results['risk_score']}, "
                        f"Threat: {detection_results['threat_level']}, "
                        f"Methods: {detection_results['detection_methods']}")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"Detection engine analysis failed for event {event.EventID}: {str(e)}")
            return None
    
    async def _check_threat_intelligence_enhanced(self, session: Session, event: Event) -> Optional[Dict]:
        """Enhanced threat intelligence check with external sources"""
        try:
            if not self.detection_config.get('threat_intel_enabled', False):
                return None
            
            results = {
                'detection_methods': ['Threat Intelligence'],
                'matched_threats': [],
                'risk_score': 0,
                'external_sources': [],
                'local_matches': []
            }
            
            # Import threat intel service
            try:
                from .threat_intel import threat_intel_service
                external_available = True
            except ImportError:
                logger.warning("Threat intelligence service not available")
                external_available = False
            
            # Check file hashes (local first, then external)
            hash_checks = []
            if event.ProcessHash:
                hash_checks.append(('process', event.ProcessHash))
            if event.FileHash:
                hash_checks.append(('file', event.FileHash))
            
            for hash_type, file_hash in hash_checks:
                # Local database check first
                local_threat = Threat.check_hash(session, file_hash)
                if local_threat:
                    results['matched_threats'].append(local_threat.ThreatID)
                    results['risk_score'] += self._get_threat_risk_score(local_threat)
                    results['local_matches'].append({
                        'hash': file_hash,
                        'hash_type': hash_type,
                        'threat_name': local_threat.ThreatName,
                        'severity': local_threat.Severity,
                        'source': 'Local Database'
                    })
                    logger.info(f"Local threat match: {file_hash} - {local_threat.ThreatName}")
                
                # External check if not found locally and service available
                elif external_available and self.threat_intel_config.get('enabled', False):
                    try:
                        self.stats['external_lookups'] += 1
                        threat_result = await threat_intel_service.check_hash_reputation(file_hash, session)
                        if threat_result:
                            if threat_result.get('threat_id'):
                                results['matched_threats'].append(threat_result['threat_id'])
                            
                            results['risk_score'] += self._calculate_threat_risk_score(threat_result)
                            results['external_sources'].append({
                                'hash': file_hash,
                                'hash_type': hash_type,
                                'source': threat_result.get('source'),
                                'threat_name': threat_result.get('threat_name'),
                                'severity': threat_result.get('severity'),
                                'confidence': threat_result.get('confidence'),
                                'detections': threat_result.get('detections')
                            })
                            
                            logger.info(f"External threat detected via {threat_result.get('source')}: "
                                      f"{file_hash} - {threat_result.get('threat_name')}")
                    except Exception as e:
                        logger.error(f"External threat check failed for {file_hash}: {str(e)}")
            
            # Check IP addresses
            ip_checks = []
            if event.DestinationIP:
                ip_checks.append(('destination', event.DestinationIP))
            if event.SourceIP:
                ip_checks.append(('source', event.SourceIP))
            
            for ip_type, ip_address in ip_checks:
                # Local check
                local_threat = Threat.check_ip(session, ip_address)
                if local_threat:
                    results['matched_threats'].append(local_threat.ThreatID)
                    results['risk_score'] += self._get_threat_risk_score(local_threat)
                    results['local_matches'].append({
                        'ip': ip_address,
                        'ip_type': ip_type,
                        'threat_name': local_threat.ThreatName,
                        'severity': local_threat.Severity,
                        'source': 'Local Database'
                    })
                    logger.info(f"Malicious IP detected: {ip_address} - {local_threat.ThreatName}")
                
                # External check
                elif external_available and self.threat_intel_config.get('enabled', False):
                    try:
                        self.stats['external_lookups'] += 1
                        threat_result = await threat_intel_service.check_ip_reputation(ip_address, session)
                        if threat_result:
                            if threat_result.get('threat_id'):
                                results['matched_threats'].append(threat_result['threat_id'])
                            
                            results['risk_score'] += self._calculate_threat_risk_score(threat_result)
                            results['external_sources'].append({
                                'ip': ip_address,
                                'ip_type': ip_type,
                                'source': threat_result.get('source'),
                                'threat_name': threat_result.get('threat_name'),
                                'severity': threat_result.get('severity')
                            })
                    except Exception as e:
                        logger.error(f"External IP check failed for {ip_address}: {str(e)}")
            
            # Check domains (if applicable)
            if hasattr(event, 'DomainName') and event.DomainName:
                local_threat = Threat.check_domain(session, event.DomainName)
                if local_threat:
                    results['matched_threats'].append(local_threat.ThreatID)
                    results['risk_score'] += self._get_threat_risk_score(local_threat)
                    results['local_matches'].append({
                        'domain': event.DomainName,
                        'threat_name': local_threat.ThreatName,
                        'severity': local_threat.Severity,
                        'source': 'Local Database'
                    })
            
            return results if (results['matched_threats'] or results['external_sources'] or results['local_matches']) else None
            
        except Exception as e:
            logger.error(f"Enhanced threat intelligence check failed: {str(e)}")
            return None
    
    def _check_detection_rules(self, session: Session, event: Event) -> Optional[Dict]:
        """Check event against detection rules"""
        try:
            if not self.detection_config.get('rules_enabled', False):
                return None
            
            # Get agent platform
            agent = session.query(Agent).filter(Agent.AgentID == event.AgentID).first()
            platform = 'Windows' if agent and 'windows' in agent.OperatingSystem.lower() else 'Linux'
            
            # Get active rules for platform
            active_rules = self._get_cached_rules(session, platform)
            
            results = {
                'detection_methods': ['Rules Engine'],
                'matched_rules': [],
                'rule_details': [],
                'risk_score': 0
            }
            
            for rule in active_rules:
                if self._evaluate_rule(event, rule):
                    results['matched_rules'].append(rule.RuleID)
                    results['risk_score'] += self._get_rule_risk_score(rule)
                    results['rule_details'].append({
                        'rule_id': rule.RuleID,
                        'rule_name': rule.RuleName,
                        'rule_type': rule.RuleType,
                        'severity': rule.AlertSeverity,
                        'mitre_tactic': rule.MitreTactic,
                        'mitre_technique': rule.MitreTechnique
                    })
                    
                    logger.info(f"Detection rule matched: {rule.RuleName} for event {event.EventID}")
            
            return results if results['matched_rules'] else None
            
        except Exception as e:
            logger.error(f"Detection rules check failed: {str(e)}")
            return None
    
    def _analyze_behavior_patterns(self, session: Session, event: Event) -> Optional[Dict]:
        """Analyze behavioral patterns and anomalies"""
        try:
            results = {
                'detection_methods': ['Behavioral Analysis'],
                'behavioral_indicators': [],
                'risk_score': 0
            }
            
            # Suspicious process behaviors
            if event.EventType == 'Process':
                suspicious_patterns = self._check_suspicious_process_behavior(event)
                if suspicious_patterns:
                    results['behavioral_indicators'].extend(suspicious_patterns)
                    results['risk_score'] += len(suspicious_patterns) * 10
            
            # Suspicious file behaviors
            if event.EventType == 'File':
                suspicious_patterns = self._check_suspicious_file_behavior(event)
                if suspicious_patterns:
                    results['behavioral_indicators'].extend(suspicious_patterns)
                    results['risk_score'] += len(suspicious_patterns) * 8
            
            # Suspicious network behaviors
            if event.EventType == 'Network':
                suspicious_patterns = self._check_suspicious_network_behavior(event)
                if suspicious_patterns:
                    results['behavioral_indicators'].extend(suspicious_patterns)
                    results['risk_score'] += len(suspicious_patterns) * 12
            
            # Time-based anomalies
            time_anomalies = self._check_time_anomalies(session, event)
            if time_anomalies:
                results['behavioral_indicators'].extend(time_anomalies)
                results['risk_score'] += len(time_anomalies) * 5
            
            return results if results['behavioral_indicators'] else None
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {str(e)}")
            return None
    
    def _check_suspicious_process_behavior(self, event: Event) -> List[str]:
        """Check for suspicious process behaviors"""
        indicators = []
        
        try:
            if not event.ProcessName or not event.CommandLine:
                return indicators
            
            process_name = event.ProcessName.lower()
            command_line = event.CommandLine.lower()
            
            # Suspicious process names
            suspicious_processes = [
                'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'bitsadmin.exe'
            ]
            
            if process_name in suspicious_processes:
                indicators.append(f"Suspicious process: {event.ProcessName}")
            
            # Suspicious command line patterns
            suspicious_patterns = [
                r'-encodedcommand',
                r'-windowstyle\s+hidden',
                r'-executionpolicy\s+bypass',
                r'invoke-expression',
                r'downloadstring',
                r'base64',
                r'powershell.*-c\s+.*',
                r'cmd.*\/c\s+.*'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, command_line, re.IGNORECASE):
                    indicators.append(f"Suspicious command pattern: {pattern}")
            
            # Living off the land techniques
            lotl_patterns = [
                r'certutil.*-urlcache',
                r'bitsadmin.*\/transfer',
                r'regsvr32.*\/s.*\/u.*\/i',
                r'rundll32.*javascript',
                r'mshta.*http'
            ]
            
            for pattern in lotl_patterns:
                if re.search(pattern, command_line, re.IGNORECASE):
                    indicators.append(f"Living off the land technique: {pattern}")
            
        except Exception as e:
            logger.error(f"Process behavior check failed: {str(e)}")
        
        return indicators
    
    def _check_suspicious_file_behavior(self, event: Event) -> List[str]:
        """Check for suspicious file behaviors"""
        indicators = []
        
        try:
            if not event.FilePath:
                return indicators
            
            file_path = event.FilePath.lower()
            file_name = event.FileName.lower() if event.FileName else ''
            
            # Suspicious locations
            suspicious_locations = [
                r'\\temp\\',
                r'\\users\\public\\',
                r'\\appdata\\roaming\\',
                r'\\windows\\temp\\',
                r'\\programdata\\'
            ]
            
            for location in suspicious_locations:
                if re.search(location, file_path, re.IGNORECASE):
                    indicators.append(f"Suspicious file location: {location}")
            
            # Suspicious extensions
            if event.FileExtension:
                suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.dll']
                if event.FileExtension.lower() in suspicious_extensions:
                    indicators.append(f"Suspicious file extension: {event.FileExtension}")
            
            # Double extensions
            if file_name.count('.') > 1:
                indicators.append("Double file extension detected")
            
            # Hidden or system files in user directories
            if '\\users\\' in file_path and ('hidden' in file_name or 'system' in file_name):
                indicators.append("Hidden/system file in user directory")
            
        except Exception as e:
            logger.error(f"File behavior check failed: {str(e)}")
        
        return indicators
    
    def _check_suspicious_network_behavior(self, event: Event) -> List[str]:
        """Check for suspicious network behaviors"""
        indicators = []
        
        try:
            # Suspicious ports
            if event.DestinationPort:
                suspicious_ports = [22, 23, 135, 139, 445, 1433, 1521, 3389, 5900, 6667]
                if event.DestinationPort in suspicious_ports:
                    indicators.append(f"Connection to suspicious port: {event.DestinationPort}")
            
            # External connections from system processes
            if event.SourceIP and event.DestinationIP:
                # Check if it's an external connection
                if not self._is_internal_ip(event.DestinationIP):
                    indicators.append("External network connection")
            
            # High port numbers (often used by malware)
            if event.DestinationPort and event.DestinationPort > 49152:
                indicators.append("Connection to high port number")
            
        except Exception as e:
            logger.error(f"Network behavior check failed: {str(e)}")
        
        return indicators
    
    def _check_time_anomalies(self, session: Session, event: Event) -> List[str]:
        """Check for time-based anomalies"""
        indicators = []
        
        try:
            # Activity during unusual hours (e.g., 2-6 AM)
            event_hour = event.EventTimestamp.hour
            if 2 <= event_hour <= 6:
                indicators.append("Activity during unusual hours")
            
            # Weekend activity for business processes
            event_weekday = event.EventTimestamp.weekday()
            if event_weekday >= 5:  # Saturday or Sunday
                if event.ProcessName and any(proc in event.ProcessName.lower() 
                                           for proc in ['excel', 'word', 'outlook']):
                    indicators.append("Business application activity on weekend")
            
        except Exception as e:
            logger.error(f"Time anomaly check failed: {str(e)}")
        
        return indicators
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is internal"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except:
            return False
    
    def _get_cached_rules(self, session: Session, platform: str) -> List[DetectionRule]:
        """Get cached detection rules"""
        try:
            cache_key = f"rules_{platform}"
            current_time = datetime.now()
            
            # Check if cache is valid
            if (cache_key in self.rules_cache and 
                self.cache_timestamp and 
                (current_time - self.cache_timestamp).seconds < 300):  # 5 minute cache
                return self.rules_cache[cache_key]
            
            # Refresh cache
            rules = DetectionRule.get_active_rules(session, platform)
            self.rules_cache[cache_key] = rules
            self.cache_timestamp = current_time
            
            return rules
            
        except Exception as e:
            logger.error(f"Rule cache error: {str(e)}")
            return DetectionRule.get_active_rules(session, platform)
    
    def _evaluate_rule(self, event: Event, rule: DetectionRule) -> bool:
        """Evaluate if event matches detection rule"""
        try:
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                return False
            
            # Handle different rule condition formats
            if isinstance(rule_condition, dict):
                if 'conditions' in rule_condition:
                    # New format with conditions array
                    conditions = rule_condition.get('conditions', [])
                    logic = rule_condition.get('logic', 'AND')
                    
                    condition_results = []
                    for condition in conditions:
                        result = self._evaluate_condition(event, condition)
                        condition_results.append(result)
                    
                    # Apply logic
                    if logic.upper() == 'AND':
                        return all(condition_results)
                    elif logic.upper() == 'OR':
                        return any(condition_results)
                else:
                    # Simple condition format
                    return self._evaluate_simple_rule(event, rule_condition)
            
            return False
                
        except Exception as e:
            logger.error(f"Rule evaluation failed for rule {rule.RuleID}: {str(e)}")
            return False
    
    def _evaluate_simple_rule(self, event: Event, rule_condition: Dict) -> bool:
        """Evaluate simple rule conditions"""
        try:
            matches = 0
            total_conditions = 0
            
            for field, value in rule_condition.items():
                if field == 'logic':
                    continue
                
                total_conditions += 1
                event_value = getattr(event, self._map_field_name(field), None)
                
                if event_value and self._check_condition_match(event_value, value):
                    matches += 1
            
            # Check logic
            logic = rule_condition.get('logic', 'AND')
            if logic.upper() == 'OR':
                return matches > 0
            else:  # Default to AND
                return matches == total_conditions
                
        except Exception as e:
            logger.error(f"Simple rule evaluation failed: {str(e)}")
            return False
    
    def _evaluate_condition(self, event: Event, condition: Dict) -> bool:
        """Evaluate single condition against event"""
        try:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')
            
            if not all([field, operator]):
                return False
            
            # Get event field value
            event_value = getattr(event, field, None)
            if event_value is None:
                return False
            
            # Apply operator
            return self._apply_operator(event_value, operator, value)
                
        except Exception as e:
            logger.error(f"Condition evaluation failed: {str(e)}")
            return False
    
    def _map_field_name(self, field: str) -> str:
        """Map rule field names to event model field names"""
        field_mapping = {
            'process_name': 'ProcessName',
            'command_line': 'CommandLine',
            'file_name': 'FileName',
            'file_path': 'FilePath',
            'registry_key': 'RegistryKey',
            'destination_ip': 'DestinationIP',
            'source_ip': 'SourceIP',
            'destination_port': 'DestinationPort'
        }
        return field_mapping.get(field, field)
    
    def _check_condition_match(self, event_value: Any, condition_value: Any) -> bool:
        """Check if event value matches condition value"""
        try:
            if isinstance(condition_value, list):
                return any(str(v).lower() in str(event_value).lower() for v in condition_value)
            else:
                return str(condition_value).lower() in str(event_value).lower()
        except:
            return False
    
    def _apply_operator(self, event_value: Any, operator: str, value: Any) -> bool:
        """Apply comparison operator"""
        try:
            if operator == 'equals':
                return str(event_value).lower() == str(value).lower()
            elif operator == 'iequals':
                return str(event_value).lower() == str(value).lower()
            elif operator == 'contains':
                return str(value).lower() in str(event_value).lower()
            elif operator == 'contains_any':
                if isinstance(value, list):
                    return any(str(v).lower() in str(event_value).lower() for v in value)
                return str(value).lower() in str(event_value).lower()
            elif operator == 'not_equals':
                return str(event_value).lower() != str(value).lower()
            elif operator == 'in':
                return event_value in value if isinstance(value, list) else False
            elif operator == 'not_in':
                return event_value not in value if isinstance(value, list) else True
            elif operator == 'regex':
                return bool(re.search(str(value), str(event_value), re.IGNORECASE))
            elif operator == 'greater_than':
                return float(event_value) > float(value) if self._is_numeric(event_value) else False
            elif operator == 'less_than':
                return float(event_value) < float(value) if self._is_numeric(event_value) else False
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
                
        except Exception as e:
            logger.error(f"Operator application failed: {str(e)}")
            return False
    
    def _is_numeric(self, value: Any) -> bool:
        """Check if value is numeric"""
        try:
            float(value)
            return True
        except (ValueError, TypeError):
            return False
    
    def _get_threat_risk_score(self, threat: Threat) -> int:
        """Get risk score based on threat severity"""
        severity_scores = {
            'Info': 10,
            'Low': 20,
            'Medium': 40,
            'High': 70,
            'Critical': 90
        }
        base_score = severity_scores.get(threat.Severity, 20)
        
        # Adjust based on confidence
        confidence_multiplier = float(threat.Confidence) if threat.Confidence else 0.5
        return int(base_score * confidence_multiplier)
    
    def _calculate_threat_risk_score(self, threat_result: Dict) -> int:
        """Calculate risk score from external threat intelligence result"""
        base_scores = {
            'Low': 20,
            'Medium': 40,
            'High': 70,
            'Critical': 90
        }
        
        severity = threat_result.get('severity', 'Medium')
        base_score = base_scores.get(severity, 40)
        
        # Adjust by confidence
        confidence = threat_result.get('confidence', 0.5)
        adjusted_score = int(base_score * confidence)
        
        # Bonus for external sources
        if threat_result.get('source') != 'Local Database':
            adjusted_score += 10
        
        return adjusted_score
    
    def _get_rule_risk_score(self, rule: DetectionRule) -> int:
        """Get risk score based on rule severity and priority"""
        severity_scores = {
            'Info': 5,
            'Low': 15,
            'Medium': 30,
            'High': 60,
            'Critical': 85
        }
        base_score = severity_scores.get(rule.AlertSeverity, 15)
        
        # Adjust based on priority (1-100)
        priority_multiplier = (rule.Priority or 50) / 100
        return int(base_score * priority_multiplier)
    
    def _calculate_risk_score(self, detection_results: Dict) -> int:
        """Calculate overall risk score from detection results"""
        risk_score = detection_results.get('risk_score', 0)
        
        # Bonus for multiple detection methods
        if len(detection_results.get('detection_methods', [])) > 1:
            risk_score += 15
        
        # Bonus for multiple matches
        total_matches = (len(detection_results.get('matched_rules', [])) + 
                        len(detection_results.get('matched_threats', [])) +
                        len(detection_results.get('external_sources', [])))
        if total_matches > 1:
            risk_score += min(total_matches * 8, 25)
        
        # Bonus for behavioral indicators
        behavioral_count = len(detection_results.get('behavioral_indicators', []))
        if behavioral_count > 0:
            risk_score += min(behavioral_count * 5, 20)
        
        # Cap at 100
        return min(risk_score, 100)
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score"""
        if risk_score >= 85:
            return 'Critical'
        elif risk_score >= 70:
            return 'High'
        elif risk_score >= 50:
            return 'Medium'
        elif risk_score >= 30:
            return 'Low'
        else:
            return 'None'
    
    async def _generate_alerts_and_responses(self, session: Session, event: Event, 
                                           detection_results: Dict) -> Dict:
        """Generate alerts and response actions based on detection results"""
        try:
            alerts_generated = []
            response_actions = []
            
            # Generate alerts for matched rules
            for rule_detail in detection_results.get('rule_details', []):
                rule_id = rule_detail['rule_id']
                rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
                if rule and not rule.TestMode:
                    alert = self._create_rule_alert(event, rule, detection_results)
                    if alert:
                        alerts_generated.append(alert)
                        session.add(alert)
                    
                    # Add response action
                    response_action = self._create_response_action(event, rule, detection_results)
                    if response_action:
                        response_actions.append(response_action)
            
            # Generate alerts for threat intelligence matches
            for threat_id in detection_results.get('matched_threats', []):
                threat = session.query(Threat).filter(Threat.ThreatID == threat_id).first()
                if threat:
                    alert = self._create_threat_alert(event, threat, detection_results)
                    if alert:
                        alerts_generated.append(alert)
                        session.add(alert)
                    
                    # Add response action for threat
                    response_action = self._create_threat_response_action(event, threat, detection_results)
                    if response_action:
                        response_actions.append(response_action)
            
            # Generate alert for behavioral anomalies if significant
            behavioral_indicators = detection_results.get('behavioral_indicators', [])
            if len(behavioral_indicators) >= 3:  # Multiple behavioral indicators
                alert = self._create_behavioral_alert(event, behavioral_indicators, detection_results)
                if alert:
                    alerts_generated.append(alert)
                    session.add(alert)
            
            # Commit alerts to database
            session.commit()
            
            return {
                'alerts': [self._alert_to_dict(alert) for alert in alerts_generated],
                'actions': response_actions
            }
            
        except Exception as e:
            logger.error(f"Alert and response generation failed: {str(e)}")
            session.rollback()
            return {'alerts': [], 'actions': []}
    
    def _create_rule_alert(self, event: Event, rule: DetectionRule, detection_results: Dict) -> Optional[Alert]:
        """Create alert for matched detection rule"""
        try:
            alert_description = f"Detection rule '{rule.RuleName}' triggered"
            if rule.Description:
                alert_description += f": {rule.Description}"
            
            # Build detailed message
            details = {
                'rule_id': rule.RuleID,
                'rule_name': rule.RuleName,
                'rule_type': rule.RuleType,
                'mitre_tactic': rule.MitreTactic,
                'mitre_technique': rule.MitreTechnique,
                'event_details': self._get_event_summary(event),
                'risk_score': detection_results.get('risk_score', 0),
                'detection_methods': detection_results.get('detection_methods', [])
            }
            
            alert = Alert(
                AlertID=None,  # Auto-generated
                EventID=event.EventID,
                AgentID=event.AgentID,
                RuleID=rule.RuleID,
                ThreatID=None,
                AlertType='Rule Detection',
                Severity=rule.AlertSeverity,
                Title=f"Rule Detection: {rule.RuleName}",
                Description=alert_description,
                Details=json.dumps(details),
                Status='Open',
                AssignedTo=None,
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Rule alert creation failed: {str(e)}")
            return None
    
    def _create_threat_alert(self, event: Event, threat: Threat, detection_results: Dict) -> Optional[Alert]:
        """Create alert for threat intelligence match"""
        try:
            alert_description = f"Threat detected: {threat.ThreatName}"
            if threat.Description:
                alert_description += f" - {threat.Description}"
            
            details = {
                'threat_id': threat.ThreatID,
                'threat_name': threat.ThreatName,
                'threat_type': threat.ThreatType,
                'severity': threat.Severity,
                'confidence': threat.Confidence,
                'source': threat.Source,
                'event_details': self._get_event_summary(event),
                'risk_score': detection_results.get('risk_score', 0),
                'iocs': {
                    'hash': threat.IOCHash,
                    'ip': threat.IOCIP,
                    'domain': threat.IOCDomain
                }
            }
            
            alert = Alert(
                AlertID=None,
                EventID=event.EventID,
                AgentID=event.AgentID,
                RuleID=None,
                ThreatID=threat.ThreatID,
                AlertType='Threat Intelligence',
                Severity=threat.Severity,
                Title=f"Threat Detected: {threat.ThreatName}",
                Description=alert_description,
                Details=json.dumps(details),
                Status='Open',
                AssignedTo=None,
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Threat alert creation failed: {str(e)}")
            return None
    
    def _create_behavioral_alert(self, event: Event, behavioral_indicators: List[str], 
                               detection_results: Dict) -> Optional[Alert]:
        """Create alert for behavioral anomalies"""
        try:
            alert_description = f"Multiple suspicious behaviors detected: {len(behavioral_indicators)} indicators"
            
            details = {
                'behavioral_indicators': behavioral_indicators,
                'event_details': self._get_event_summary(event),
                'risk_score': detection_results.get('risk_score', 0),
                'analysis_time': detection_results.get('analysis_time')
            }
            
            # Determine severity based on number of indicators
            if len(behavioral_indicators) >= 5:
                severity = 'High'
            elif len(behavioral_indicators) >= 4:
                severity = 'Medium'
            else:
                severity = 'Low'
            
            alert = Alert(
                AlertID=None,
                EventID=event.EventID,
                AgentID=event.AgentID,
                RuleID=None,
                ThreatID=None,
                AlertType='Behavioral Analysis',
                Severity=severity,
                Title="Suspicious Behavior Detected",
                Description=alert_description,
                Details=json.dumps(details),
                Status='Open',
                AssignedTo=None,
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Behavioral alert creation failed: {str(e)}")
            return None
    
    def _create_response_action(self, event: Event, rule: DetectionRule, 
                              detection_results: Dict) -> Optional[Dict]:
        """Create response action for detection rule"""
        try:
            if not rule.ResponseAction or rule.ResponseAction == 'None':
                return None
            
            response_action = {
                'action_type': rule.ResponseAction,
                'rule_id': rule.RuleID,
                'rule_name': rule.RuleName,
                'event_id': event.EventID,
                'agent_id': str(event.AgentID),
                'severity': rule.AlertSeverity,
                'timestamp': datetime.now().isoformat(),
                'details': {}
            }
            
            # Add specific action details based on type
            if rule.ResponseAction == 'Quarantine':
                response_action['details'] = {
                    'action': 'quarantine_file',
                    'file_path': event.FilePath if hasattr(event, 'FilePath') else None,
                    'file_hash': event.FileHash if hasattr(event, 'FileHash') else None,
                    'process_name': event.ProcessName if hasattr(event, 'ProcessName') else None
                }
            elif rule.ResponseAction == 'Block':
                response_action['details'] = {
                    'action': 'block_process',
                    'process_name': event.ProcessName if hasattr(event, 'ProcessName') else None,
                    'process_hash': event.ProcessHash if hasattr(event, 'ProcessHash') else None
                }
            elif rule.ResponseAction == 'Isolate':
                response_action['details'] = {
                    'action': 'isolate_agent',
                    'reason': f"Rule violation: {rule.RuleName}"
                }
            elif rule.ResponseAction == 'Kill':
                response_action['details'] = {
                    'action': 'kill_process',
                    'process_name': event.ProcessName if hasattr(event, 'ProcessName') else None,
                    'process_id': event.ProcessID if hasattr(event, 'ProcessID') else None
                }
            
            return response_action
            
        except Exception as e:
            logger.error(f"Response action creation failed: {str(e)}")
            return None
    
    def _create_threat_response_action(self, event: Event, threat: Threat, 
                                     detection_results: Dict) -> Optional[Dict]:
        """Create response action for threat intelligence match"""
        try:
            # Determine action based on threat severity
            if threat.Severity in ['Critical', 'High']:
                action_type = 'Quarantine'
            elif threat.Severity == 'Medium':
                action_type = 'Block'
            else:
                action_type = 'Monitor'
            
            response_action = {
                'action_type': action_type,
                'threat_id': threat.ThreatID,
                'threat_name': threat.ThreatName,
                'event_id': event.EventID,
                'agent_id': str(event.AgentID),
                'severity': threat.Severity,
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'threat_type': threat.ThreatType,
                    'confidence': threat.Confidence,
                    'source': threat.Source
                }
            }
            
            # Add specific IOC details
            if threat.IOCHash and (event.FileHash == threat.IOCHash or event.ProcessHash == threat.IOCHash):
                response_action['details']['ioc_type'] = 'hash'
                response_action['details']['ioc_value'] = threat.IOCHash
                response_action['details']['action'] = 'quarantine_file'
            elif threat.IOCIP and (event.DestinationIP == threat.IOCIP or event.SourceIP == threat.IOCIP):
                response_action['details']['ioc_type'] = 'ip'
                response_action['details']['ioc_value'] = threat.IOCIP
                response_action['details']['action'] = 'block_ip'
            elif threat.IOCDomain and hasattr(event, 'DomainName') and event.DomainName == threat.IOCDomain:
                response_action['details']['ioc_type'] = 'domain'
                response_action['details']['ioc_value'] = threat.IOCDomain
                response_action['details']['action'] = 'block_domain'
            
            return response_action
            
        except Exception as e:
            logger.error(f"Threat response action creation failed: {str(e)}")
            return None
    
    def _get_event_summary(self, event: Event) -> Dict:
        """Get summary of event details for alert"""
        summary = {
            'event_id': event.EventID,
            'event_type': event.EventType,
            'timestamp': event.EventTimestamp.isoformat(),
            'agent_id': str(event.AgentID)
        }
        
        # Add relevant fields based on event type
        if event.EventType == 'Process':
            summary.update({
                'process_name': event.ProcessName,
                'command_line': event.CommandLine,
                'process_hash': event.ProcessHash,
                'parent_process': event.ParentProcess
            })
        elif event.EventType == 'File':
            summary.update({
                'file_name': event.FileName,
                'file_path': event.FilePath,
                'file_hash': event.FileHash,
                'file_extension': event.FileExtension,
                'action': event.Action
            })
        elif event.EventType == 'Network':
            summary.update({
                'source_ip': event.SourceIP,
                'destination_ip': event.DestinationIP,
                'destination_port': event.DestinationPort,
                'protocol': event.Protocol,
                'action': event.Action
            })
        elif event.EventType == 'Registry':
            summary.update({
                'registry_key': event.RegistryKey,
                'registry_value': event.RegistryValue,
                'action': event.Action
            })
        
        return summary
    
    def _alert_to_dict(self, alert: Alert) -> Dict:
        """Convert alert object to dictionary"""
        return {
            'alert_id': alert.AlertID,
            'event_id': alert.EventID,
            'agent_id': str(alert.AgentID),
            'rule_id': alert.RuleID,
            'threat_id': alert.ThreatID,
            'alert_type': alert.AlertType,
            'severity': alert.Severity,
            'title': alert.Title,
            'description': alert.Description,
            'details': json.loads(alert.Details) if alert.Details else {},
            'status': alert.Status,
            'assigned_to': alert.AssignedTo,
            'created_at': alert.CreatedAt.isoformat(),
            'updated_at': alert.UpdatedAt.isoformat()
        }
    
    def _generate_recommendations(self, detection_results: Dict) -> List[str]:
        """Generate security recommendations based on detection results"""
        recommendations = []
        
        try:
            risk_score = detection_results.get('risk_score', 0)
            threat_level = detection_results.get('threat_level', 'None')
            behavioral_indicators = detection_results.get('behavioral_indicators', [])
            
            # High-risk recommendations
            if risk_score >= 70:
                recommendations.append("Immediately investigate this incident")
                recommendations.append("Consider isolating the affected agent")
                recommendations.append("Review related events from the same agent")
                
                if detection_results.get('matched_threats'):
                    recommendations.append("Update threat intelligence feeds")
                    recommendations.append("Scan other agents for similar threats")
            
            # Medium-risk recommendations
            elif risk_score >= 40:
                recommendations.append("Monitor agent activity closely")
                recommendations.append("Review security policies")
                recommendations.append("Consider additional endpoint hardening")
            
            # Behavioral-specific recommendations
            if 'Suspicious process' in str(behavioral_indicators):
                recommendations.append("Review process execution policies")
                recommendations.append("Consider application whitelisting")
            
            if 'External network connection' in str(behavioral_indicators):
                recommendations.append("Review network access controls")
                recommendations.append("Consider implementing network segmentation")
            
            if 'Suspicious file location' in str(behavioral_indicators):
                recommendations.append("Review file system permissions")
                recommendations.append("Implement folder access monitoring")
            
            # Rule-specific recommendations
            if detection_results.get('matched_rules'):
                recommendations.append("Review and tune detection rules")
                recommendations.append("Verify rule effectiveness")
            
            # Time-based recommendations
            if 'Activity during unusual hours' in str(behavioral_indicators):
                recommendations.append("Review user access schedules")
                recommendations.append("Implement time-based access controls")
            
            # General recommendations
            if not recommendations:
                recommendations.append("Continue monitoring")
                recommendations.append("Review security awareness training")
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
            recommendations.append("Review security posture")
        
        return recommendations
    
    def _merge_detection_results(self, base_results: Dict, new_results: Dict) -> Dict:
        """Merge detection results from different analysis methods"""
        try:
            # Merge detection methods
            base_methods = set(base_results.get('detection_methods', []))
            new_methods = set(new_results.get('detection_methods', []))
            base_results['detection_methods'] = list(base_methods.union(new_methods))
            
            # Merge matched rules
            base_rules = base_results.get('matched_rules', [])
            new_rules = new_results.get('matched_rules', [])
            base_results['matched_rules'] = list(set(base_rules + new_rules))
            
            # Merge matched threats
            base_threats = base_results.get('matched_threats', [])
            new_threats = new_results.get('matched_threats', [])
            base_results['matched_threats'] = list(set(base_threats + new_threats))
            
            # Merge external sources
            base_external = base_results.get('external_sources', [])
            new_external = new_results.get('external_sources', [])
            base_results['external_sources'] = base_external + new_external
            
            # Merge behavioral indicators
            base_behavioral = base_results.get('behavioral_indicators', [])
            new_behavioral = new_results.get('behavioral_indicators', [])
            base_results['behavioral_indicators'] = base_behavioral + new_behavioral
            
            # Merge rule details
            base_rule_details = base_results.get('rule_details', [])
            new_rule_details = new_results.get('rule_details', [])
            base_results['rule_details'] = base_rule_details + new_rule_details
            
            # Merge local matches
            base_local = base_results.get('local_matches', [])
            new_local = new_results.get('local_matches', [])
            base_results['local_matches'] = base_local + new_local
            
            # Add risk scores
            base_results['risk_score'] = (base_results.get('risk_score', 0) + 
                                        new_results.get('risk_score', 0))
            
            return base_results
            
        except Exception as e:
            logger.error(f"Detection results merge failed: {str(e)}")
            return base_results
    
    def get_performance_stats(self) -> Dict:
        """Get detection engine performance statistics"""
        return {
            'events_analyzed': self.stats['events_analyzed'],
            'threats_detected': self.stats['threats_detected'],
            'alerts_generated': self.stats['alerts_generated'],
            'rules_matched': self.stats['rules_matched'],
            'external_lookups': self.stats['external_lookups'],
            'detection_rate': (self.stats['threats_detected'] / max(self.stats['events_analyzed'], 1)) * 100,
            'alert_rate': (self.stats['alerts_generated'] / max(self.stats['events_analyzed'], 1)) * 100
        }
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'rules_matched': 0,
            'external_lookups': 0
        }
    
    def clear_cache(self):
        """Clear detection engine cache"""
        self.rules_cache.clear()
        self.threats_cache.clear()
        self.cache_timestamp = None
        logger.info("Detection engine cache cleared")


# Create global detection engine instance
detection_engine = DetectionEngine()