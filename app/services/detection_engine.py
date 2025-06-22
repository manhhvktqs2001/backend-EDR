# app/services/detection_engine.py - COMPLETELY FIXED
"""
Detection Engine - COMPLETELY FIXED
Core detection logic WITH automatic alert creation AND realtime notifications
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
from ..models.alert import Alert  # ADDED: For alert creation
from ..config import config

logger = logging.getLogger('detection_engine')

class DetectionEngine:
    """FIXED: Detection engine with automatic alert creation AND notifications"""
    
    def __init__(self):
        self.detection_config = config['detection']
        self.alert_config = config['alert']
        self.rules_cache = {}
        self.cache_timestamp = None
        
        # Performance counters
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_created': 0,  # FIXED: Track alerts created
            'notifications_sent': 0,  # ADDED: Track notifications
            'rules_matched': 0,
            'total_processing_time': 0.0
        }
        
        logger.info("🔍 Detection Engine - FIXED MODE: Creates alerts AND sends notifications")
    
    async def analyze_event_and_create_alerts(self, session: Session, event: Event) -> Dict[str, Any]:
        """
        FIXED: Analyze event, create alerts, AND send notifications
        Returns complete results including created alerts
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"🔍 ANALYZING EVENT {event.EventID}: {event.EventType} - {event.EventAction}")
            
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
                'alerts_created': [],  # FIXED: Track created alerts
                'notifications_sent': [],  # ADDED: Track notifications
                'behavioral_indicators': [],
                'recommendations': [],
                'analysis_time': start_time.isoformat()
            }
            
            # Get agent for context
            agent = session.query(Agent).filter(Agent.AgentID == event.AgentID).first()
            if not agent:
                logger.warning(f"Agent not found for event {event.EventID}")
                return detection_results
            
            # Step 1: Check detection rules
            rules_results = self._check_detection_rules(session, event, agent)
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
            
            # Step 5: FIXED - Create alerts if threshold exceeded
            risk_threshold = self.detection_config.get('risk_score_threshold', 50)
            if detection_results['risk_score'] >= risk_threshold:
                detection_results['threat_detected'] = True
                
                # CREATE ALERTS (not just notifications)
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
    
    def _check_detection_rules(self, session: Session, event: Event, agent: Agent) -> Optional[Dict]:
        """Check event against active detection rules"""
        try:
            if not self.detection_config.get('rules_enabled', False):
                return None
            
            platform = self._get_platform_from_agent(agent)
            active_rules = self._get_active_rules(session, platform)
            
            results = {
                'detection_methods': ['Rules Engine'],
                'matched_rules': [],
                'rule_details': [],
                'risk_score': 0
            }
            
            for rule in active_rules:
                try:
                    if self._evaluate_rule(event, rule):
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
                        
                        logger.info(f"🎯 RULE MATCHED: {rule.RuleName} (Risk: +{rule_risk})")
                        
                except Exception as e:
                    logger.error(f"Rule evaluation error for rule {rule.RuleID}: {e}")
                    continue
            
            return results if results['matched_rules'] else None
            
        except Exception as e:
            logger.error(f"Detection rules check failed: {str(e)}")
            return None
    
    async def _check_threat_intelligence_async(self, session: Session, event: Event) -> Optional[Dict]:
        """Async threat intelligence check with external sources"""
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
                    # Local database check first
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
                    
                    # TODO: Add external threat intel check
                    # external_result = await self._check_external_threat_intel(hash_value)
            
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
                results['risk_score'] += len(indicators) * 15  # Higher weight
            
            # File behavior analysis
            elif event.EventType == 'File':
                indicators = self._check_file_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 12
            
            # Network behavior analysis
            elif event.EventType == 'Network':
                indicators = self._check_network_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 18  # Highest weight
            
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
        
        # Process injection indicators
        if event.ParentPID and event.ProcessName:
            suspicious_parents = ['explorer.exe', 'winlogon.exe', 'csrss.exe']
            suspicious_children = ['powershell.exe', 'cmd.exe', 'wscript.exe']
            
            if any(parent in process_name for parent in suspicious_parents):
                if any(child in event.ProcessName.lower() for child in suspicious_children):
                    indicators.append("Suspicious parent-child process relationship")
        
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
        
        # Dangerous file types in suspicious locations
        if event.FileExtension and any(loc in file_path for loc in ['temp', 'public', 'appdata']):
            dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.dll']
            if event.FileExtension.lower() in dangerous_extensions:
                indicators.append(f"Executable file in suspicious location: {event.FileExtension}")
        
        # Double extension
        if file_name and file_name.count('.') > 1:
            dangerous_combos = ['.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.exe']
            if any(combo in file_name for combo in dangerous_combos):
                indicators.append("Double extension detected")
        
        # Hidden files
        if file_name and file_name.startswith('.') and not file_name.startswith('..'):
            indicators.append("Hidden file")
        
        return indicators
    
    def _check_network_behavior(self, event: Event) -> List[str]:
        """Enhanced network behavior analysis"""
        indicators = []
        
        # Suspicious ports
        if event.DestinationPort:
            suspicious_ports = {
                22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS',
                445: 'SMB', 1433: 'SQL Server', 3389: 'RDP',
                4444: 'Common backdoor', 6667: 'IRC', 8080: 'HTTP Proxy'
            }
            
            if event.DestinationPort in suspicious_ports:
                service = suspicious_ports[event.DestinationPort]
                indicators.append(f"Connection to suspicious port: {event.DestinationPort} ({service})")
        
        # External connections from internal processes
        if event.DestinationIP and not self._is_private_ip(event.DestinationIP):
            indicators.append("External network connection")
            
            # Check for connections to known bad countries/regions
            # This would require GeoIP lookup in a real implementation
            pass
        
        # High number of connections (if we had count data)
        # This would require session correlation
        
        return indicators
    
    def _check_registry_behavior(self, event: Event) -> List[str]:
        """Registry behavior analysis"""
        indicators = []
        
        if not event.RegistryKey:
            return indicators
        
        registry_key = event.RegistryKey.lower()
        
        # Suspicious registry keys
        suspicious_keys = [
            r'\\software\\microsoft\\windows\\currentversion\\run',
            r'\\software\\microsoft\\windows\\currentversion\\runonce',
            r'\\system\\currentcontrolset\\services',
            r'\\software\\classes\\exefile\\shell\\open\\command',
            r'\\software\\microsoft\\windows nt\\currentversion\\winlogon',
            r'\\system\\currentcontrolset\\control\\lsa'
        ]
        
        key_descriptions = {
            'run': 'Startup program modification',
            'runonce': 'One-time startup modification',
            'services': 'Service configuration change',
            'exefile': 'Executable hijacking attempt',
            'winlogon': 'Logon process modification',
            'lsa': 'Security subsystem modification'
        }
        
        for suspicious_key in suspicious_keys:
            if re.search(suspicious_key, registry_key, re.IGNORECASE):
                for key_type, description in key_descriptions.items():
                    if key_type in suspicious_key:
                        indicators.append(f"Registry modification: {description}")
                        break
                else:
                    indicators.append("Suspicious registry modification")
        
        return indicators
    
    async def _create_alerts_for_detections(self, session: Session, event: Event, 
                                          agent: Agent, detection_results: Dict) -> List[int]:
        """FIXED: Create actual alerts for detected threats"""
        try:
            alerts_created = []
            
            # Create alerts for matched rules
            for rule_detail in detection_results.get('rule_details', []):
                try:
                    alert = Alert.create_alert(
                        agent_id=str(event.AgentID),
                        alert_type=rule_detail['alert_type'],
                        title=rule_detail['alert_title'],
                        severity=rule_detail['severity'],
                        detection_method='Rule Detection',
                        Description=f"Rule '{rule_detail['rule_name']}' triggered by {event.EventType} event",
                        EventID=event.EventID,
                        RuleID=rule_detail['rule_id'],
                        RiskScore=detection_results['risk_score'],
                        Confidence=0.9,
                        MitreTactic=rule_detail.get('mitre_tactic'),
                        MitreTechnique=rule_detail.get('mitre_technique')
                    )
                    
                    session.add(alert)
                    session.flush()
                    alerts_created.append(alert.AlertID)
                    
                    logger.warning(f"🚨 ALERT CREATED: {alert.AlertID} - {rule_detail['rule_name']}")
                    
                except Exception as e:
                    logger.error(f"Failed to create rule alert: {e}")
                    continue
            
            # Create alerts for threat intelligence matches
            for threat_detail in detection_results.get('threat_details', []):
                try:
                    alert = Alert.create_alert(
                        agent_id=str(event.AgentID),
                        alert_type='Threat Intelligence Match',
                        title=f"Threat Detected: {threat_detail['threat_name']}",
                        severity=threat_detail['severity'],
                        detection_method='Threat Intelligence',
                        Description=f"Known threat '{threat_detail['threat_name']}' detected in {threat_detail['field_type']}",
                        EventID=event.EventID,
                        ThreatID=threat_detail['threat_id'],
                        RiskScore=detection_results['risk_score'],
                        Confidence=0.95
                    )
                    
                    session.add(alert)
                    session.flush()
                    alerts_created.append(alert.AlertID)
                    
                    logger.warning(f"🚨 THREAT ALERT CREATED: {alert.AlertID} - {threat_detail['threat_name']}")
                    
                except Exception as e:
                    logger.error(f"Failed to create threat alert: {e}")
                    continue
            
            # Create alert for high-risk behavioral detection
            behavioral_indicators = detection_results.get('behavioral_indicators', [])
            if len(behavioral_indicators) >= 3:
                try:
                    severity = 'High' if len(behavioral_indicators) >= 5 else 'Medium'
                    
                    alert = Alert.create_alert(
                        agent_id=str(event.AgentID),
                        alert_type='Behavioral Detection',
                        title=f"Suspicious Behavior: {len(behavioral_indicators)} indicators",
                        severity=severity,
                        detection_method='Behavioral Analysis',
                        Description=f"Multiple suspicious behaviors detected: {', '.join(behavioral_indicators[:3])}",
                        EventID=event.EventID,
                        RiskScore=detection_results['risk_score'],
                        Confidence=0.7
                    )
                    
                    session.add(alert)
                    session.flush()
                    alerts_created.append(alert.AlertID)
                    
                    logger.warning(f"🚨 BEHAVIORAL ALERT CREATED: {alert.AlertID} - {len(behavioral_indicators)} indicators")
                    
                except Exception as e:
                    logger.error(f"Failed to create behavioral alert: {e}")
            
            return alerts_created
            
        except Exception as e:
            logger.error(f"Alert creation failed: {str(e)}")
            return []
    
    async def _send_notifications_to_agent(self, session: Session, agent: Agent, 
                                         detection_results: Dict, alert_ids: List[int]) -> List[Dict]:
        """Send notifications to agent about created alerts"""
        try:
            from ..services.agent_communication_service import agent_communication_service
            
            notifications = []
            
            # Create notification for each alert
            for alert_id in alert_ids:
                try:
                    alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
                    if alert:
                        notification = {
                            'type': 'security_alert',
                            'alert_id': alert_id,
                            'title': alert.Title,
                            'description': alert.Description,
                            'severity': alert.Severity,
                            'risk_score': alert.RiskScore,
                            'detection_method': alert.DetectionMethod,
                            'event_id': alert.EventID,
                            'timestamp': datetime.now().isoformat(),
                            'action_required': alert.Severity in ['High', 'Critical'],
                            'recommendations': detection_results.get('recommendations', [])
                        }
                        notifications.append(notification)
                        
                except Exception as e:
                    logger.error(f"Failed to create notification for alert {alert_id}: {e}")
                    continue
            
            # Send notifications to agent
            if notifications:
                success = await agent_communication_service.send_detection_notifications_to_agent(
                    session, str(agent.AgentID), notifications
                )
                
                if success:
                    logger.info(f"📤 NOTIFICATIONS SENT: {len(notifications)} to agent {agent.HostName}")
                    return notifications
                else:
                    logger.error(f"Failed to send notifications to agent {agent.HostName}")
            
            return []
            
        except Exception as e:
            logger.error(f"Notification sending failed: {str(e)}")
            return []
    
    # Helper methods (keep existing implementations)
    def _get_platform_from_agent(self, agent: Agent) -> str:
        """Get platform from agent OS"""
        if not agent or not agent.OperatingSystem:
            return 'All'
        
        os_lower = agent.OperatingSystem.lower()
        if 'windows' in os_lower:
            return 'Windows'
        elif 'linux' in os_lower:
            return 'Linux'
        elif 'mac' in os_lower:
            return 'macOS'
        else:
            return 'All'
    
    def _get_active_rules(self, session: Session, platform: str) -> List[DetectionRule]:
        """Get active detection rules for platform"""
        try:
            query = session.query(DetectionRule).filter(DetectionRule.IsActive == True)
            
            if platform != 'All':
                query = query.filter(
                    (DetectionRule.Platform == 'All') | (DetectionRule.Platform == platform)
                )
            
            return query.order_by(DetectionRule.Priority.desc()).all()
        except Exception as e:
            logger.error(f"Error getting active rules: {e}")
            return []
    
    def _evaluate_rule(self, event: Event, rule: DetectionRule) -> bool:
        """Evaluate if event matches detection rule"""
        try:
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                return False
            
            if isinstance(rule_condition, dict):
                return self._evaluate_rule_conditions(event, rule_condition)
            
            return False
            
        except Exception as e:
            logger.error(f"Rule evaluation failed for rule {rule.RuleID}: {str(e)}")
            return False
    
    def _evaluate_rule_conditions(self, event: Event, conditions: Dict) -> bool:
        """Evaluate rule conditions against event"""
        try:
            matches = 0
            total_conditions = 0
            
            for field, value in conditions.items():
                if field == 'logic':
                    continue
                
                total_conditions += 1
                event_field = self._map_rule_field(field)
                event_value = getattr(event, event_field, None)
                
                if event_value and self._check_condition_match(event_value, value):
                    matches += 1
            
            if total_conditions == 0:
                return False
            
            logic = conditions.get('logic', 'AND')
            if logic.upper() == 'OR':
                return matches > 0
            else:
                return matches == total_conditions
                
        except Exception as e:
            logger.error(f"Condition evaluation failed: {str(e)}")
            return False
    
    def _map_rule_field(self, field: str) -> str:
        """Map rule field to event model field"""
        mapping = {
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
        return mapping.get(field, field)
    
    def _check_condition_match(self, event_value: Any, expected_value: Any) -> bool:
        """Check if event value matches expected value"""
        try:
            if isinstance(expected_value, list):
                return any(str(v).lower() in str(event_value).lower() for v in expected_value)
            else:
                return str(expected_value).lower() in str(event_value).lower()
        except:
            return False
    
    def _get_rule_risk_score(self, rule: DetectionRule) -> int:
        """Calculate risk score for rule match"""
        severity_scores = {
            'Low': 20,
            'Medium': 40,
            'High': 70,
            'Critical': 90
        }
        base_score = severity_scores.get(rule.AlertSeverity, 40)
        priority_multiplier = (rule.Priority or 50) / 100
        return int(base_score * priority_multiplier)
    
    def _get_threat_risk_score(self, threat: Threat) -> int:
        """Calculate risk score for threat match"""
        severity_scores = {
            'Low': 25,
            'Medium': 50,
            'High': 80,
            'Critical': 95
        }
        base_score = severity_scores.get(threat.Severity, 50)
        confidence_multiplier = float(threat.Confidence) if threat.Confidence else 0.7
        return int(base_score * confidence_multiplier)
    
    def _calculate_risk_score(self, detection_results: Dict) -> int:
        """Calculate overall risk score with bonuses"""
        risk_score = detection_results.get('risk_score', 0)
        
        # Bonus for multiple detection methods
        methods_count = len(detection_results.get('detection_methods', []))
        if methods_count > 1:
            risk_score += methods_count * 10
        
        # Bonus for multiple matches
        total_matches = (len(detection_results.get('matched_rules', [])) + 
                        len(detection_results.get('matched_threats', [])))
        if total_matches > 1:
            risk_score += min(total_matches * 15, 40)
        
        # Bonus for behavioral indicators
        behavioral_count = len(detection_results.get('behavioral_indicators', []))
        if behavioral_count >= 3:
            risk_score += behavioral_count * 5
        
        return min(risk_score, 100)  # Cap at 100
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score"""
        if risk_score >= 80:
            return 'Malicious'
        elif risk_score >= 50:
            return 'Suspicious'
        else:
            return 'None'
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _merge_results(self, base_results: Dict, new_results: Dict) -> Dict:
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
            
            # Merge details
            for detail_key in ['rule_details', 'threat_details', 'behavioral_indicators']:
                base_details = base_results.get(detail_key, [])
                new_details = new_results.get(detail_key, [])
                base_results[detail_key] = base_details + new_details
            
            # Add risk scores
            base_results['risk_score'] = (base_results.get('risk_score', 0) + 
                                        new_results.get('risk_score', 0))
            
            return base_results
            
        except Exception as e:
            logger.error(f"Results merge failed: {str(e)}")
            return base_results
    
    def _generate_recommendations(self, detection_results: Dict) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        try:
            risk_score = detection_results.get('risk_score', 0)
            behavioral_indicators = detection_results.get('behavioral_indicators', [])
            matched_rules = detection_results.get('matched_rules', [])
            matched_threats = detection_results.get('matched_threats', [])
            
            # Critical risk recommendations
            if risk_score >= 80:
                recommendations.extend([
                    "🚨 IMMEDIATE ACTION REQUIRED",
                    "Isolate the affected endpoint immediately",
                    "Investigate all related processes and files",
                    "Check for lateral movement indicators",
                    "Review recent user activities"
                ])
            
            # High risk recommendations
            elif risk_score >= 60:
                recommendations.extend([
                    "⚠️ HIGH PRIORITY INVESTIGATION",
                    "Monitor endpoint activity closely",
                    "Review security event logs",
                    "Consider temporary access restrictions"
                ])
            
            # Medium risk recommendations
            elif risk_score >= 40:
                recommendations.extend([
                    "📋 MONITOR AND ANALYZE",
                    "Increase logging on this endpoint",
                    "Review security policies",
                    "Schedule detailed security scan"
                ])
            
            # Specific recommendations based on detection type
            if matched_threats:
                recommendations.extend([
                    "🔍 THREAT INTELLIGENCE MATCH",
                    "Cross-reference with other security tools",
                    "Check threat feed sources for updates",
                    "Review similar indicators across environment"
                ])
            
            if matched_rules:
                recommendations.extend([
                    "📏 RULE-BASED DETECTION",
                    "Validate detection rule accuracy",
                    "Fine-tune rule parameters if needed",
                    "Review rule coverage for similar threats"
                ])
            
            # Behavioral-specific recommendations
            process_behaviors = [b for b in behavioral_indicators if 'process' in b.lower()]
            if process_behaviors:
                recommendations.extend([
                    "🔧 PROCESS BEHAVIOR ANALYSIS",
                    "Review process execution chains",
                    "Implement application whitelisting",
                    "Monitor for privilege escalation"
                ])
            
            network_behaviors = [b for b in behavioral_indicators if 'network' in b.lower() or 'connection' in b.lower()]
            if network_behaviors:
                recommendations.extend([
                    "🌐 NETWORK BEHAVIOR ANALYSIS",
                    "Review firewall rules and network segmentation",
                    "Monitor for data exfiltration patterns",
                    "Implement network traffic analysis"
                ])
            
            file_behaviors = [b for b in behavioral_indicators if 'file' in b.lower() or 'location' in b.lower()]
            if file_behaviors:
                recommendations.extend([
                    "📁 FILE BEHAVIOR ANALYSIS",
                    "Scan affected files with multiple engines",
                    "Review file system permissions",
                    "Implement file integrity monitoring"
                ])
            
            # General security recommendations
            if not recommendations:
                recommendations.extend([
                    "✅ STANDARD MONITORING",
                    "Continue regular security monitoring",
                    "Maintain updated threat intelligence",
                    "Review security awareness training"
                ])
            
            # Always add forensic recommendations for high-risk events
            if risk_score >= 70:
                recommendations.extend([
                    "🔬 FORENSIC ANALYSIS",
                    "Preserve system state for forensic analysis",
                    "Document all investigative steps",
                    "Consider engaging incident response team"
                ])
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
            recommendations.append("Review security posture and investigate manually")
        
        return recommendations
    
    def get_stats(self) -> Dict:
        """Get comprehensive detection engine statistics"""
        try:
            total_events = max(self.stats['events_analyzed'], 1)
            avg_processing_time = self.stats['total_processing_time'] / total_events
            
            return {
                'events_analyzed': self.stats['events_analyzed'],
                'threats_detected': self.stats['threats_detected'],
                'alerts_created': self.stats['alerts_created'],
                'notifications_sent': self.stats['notifications_sent'],
                'rules_matched': self.stats['rules_matched'],
                'detection_rate': round((self.stats['threats_detected'] / total_events) * 100, 2),
                'alert_creation_rate': round((self.stats['alerts_created'] / total_events) * 100, 2),
                'notification_rate': round((self.stats['notifications_sent'] / total_events) * 100, 2),
                'average_processing_time_ms': round(avg_processing_time * 1000, 2),
                'total_processing_time': round(self.stats['total_processing_time'], 3)
            }
        except Exception as e:
            logger.error(f"Stats calculation failed: {e}")
            return {}
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'rules_matched': 0,
            'total_processing_time': 0.0
        }
        logger.info("📊 Detection engine statistics reset")
    
    def get_health_status(self) -> Dict:
        """Get detection engine health status"""
        try:
            stats = self.get_stats()
            
            # Determine health based on performance
            avg_processing_time = stats.get('average_processing_time_ms', 0)
            detection_rate = stats.get('detection_rate', 0)
            
            if avg_processing_time > 1000:  # > 1 second
                health_status = "degraded"
                issues = ["High processing latency"]
            elif detection_rate > 50:  # > 50% detection rate might indicate too many false positives
                health_status = "warning"
                issues = ["High detection rate - check for false positives"]
            else:
                health_status = "healthy"
                issues = []
            
            return {
                'status': health_status,
                'issues': issues,
                'performance_metrics': stats,
                'rules_cache_size': len(self.rules_cache),
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Health status check failed: {e}")
            return {
                'status': 'error',
                'issues': [f"Health check failed: {str(e)}"],
                'last_updated': datetime.now().isoformat()
            }

# Global detection engine instance
detection_engine = DetectionEngine()