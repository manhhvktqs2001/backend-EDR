# app/services/detection_engine_sync.py - Synchronous Detection Engine
"""
Synchronous Detection Engine
Core detection logic without async dependencies for reliable rule evaluation
"""

import logging
import json
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..models.agent import Agent
from ..models.event import Event
from ..models.alert import Alert
from ..models.threat import Threat
from ..models.detection_rule import DetectionRule
from ..config import config

logger = logging.getLogger('detection_engine_sync')

class DetectionEngineSync:
    """Synchronous detection engine for reliable rule evaluation"""
    
    def __init__(self):
        self.detection_config = config['detection']
        self.alert_config = config['alert']
        self.rules_cache = {}
        self.cache_timestamp = None
        
        # Performance counters
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'rules_matched': 0
        }
    
    def analyze_event_sync(self, session: Session, event: Event) -> Optional[Dict]:
        """
        Synchronous event analysis with rule evaluation and alert generation - ENHANCED LOGGING
        """
        try:
            logger.info(f"🔍 Analyzing event {event.EventID}: {event.EventType}")
            
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
                'alerts_generated': [],
                'behavioral_indicators': [],
                'recommendations': [],
                'analysis_time': datetime.now().isoformat()
            }
            
            # Step 1: Check detection rules
            rules_results = self._check_detection_rules(session, event)
            if rules_results:
                detection_results = self._merge_results(detection_results, rules_results)
                self.stats['rules_matched'] += len(rules_results.get('matched_rules', []))
            
            # Step 2: Check threat intelligence
            threat_results = self._check_threat_intelligence(session, event)
            if threat_results:
                detection_results = self._merge_results(detection_results, threat_results)
                self.stats['threats_detected'] += len(threat_results.get('matched_threats', []))
            
            # Step 3: Behavioral analysis
            behavioral_results = self._analyze_behavioral_patterns(event)
            if behavioral_results:
                detection_results = self._merge_results(detection_results, behavioral_results)
            
            # Step 4: Calculate risk score
            detection_results['risk_score'] = self._calculate_risk_score(detection_results)
            
            # Step 5: Determine threat level
            detection_results['threat_level'] = self._determine_threat_level(detection_results['risk_score'])
            
            # Step 6: Generate alerts if threshold exceeded
            risk_threshold = self.detection_config.get('risk_score_threshold', 70)
            if detection_results['risk_score'] >= risk_threshold:
                alerts = self._generate_alerts(session, event, detection_results)
                detection_results['alerts_generated'] = alerts
                detection_results['threat_detected'] = True
                self.stats['alerts_generated'] += len(alerts)
            
            # Step 7: Generate recommendations
            detection_results['recommendations'] = self._generate_recommendations(detection_results)
            
            # ENHANCED: Log detection results
            if detection_results.get('threat_detected'):
                logger.info(f"🚨 THREAT DETECTED - Event {event.EventID}:")
                logger.info(f"   Risk Score: {detection_results.get('risk_score', 0)}")
                logger.info(f"   Threat Level: {detection_results.get('threat_level', 'None')}")
                logger.info(f"   Methods: {', '.join(detection_results.get('detection_methods', []))}")
                logger.info(f"   Alerts Generated: {len(detection_results.get('alerts_generated', []))}")
            
            logger.debug(f"Event {event.EventID} analyzed - Risk: {detection_results['risk_score']}, "
                        f"Threat: {detection_results['threat_level']}, "
                        f"Methods: {detection_results['detection_methods']}")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"💥 Detection engine analysis failed for event {event.EventID}: {str(e)}")
            return None
    
    def _check_detection_rules(self, session: Session, event: Event) -> Optional[Dict]:
        """Check event against active detection rules"""
        try:
            if not self.detection_config.get('rules_enabled', False):
                return None
            
            # Get agent platform for rule filtering
            agent = session.query(Agent).filter(Agent.AgentID == event.AgentID).first()
            platform = self._get_platform_from_agent(agent)
            
            # Get active rules
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
                        
                        logger.info(f"🔍 Rule matched: {rule.RuleName} for event {event.EventID}")
                except Exception as e:
                    logger.error(f"Rule evaluation error for rule {rule.RuleID}: {e}")
                    continue
            
            return results if results['matched_rules'] else None
            
        except Exception as e:
            logger.error(f"Detection rules check failed: {str(e)}")
            return None
    
    def _check_threat_intelligence(self, session: Session, event: Event) -> Optional[Dict]:
        """Check event against threat intelligence database"""
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
            hash_fields = ['ProcessHash', 'FileHash']
            for hash_field in hash_fields:
                hash_value = getattr(event, hash_field, None)
                if hash_value:
                    threat = Threat.check_hash(session, hash_value)
                    if threat:
                        results['matched_threats'].append(threat.ThreatID)
                        results['risk_score'] += self._get_threat_risk_score(threat)
                        results['threat_details'].append({
                            'threat_id': threat.ThreatID,
                            'threat_name': threat.ThreatName,
                            'threat_type': threat.ThreatType,
                            'severity': threat.Severity,
                            'hash_type': hash_field,
                            'hash_value': hash_value
                        })
                        logger.warning(f"🚨 Threat hash detected: {hash_value} -> {threat.ThreatName}")
            
            # Check IP addresses
            ip_fields = ['SourceIP', 'DestinationIP']
            for ip_field in ip_fields:
                ip_value = getattr(event, ip_field, None)
                if ip_value:
                    threat = Threat.check_ip(session, ip_value)
                    if threat:
                        results['matched_threats'].append(threat.ThreatID)
                        results['risk_score'] += self._get_threat_risk_score(threat)
                        results['threat_details'].append({
                            'threat_id': threat.ThreatID,
                            'threat_name': threat.ThreatName,
                            'threat_type': threat.ThreatType,
                            'severity': threat.Severity,
                            'ip_type': ip_field,
                            'ip_value': ip_value
                        })
                        logger.warning(f"🚨 Malicious IP detected: {ip_value} -> {threat.ThreatName}")
            
            return results if results['matched_threats'] else None
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed: {str(e)}")
            return None
    
    def _analyze_behavioral_patterns(self, event: Event) -> Optional[Dict]:
        """Analyze behavioral patterns in the event"""
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
                results['risk_score'] += len(indicators) * 10
            
            # File behavior analysis
            elif event.EventType == 'File':
                indicators = self._check_file_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 8
            
            # Network behavior analysis
            elif event.EventType == 'Network':
                indicators = self._check_network_behavior(event)
                results['behavioral_indicators'].extend(indicators)
                results['risk_score'] += len(indicators) * 12
            
            return results if results['behavioral_indicators'] else None
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {str(e)}")
            return None
    
    def _check_process_behavior(self, event: Event) -> List[str]:
        """Check for suspicious process behaviors"""
        indicators = []
        
        if not event.ProcessName or not event.CommandLine:
            return indicators
        
        process_name = event.ProcessName.lower()
        command_line = event.CommandLine.lower()
        
        # Suspicious processes
        suspicious_processes = [
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'bitsadmin.exe'
        ]
        
        if process_name in suspicious_processes:
            indicators.append(f"Suspicious process: {event.ProcessName}")
        
        # Suspicious command patterns
        suspicious_patterns = [
            r'-encodedcommand',
            r'-windowstyle\s+hidden',
            r'-executionpolicy\s+bypass',
            r'invoke-expression',
            r'downloadstring',
            r'base64',
            r'certutil.*-urlcache',
            r'bitsadmin.*\/transfer'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, command_line, re.IGNORECASE):
                indicators.append(f"Suspicious command pattern: {pattern}")
        
        return indicators
    
    def _check_file_behavior(self, event: Event) -> List[str]:
        """Check for suspicious file behaviors"""
        indicators = []
        
        if not event.FilePath:
            return indicators
        
        file_path = event.FilePath.lower()
        
        # Suspicious locations
        suspicious_locations = [
            r'\\temp\\', r'\\users\\public\\', r'\\appdata\\roaming\\',
            r'\\windows\\temp\\', r'\\programdata\\'
        ]
        
        for location in suspicious_locations:
            if re.search(location, file_path, re.IGNORECASE):
                indicators.append(f"Suspicious file location: {location}")
        
        # Suspicious extensions in temp directories
        if event.FileExtension and 'temp' in file_path:
            dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif']
            if event.FileExtension.lower() in dangerous_extensions:
                indicators.append(f"Dangerous file in temp: {event.FileExtension}")
        
        return indicators
    
    def _check_network_behavior(self, event: Event) -> List[str]:
        """Check for suspicious network behaviors"""
        indicators = []
        
        # Suspicious ports
        if event.DestinationPort:
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 4444, 6667]
            if event.DestinationPort in suspicious_ports:
                indicators.append(f"Connection to suspicious port: {event.DestinationPort}")
        
        # External connections
        if event.DestinationIP and not self._is_private_ip(event.DestinationIP):
            indicators.append("External network connection")
        
        return indicators
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
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
            
            # Filter by platform
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
            
            # Apply logic
            logic = conditions.get('logic', 'AND')
            if logic.upper() == 'OR':
                return matches > 0
            else:  # Default AND
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
            'Low': 15,
            'Medium': 30,
            'High': 60,
            'Critical': 85
        }
        base_score = severity_scores.get(rule.AlertSeverity, 30)
        priority_multiplier = (rule.Priority or 50) / 100
        return int(base_score * priority_multiplier)
    
    def _get_threat_risk_score(self, threat: Threat) -> int:
        """Calculate risk score for threat match"""
        severity_scores = {
            'Low': 20,
            'Medium': 40,
            'High': 70,
            'Critical': 90
        }
        base_score = severity_scores.get(threat.Severity, 40)
        confidence_multiplier = float(threat.Confidence) if threat.Confidence else 0.5
        return int(base_score * confidence_multiplier)
    
    def _calculate_risk_score(self, detection_results: Dict) -> int:
        """Calculate overall risk score"""
        risk_score = detection_results.get('risk_score', 0)
        
        # Bonus for multiple detection methods
        methods_count = len(detection_results.get('detection_methods', []))
        if methods_count > 1:
            risk_score += methods_count * 5
        
        # Bonus for multiple matches
        total_matches = (len(detection_results.get('matched_rules', [])) + 
                        len(detection_results.get('matched_threats', [])))
        if total_matches > 1:
            risk_score += min(total_matches * 10, 30)
        
        return min(risk_score, 100)  # Cap at 100
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score - FIXED"""
        if risk_score >= 85:
            return 'Malicious'  # Changed from 'Critical'
        elif risk_score >= 50:
            return 'Suspicious'  # Changed from 'High'
        else:
            return 'None'  # All other cases
    
    def _generate_alerts(self, session: Session, event: Event, detection_results: Dict) -> List[int]:
        """Generate alerts for detected threats"""
        try:
            alerts_generated = []
            
            # Generate alerts for matched rules
            for rule_detail in detection_results.get('rule_details', []):
                try:
                    rule_id = rule_detail['rule_id']
                    rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
                    
                    if rule and not rule.TestMode:
                        alert = self._create_rule_alert(event, rule, detection_results)
                        if alert:
                            session.add(alert)
                            session.flush()  # Get alert ID
                            alerts_generated.append(alert.AlertID)
                            logger.info(f"🚨 Alert created: {rule.RuleName} -> Alert #{alert.AlertID}")
                except Exception as e:
                    logger.error(f"Failed to create rule alert: {e}")
                    continue
            
            # Generate alerts for threat matches
            for threat_detail in detection_results.get('threat_details', []):
                try:
                    threat_id = threat_detail['threat_id']
                    threat = session.query(Threat).filter(Threat.ThreatID == threat_id).first()
                    
                    if threat:
                        alert = self._create_threat_alert(event, threat, detection_results)
                        if alert:
                            session.add(alert)
                            session.flush()
                            alerts_generated.append(alert.AlertID)
                            logger.warning(f"🚨 Threat alert created: {threat.ThreatName} -> Alert #{alert.AlertID}")
                except Exception as e:
                    logger.error(f"Failed to create threat alert: {e}")
                    continue
            
            # Generate behavioral alert if many indicators
            behavioral_indicators = detection_results.get('behavioral_indicators', [])
            if len(behavioral_indicators) >= 3:
                try:
                    alert = self._create_behavioral_alert(event, behavioral_indicators, detection_results)
                    if alert:
                        session.add(alert)
                        session.flush()
                        alerts_generated.append(alert.AlertID)
                        logger.warning(f"🚨 Behavioral alert created: {len(behavioral_indicators)} indicators -> Alert #{alert.AlertID}")
                except Exception as e:
                    logger.error(f"Failed to create behavioral alert: {e}")
            
            return alerts_generated
            
        except Exception as e:
            logger.error(f"Alert generation failed: {str(e)}")
            return []
    
    def _create_rule_alert(self, event: Event, rule: DetectionRule, detection_results: Dict) -> Optional[Alert]:
        """Create alert for matched detection rule - FIXED"""
        try:
            alert_description = f"Detection rule '{rule.RuleName}' triggered"
            if rule.AlertDescription:
                alert_description += f": {rule.AlertDescription}"
            
            alert = Alert.create_alert(
                agent_id=str(event.AgentID),
                alert_type=rule.AlertType or 'Rule Detection',
                title=rule.AlertTitle or f"Rule Detection: {rule.RuleName}",
                severity=rule.AlertSeverity or 'Medium',
                detection_method="Rules Engine",
                Description=alert_description,
                EventID=event.EventID,
                RuleID=rule.RuleID,
                MitreTactic=rule.MitreTactic,
                MitreTechnique=rule.MitreTechnique,
                RiskScore=detection_results.get('risk_score', 0),
                Confidence=0.8
            )
            
            logger.info(f"🚨 Alert created: {rule.RuleName} -> {rule.AlertSeverity}")
            return alert
            
        except Exception as e:
            logger.error(f"Rule alert creation failed: {str(e)}")
            return None
    
    def _create_threat_alert(self, event: Event, threat: Threat, detection_results: Dict) -> Optional[Alert]:
        """Create alert for threat intelligence match"""
        try:
            description = f"Threat detected: {threat.ThreatName}"
            if threat.Description:
                description += f" - {threat.Description}"
            
            alert = Alert(
                EventID=event.EventID,
                AgentID=event.AgentID,
                RuleID=None,
                ThreatID=threat.ThreatID,
                AlertType='Threat Intelligence',
                Title=f"Threat Detected: {threat.ThreatName}",
                Description=description,
                Severity=threat.Severity,
                Priority=threat.Severity,
                Confidence=float(threat.Confidence) if threat.Confidence else 0.7,
                DetectionMethod='Threat Intelligence',
                RiskScore=detection_results.get('risk_score', 0),
                MitreTactic=threat.MitreTactic,
                MitreTechnique=threat.MitreTechnique,
                Status='Open',
                FirstDetected=datetime.now(),
                LastDetected=datetime.now(),
                EventCount=1,
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
            description = f"Multiple suspicious behaviors detected: {len(behavioral_indicators)} indicators"
            
            # Determine severity based on number of indicators
            if len(behavioral_indicators) >= 5:
                severity = 'High'
            elif len(behavioral_indicators) >= 4:
                severity = 'Medium'
            else:
                severity = 'Low'
            
            alert = Alert(
                EventID=event.EventID,
                AgentID=event.AgentID,
                RuleID=None,
                ThreatID=None,
                AlertType='Behavioral Analysis',
                Title="Suspicious Behavior Detected",
                Description=description,
                Severity=severity,
                Priority=severity,
                Confidence=0.6,  # Medium confidence for behavioral
                DetectionMethod='Behavioral Analysis',
                RiskScore=detection_results.get('risk_score', 0),
                MitreTactic=None,
                MitreTechnique=None,
                Status='Open',
                FirstDetected=datetime.now(),
                LastDetected=datetime.now(),
                EventCount=1,
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Behavioral alert creation failed: {str(e)}")
            return None
    
    def _generate_recommendations(self, detection_results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        try:
            risk_score = detection_results.get('risk_score', 0)
            behavioral_indicators = detection_results.get('behavioral_indicators', [])
            
            # High-risk recommendations
            if risk_score >= 70:
                recommendations.append("Immediately investigate this incident")
                recommendations.append("Consider isolating the affected agent")
                recommendations.append("Review related events from the same agent")
            
            # Medium-risk recommendations
            elif risk_score >= 40:
                recommendations.append("Monitor agent activity closely")
                recommendations.append("Review security policies")
                recommendations.append("Consider additional endpoint hardening")
            
            # Behavioral-specific recommendations
            if any('Suspicious process' in indicator for indicator in behavioral_indicators):
                recommendations.append("Review process execution policies")
                recommendations.append("Consider application whitelisting")
            
            if any('External network' in indicator for indicator in behavioral_indicators):
                recommendations.append("Review network access controls")
                recommendations.append("Consider implementing network segmentation")
            
            # Rule-specific recommendations
            if detection_results.get('matched_rules'):
                recommendations.append("Review and tune detection rules")
                recommendations.append("Verify rule effectiveness")
            
            # General recommendations
            if not recommendations:
                recommendations.append("Continue monitoring")
                recommendations.append("Review security awareness training")
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
            recommendations.append("Review security posture")
        
        return recommendations
    
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
    
    def get_stats(self) -> Dict:
        """Get detection engine statistics"""
        return {
            'events_analyzed': self.stats['events_analyzed'],
            'threats_detected': self.stats['threats_detected'],
            'alerts_generated': self.stats['alerts_generated'],
            'rules_matched': self.stats['rules_matched'],
            'detection_rate': (self.stats['threats_detected'] / max(self.stats['events_analyzed'], 1)) * 100,
            'alert_rate': (self.stats['alerts_generated'] / max(self.stats['events_analyzed'], 1)) * 100
        }
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_analyzed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'rules_matched': 0
        }

    def _alert_to_dict(self, alert: Alert) -> Dict:
        """Convert alert object to dictionary - FIXED"""
        return {
            'alert_id': alert.AlertID,  # This will be the actual ID, not None
            'event_id': alert.EventID,
            'agent_id': str(alert.AgentID),
            'rule_id': alert.RuleID,
            'threat_id': alert.ThreatID,
            'alert_type': alert.AlertType,
            'severity': alert.Severity,
            'title': alert.Title,
            'description': alert.Description,
            'status': alert.Status,
            'risk_score': alert.RiskScore,
            'created_at': alert.CreatedAt.isoformat() if alert.CreatedAt else None,
            'detection_method': getattr(alert, 'DetectionMethod', 'Unknown')
        }


# Global synchronous detection engine instance
detection_engine = DetectionEngineSync()