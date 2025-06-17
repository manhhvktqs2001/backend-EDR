"""
Detection Engine Service
Core detection logic for analyzing events and generating alerts
"""

import logging
import json
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from sqlalchemy.orm import Session
from ..models.agent import Agent
from ..models.event import Event
from ..models.alert import Alert
from ..models.threat import Threat
from ..models.detection_rule import DetectionRule
from ..config import config

logger = logging.getLogger('detection_engine')

class DetectionEngine:
    """Core detection engine for EDR system"""
    
    def __init__(self):
        self.detection_config = config['detection']
        self.alert_config = config['alert']
        self.rules_cache = {}
        self.threats_cache = {}
        self.cache_timestamp = None
        self.cache_ttl = self.detection_config['threat_intel_cache_ttl']
    
    def analyze_event(self, session: Session, event: Event) -> Optional[Dict]:
        """
        Analyze event through detection engine
        Returns detection results with alerts and risk scoring
        """
        try:
            detection_results = {
                'event_id': event.EventID,
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'matched_threats': [],
                'alerts_generated': [],
                'recommendations': []
            }
            
            # Step 1: Threat Intelligence Check
            threat_results = self._check_threat_intelligence(session, event)
            if threat_results:
                detection_results.update(threat_results)
            
            # Step 2: Detection Rules Check
            rules_results = self._check_detection_rules(session, event)
            if rules_results:
                detection_results = self._merge_detection_results(detection_results, rules_results)
            
            # Step 3: Calculate overall risk score
            detection_results['risk_score'] = self._calculate_risk_score(detection_results)
            
            # Step 4: Determine threat level
            detection_results['threat_level'] = self._determine_threat_level(detection_results['risk_score'])
            
            # Step 5: Generate alerts if necessary
            if detection_results['risk_score'] >= self.detection_config['risk_score_threshold']:
                alerts = self._generate_alerts(session, event, detection_results)
                detection_results['alerts_generated'] = alerts
                detection_results['threat_detected'] = True
            
            logger.debug(f"Event {event.EventID} analyzed - Risk: {detection_results['risk_score']}, Threat: {detection_results['threat_level']}")
            
            return detection_results
            
        except Exception as e:
            logger.error(f"Detection engine analysis failed for event {event.EventID}: {str(e)}")
            return None
    
    def _check_threat_intelligence(self, session: Session, event: Event) -> Optional[Dict]:
        """Check event against threat intelligence database"""
        try:
            if not self.detection_config['threat_intel_enabled']:
                return None
            
            results = {
                'detection_methods': ['Threat Intelligence'],
                'matched_threats': [],
                'risk_score': 0
            }
            
            # Check file hashes
            if event.ProcessHash:
                threat = Threat.check_hash(session, event.ProcessHash)
                if threat:
                    results['matched_threats'].append(threat.ThreatID)
                    results['risk_score'] += self._get_threat_risk_score(threat)
                    logger.info(f"Malicious hash detected: {event.ProcessHash} - {threat.ThreatName}")
            
            if event.FileHash:
                threat = Threat.check_hash(session, event.FileHash)
                if threat:
                    results['matched_threats'].append(threat.ThreatID)
                    results['risk_score'] += self._get_threat_risk_score(threat)
                    logger.info(f"Malicious file hash detected: {event.FileHash} - {threat.ThreatName}")
            
            # Check IP addresses
            if event.DestinationIP:
                threat = Threat.check_ip(session, event.DestinationIP)
                if threat:
                    results['matched_threats'].append(threat.ThreatID)
                    results['risk_score'] += self._get_threat_risk_score(threat)
                    logger.info(f"Malicious IP detected: {event.DestinationIP} - {threat.ThreatName}")
            
            # Check domains (would need domain extraction from URLs/processes)
            
            return results if results['matched_threats'] else None
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed: {str(e)}")
            return None
    
    def _check_detection_rules(self, session: Session, event: Event) -> Optional[Dict]:
        """Check event against detection rules"""
        try:
            if not self.detection_config['rules_enabled']:
                return None
            
            # Get active rules for event platform
            agent = session.query(Agent).filter(Agent.AgentID == event.AgentID).first()
            platform = 'Windows' if agent and 'windows' in agent.OperatingSystem.lower() else 'Linux'
            
            active_rules = DetectionRule.get_active_rules(session, platform)
            
            results = {
                'detection_methods': ['Rules Engine'],
                'matched_rules': [],
                'risk_score': 0
            }
            
            for rule in active_rules:
                if self._evaluate_rule(event, rule):
                    results['matched_rules'].append(rule.RuleID)
                    results['risk_score'] += self._get_rule_risk_score(rule)
                    logger.info(f"Detection rule matched: {rule.RuleName} for event {event.EventID}")
            
            return results if results['matched_rules'] else None
            
        except Exception as e:
            logger.error(f"Detection rules check failed: {str(e)}")
            return None
    
    def _evaluate_rule(self, event: Event, rule: DetectionRule) -> bool:
        """Evaluate if event matches detection rule"""
        try:
            rule_condition = rule.get_rule_condition()
            if not rule_condition:
                return False
            
            # Get rule conditions
            conditions = rule_condition.get('conditions', [])
            logic = rule_condition.get('logic', 'AND')
            
            # Evaluate conditions
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
                return any(condition_results)  # Default to OR
                
        except Exception as e:
            logger.error(f"Rule evaluation failed for rule {rule.RuleID}: {str(e)}")
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
            logger.error(f"Condition evaluation failed: {str(e)}")
            return False
    
    def _is_numeric(self, value) -> bool:
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
            risk_score += 10
        
        # Bonus for multiple matches
        total_matches = len(detection_results.get('matched_rules', [])) + len(detection_results.get('matched_threats', []))
        if total_matches > 1:
            risk_score += min(total_matches * 5, 20)
        
        # Cap at 100
        return min(risk_score, 100)
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score"""
        if risk_score >= 80:
            return 'Malicious'
        elif risk_score >= 50:
            return 'Suspicious'
        else:
            return 'None'
    
    def _generate_alerts(self, session: Session, event: Event, detection_results: Dict) -> List[int]:
        """Generate alerts based on detection results"""
        try:
            alerts_generated = []
            
            # Generate alerts for matched rules
            for rule_id in detection_results.get('matched_rules', []):
                rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
                if rule and not rule.TestMode:
                    alert = self._create_rule_alert(event, rule, detection_results)
                    session.add(alert)
                    session.flush()
                    alerts_generated.append(alert.AlertID)
                    logger.info(f"Alert generated from rule {rule.RuleName}: Alert ID {alert.AlertID}")
            
            # Generate alerts for matched threats
            for threat_id in detection_results.get('matched_threats', []):
                threat = session.query(Threat).filter(Threat.ThreatID == threat_id).first()
                if threat:
                    alert = self._create_threat_alert(event, threat, detection_results)
                    session.add(alert)
                    session.flush()
                    alerts_generated.append(alert.AlertID)
                    logger.info(f"Alert generated from threat {threat.ThreatName}: Alert ID {alert.AlertID}")
            
            return alerts_generated
            
        except Exception as e:
            logger.error(f"Alert generation failed: {str(e)}")
            return []
    
    def _create_rule_alert(self, event: Event, rule: DetectionRule, detection_results: Dict) -> Alert:
        """Create alert from detection rule match"""
        return Alert.create_alert(
            agent_id=str(event.AgentID),
            alert_type=rule.AlertType,
            title=rule.AlertTitle,
            severity=rule.AlertSeverity,
            detection_method='Rules',
            EventID=event.EventID,
            RuleID=rule.RuleID,
            Description=rule.AlertDescription,
            RiskScore=detection_results['risk_score'],
            MitreTactic=rule.MitreTactic,
            MitreTechnique=rule.MitreTechnique,
            Priority=self._map_severity_to_priority(rule.AlertSeverity)
        )
    
    def _create_threat_alert(self, event: Event, threat: Threat, detection_results: Dict) -> Alert:
        """Create alert from threat intelligence match"""
        return Alert.create_alert(
            agent_id=str(event.AgentID),
            alert_type=f"{threat.ThreatCategory} Detection",
            title=f"Threat Detected: {threat.ThreatName}",
            severity=threat.Severity,
            detection_method='Threat Intelligence',
            EventID=event.EventID,
            ThreatID=threat.ThreatID,
            Description=threat.Description,
            RiskScore=detection_results['risk_score'],
            MitreTactic=threat.MitreTactic,
            MitreTechnique=threat.MitreTechnique,
            Priority=self._map_severity_to_priority(threat.Severity),
            Confidence=float(threat.Confidence) if threat.Confidence else 0.8
        )
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map severity to priority level"""
        mapping = {
            'Info': 'Low',
            'Low': 'Low',
            'Medium': 'Medium',
            'High': 'High',
            'Critical': 'Critical'
        }
        return mapping.get(severity, 'Medium')
    
    def _merge_detection_results(self, results1: Dict, results2: Dict) -> Dict:
        """Merge detection results from multiple sources"""
        merged = results1.copy()
        
        # Merge lists
        for key in ['detection_methods', 'matched_rules', 'matched_threats']:
            if key in results2:
                merged[key] = list(set(merged.get(key, []) + results2[key]))
        
        # Sum risk scores
        merged['risk_score'] = merged.get('risk_score', 0) + results2.get('risk_score', 0)
        
        return merged

# Global detection engine instance
detection_engine = DetectionEngine()