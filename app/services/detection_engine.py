# app/services/detection_engine_fixed.py - COMPLETELY FIXED VERSION
"""
Detection Engine - COMPLETELY FIXED VERSION
Handles event analysis, rule evaluation, and alert notifications
"""

import logging
import re
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from ..models.event import Event
from ..models.agent import Agent
from ..models.alert import Alert
from ..models.detection_rule import DetectionRule
from ..models.threat import Threat
from ..config import config

logger = logging.getLogger(__name__)

class DetectionEngine:
    """Core detection engine implementation - FIXED VERSION"""
    
    # Database-compliant threat levels
    THREAT_LEVELS = {
        'None': 0,
        'Suspicious': 50,
        'Malicious': 80
    }
    
    # Severity scoring
    SEVERITY_SCORES = {
        'Critical': 100,
        'High': 80,
        'Medium': 60,
        'Low': 40,
        'Info': 20
    }
    
    # Field mappings for rule evaluation
    FIELD_MAPPINGS = {
        'process_name': 'ProcessName',
        'process_path': 'ProcessPath',
        'command_line': 'CommandLine',
        'process_id': 'ProcessID',
        'parent_pid': 'ParentPID',
        'parent_process_name': 'ParentProcessName',
        'process_user': 'ProcessUser',
        'process_hash': 'ProcessHash',
        'file_name': 'FileName',
        'file_path': 'FilePath',
        'file_hash': 'FileHash',
        'file_size': 'FileSize',
        'file_extension': 'FileExtension',
        'file_operation': 'FileOperation',
        'source_ip': 'SourceIP',
        'destination_ip': 'DestinationIP',
        'source_port': 'SourcePort',
        'destination_port': 'DestinationPort',
        'protocol': 'Protocol',
        'registry_key': 'RegistryKey',
        'registry_value_name': 'RegistryValueName',
        'registry_value_data': 'RegistryValueData',
        'event_type': 'EventType',
        'event_action': 'EventAction'
    }
    
    def __init__(self):
        self.config = config.get('detection', {})
        self._init_operators()
        logger.info("🔍 Detection Engine initialized - FIXED VERSION")
        
    def _init_operators(self):
        """Initialize comparison operators"""
        self.operators = {
            'equals': self._op_equals,
            'iequals': self._op_iequals,
            'contains': self._op_contains,
            'icontains': self._op_icontains,
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
        
    async def analyze_event_and_create_alerts(self, session: Session, event: Event) -> Dict:
        """
        FIXED: Analyze an event and create alerts if threats detected
        Args:
            session: Database session
            event: Event to analyze
        Returns:
            Dictionary with detection results
        """
        results = self._init_results(event)
        
        try:
            agent = session.query(Agent).filter_by(AgentID=event.AgentID).first()
            if not agent:
                logger.warning(f"Agent {event.AgentID} not found")
                return results

            # Run detection phases
            await self._execute_detection_phases(session, event, results)

            # Finalize results
            self._finalize_results(results)
            
            # Create alerts if needed
            if results['threat_detected']:
                await self._handle_alert_creation(session, event, agent, results)

            # Update event
            self._update_event_data(event, results)
            
            logger.info(f"🔍 EVENT ANALYZED: {event.EventType} - {event.ProcessName}")
            logger.info(f"   Risk Score: {results['risk_score']}")
            logger.info(f"   Threat Level: {results['threat_level']}")
            logger.info(f"   Threats Detected: {results['threat_detected']}")
            
        except Exception as e:
            logger.error(f"Event analysis failed: {str(e)}", exc_info=True)
        
        return results

    async def _execute_detection_phases(self, session: Session, 
                                     event: Event, results: Dict) -> None:
        """Execute all detection phases"""
        # Rule-based detection
        if self.config.get('rule_engine_enabled', True):
            rule_results = await self._process_rules(session, event)
            if rule_results:
                self._merge_results(results, rule_results)

        # Threat intelligence
        if self.config.get('threat_intel_enabled', True) and event.ProcessHash:
            threat_results = await self._check_threats(session, event)
            if threat_results:
                self._merge_results(results, threat_results)

        results['threat_detected'] = bool(
            results.get('matched_rules') or 
            results.get('matched_threats')
        )

    async def _process_rules(self, session: Session, event: Event) -> Dict:
        """Process all active detection rules"""
        rules = session.query(DetectionRule).filter_by(IsActive=True).all()
        results = {
            'detection_methods': ['rule_engine'],
            'matched_rules': [],
            'rule_details': [],
            'risk_score': 0
        }
        
        for rule in rules:
            if self._evaluate_rule(event, rule):
                risk_score = self.SEVERITY_SCORES.get(rule.AlertSeverity, 50)
                
                results['matched_rules'].append(rule.RuleID)
                results['risk_score'] += risk_score
                results['rule_details'].append({
                    'rule_id': rule.RuleID,
                    'rule_name': rule.RuleName,
                    'severity': rule.AlertSeverity,
                    'risk_score': risk_score
                })
                
                logger.warning(f"🚨 RULE MATCHED: {rule.RuleName}")
                logger.warning(f"   Process: {event.ProcessName}")
                logger.warning(f"   Severity: {rule.AlertSeverity}")
                logger.warning(f"   Risk Score: {risk_score}")

        return results if results['matched_rules'] else {}

    def _evaluate_rule(self, event: Event, rule: DetectionRule) -> bool:
        """Evaluate a single rule against event data"""
        try:
            condition = rule.get_rule_condition()
            if not condition:
                return False
            
            if isinstance(condition, dict):
                if 'conditions' in condition:
                    return self._evaluate_condition_group(event, condition)
                return self._evaluate_simple_condition(event, condition)
            
            return False
            
        except Exception as e:
            logger.error(f"Rule evaluation failed: {str(e)}")
            return False
    
    def _evaluate_condition_group(self, event: Event, condition_group: Dict) -> bool:
        """Evaluate a group of conditions"""
        logic = condition_group.get('logic', 'AND').upper()
        conditions = condition_group.get('conditions', [])
        results = []

        for cond in conditions:
            field = cond.get('field')
            operator = cond.get('operator', 'equals')
            value = cond.get('value')
            
            if not field:
                continue
            
            event_value = getattr(event, self.FIELD_MAPPINGS.get(field, field), None)
            op_func = self.operators.get(operator)
            
            if op_func:
                results.append(op_func(event_value, value))

        return any(results) if logic == 'OR' else all(results)
    
    def _evaluate_simple_condition(self, event: Event, condition: Dict) -> bool:
        """Evaluate a simple condition"""
        field = condition.get('field')
        operator = condition.get('operator', 'equals')
        value = condition.get('value')
        
        if not field:
            return False
        
        event_value = getattr(event, self.FIELD_MAPPINGS.get(field, field), None)
        op_func = self.operators.get(operator)
        
        if op_func:
            return op_func(event_value, value)
        
        return False

    async def _check_threats(self, session: Session, event: Event) -> Dict:
        """Check against threat intelligence"""
        threat = Threat.check_hash(session, event.ProcessHash)
        if not threat:
            return {}

        risk_score = self.SEVERITY_SCORES.get(threat.Severity, 50)
        return {
            'detection_methods': ['threat_intel'],
            'matched_threats': [threat.ThreatID],
            'threat_details': [{
                'threat_id': threat.ThreatID,
                'threat_name': threat.ThreatName,
                'severity': threat.Severity,
                'risk_score': risk_score
            }],
            'risk_score': risk_score
        }

    def _finalize_results(self, results: Dict) -> None:
        """Calculate final scores and threat level"""
        # Apply multiplier for multiple detection methods
        if len(results.get('detection_methods', [])) > 1:
            results['risk_score'] = min(int(results['risk_score'] * 1.2), 100)
        
        # Determine threat level
        results['threat_level'] = self._calculate_threat_level(results['risk_score'])

    def _calculate_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score"""
        if risk_score >= self.THREAT_LEVELS['Malicious']:
            return 'Malicious'
        elif risk_score >= self.THREAT_LEVELS['Suspicious']:
            return 'Suspicious'
        return 'None'

    async def _handle_alert_creation(self, session: Session, event: Event,
                                   agent: Agent, results: Dict) -> None:
        """Handle alert creation and notification"""
        alert = self._create_alert_record(session, event, agent, results)
        if alert:
            results['alerts_created'] = [alert.AlertID]
            await self._send_alert_notification(session, agent, alert)

    def _create_alert_record(self, session: Session, event: Event,
                           agent: Agent, results: Dict) -> Optional[Alert]:
        """Create an alert record in database"""
        try:
            alert_data = {
                'AgentID': agent.AgentID,
                'EventID': event.EventID,
                'AlertType': 'security_detection',
                'RiskScore': results['risk_score'],
                'Status': 'open',
                'FirstDetected': datetime.now(),
                'LastDetected': datetime.now(),
                'CreatedAt': datetime.now()
            }

            if results.get('rule_details'):
                rule = results['rule_details'][0]
                alert_data.update({
                    'RuleID': rule['rule_id'],
                    'Title': f"Rule: {rule['rule_name']}",
                    'Severity': rule['severity'],
                    'Priority': rule['severity'],
                    'DetectionMethod': 'rule_engine'
                })
            elif results.get('threat_details'):
                threat = results['threat_details'][0]
                alert_data.update({
                    'ThreatID': threat['threat_id'],
                    'Title': f"Threat: {threat['threat_name']}",
                    'Severity': threat['severity'],
                    'Priority': threat['severity'],
                    'DetectionMethod': 'threat_intel'
                })

            alert = Alert(**alert_data)
            session.add(alert)
            session.flush()
            return alert
            
        except Exception as e:
            logger.error(f"Alert creation failed: {str(e)}")
            return None
    
    async def _send_alert_notification(self, session: Session, 
                                     agent: Agent, alert: Alert) -> None:
        """FIXED: Send alert notification to agent using proper communication service"""
        try:
            from ..services.agent_communication_service import AgentCommunicationService
            
            # Create notification service instance
            notification_service = AgentCommunicationService()
            
            # Create notification data
            notification = {
                'type': 'security_alert',
                'alert_id': alert.AlertID,
                'title': alert.Title or f"Security Alert - {alert.DetectionMethod}",
                'severity': alert.Severity or 'Medium',
                'message': f"Security threat detected: {alert.Title}",
                'detection_method': alert.DetectionMethod or 'rule_engine',
                'risk_score': alert.RiskScore or 0,
                'timestamp': datetime.now().isoformat(),
                'requires_action': alert.Severity in ['High', 'Critical'],
                'auto_display': True,
                'display_popup': True,
                'play_sound': alert.Severity in ['High', 'Critical']
            }
            
            # Send notification to agent
            success = await notification_service.send_realtime_notification(
                session=session,
                agent_id=str(agent.AgentID),
                notification=notification
            )
            
            if success:
                logger.warning(f"🚨 ALERT NOTIFICATION SENT TO AGENT:")
                logger.warning(f"   🎯 Agent: {agent.HostName} ({agent.AgentID})")
                logger.warning(f"   📋 Alert ID: {alert.AlertID}")
                logger.warning(f"   🔔 Title: {alert.Title}")
                logger.warning(f"   ⚡ Severity: {alert.Severity}")
                logger.warning(f"   📊 Risk Score: {alert.RiskScore}")
            else:
                logger.error(f"❌ Failed to send alert notification to agent {agent.HostName}")
                
        except Exception as e:
            logger.error(f"💥 Alert notification failed: {str(e)}")
            import traceback
            logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")

    def _update_event_data(self, event: Event, results: Dict) -> None:
        """Update event with analysis results"""
        event.RiskScore = results['risk_score']
        event.Analyzed = True
        event.AnalyzedAt = datetime.now()
        event.ThreatLevel = results['threat_level']

    def _init_results(self, event: Event) -> Dict:
        """Initialize results dictionary"""
        return {
            'event_id': event.EventID,
            'agent_id': event.AgentID,
            'threat_detected': False,
            'threat_level': 'None',
            'risk_score': 0,
            'detection_methods': [],
            'matched_rules': [],
            'matched_threats': [],
            'alerts_created': [],
            'event_type': event.EventType,
            'process_name': event.ProcessName,
            'timestamp': datetime.now().isoformat()
        }

    def _merge_results(self, base: Dict, new: Dict) -> Dict:
        """Merge detection results"""
        for key, value in new.items():
            if isinstance(value, list):
                base.setdefault(key, []).extend(value)
            elif isinstance(value, (int, float)):
                base[key] = base.get(key, 0) + value
            else:
                base[key] = value
        return base

    # Operator implementations
    def _op_equals(self, a: Any, b: Any) -> bool:
        return str(a) == str(b)

    def _op_iequals(self, a: Any, b: Any) -> bool:
        return str(a).lower() == str(b).lower()

    def _op_contains(self, a: Any, b: Any) -> bool:
        return str(b) in str(a)

    def _op_icontains(self, a: Any, b: Any) -> bool:
        return str(b).lower() in str(a).lower()

    def _op_not_equals(self, a: Any, b: Any) -> bool:
        return not self._op_equals(a, b)

    def _op_not_contains(self, a: Any, b: Any) -> bool:
        return not self._op_contains(a, b)

    def _op_starts_with(self, a: Any, b: Any) -> bool:
        return str(a).startswith(str(b))

    def _op_ends_with(self, a: Any, b: Any) -> bool:
        return str(a).endswith(str(b))

    def _op_regex(self, a: Any, pattern: str) -> bool:
        try:
            return bool(re.search(pattern, str(a), re.IGNORECASE))
        except re.error:
            return False

    def _op_in(self, a: Any, items: List) -> bool:
        return str(a) in [str(i) for i in items]

    def _op_not_in(self, a: Any, items: List) -> bool:
        return not self._op_in(a, items)

    def _op_exists(self, a: Any, _: Any) -> bool:
        return a is not None and str(a).strip() != ""

    def _op_not_exists(self, a: Any, _: Any) -> bool:
        return not self._op_exists(a, _)

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