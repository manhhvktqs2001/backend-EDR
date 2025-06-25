# app/services/detection_engine.py - FIXED: Raw Data Analysis
"""
Detection Engine - FIXED VERSION
Phân tích RAW event data TRƯỚC khi insert vào DB
"""

import logging
import re
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from ..models.detection_rule import DetectionRule
from ..models.threat import Threat
from ..config import config

logger = logging.getLogger(__name__)

class DetectionEngine:
    """Detection engine for raw event data analysis"""
    
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
    
    def __init__(self):
        self.config = config.get('detection', {})
        self._init_operators()
        logger.info("🔍 Detection Engine - Raw Data Analysis Mode")
        
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
    
    async def analyze_raw_event_data(self, session: Session, event_data: Dict) -> Dict:
        """
        FIXED: Analyze RAW event data BEFORE database insert
        Args:
            session: Database session
            event_data: Raw event data from agent
        Returns:
            Dictionary with detection results
        """
        results = self._init_results(event_data)
        
        try:
            logger.info(f"🔍 ANALYZING RAW EVENT DATA:")
            logger.info(f"   📋 Type: {event_data.get('event_type')}")
            logger.info(f"   🔧 Action: {event_data.get('event_action')}")
            if event_data.get('process_name'):
                logger.info(f"   🖥️ Process: {event_data.get('process_name')}")
                
                # Special logging for notepad.exe
                if 'notepad.exe' in event_data.get('process_name', '').lower():
                    logger.warning(f"🎯 NOTEPAD.EXE DETECTED - Running detection...")
            
            # Execute detection phases
            await self._execute_detection_phases(session, event_data, results)
            
            # Finalize results
            self._finalize_results(results)
            
            logger.info(f"🔍 DETECTION COMPLETE:")
            logger.info(f"   🚨 Threat Detected: {results['threat_detected']}")
            logger.info(f"   📊 Risk Score: {results['risk_score']}")
            logger.info(f"   📋 Rules Matched: {len(results.get('matched_rules', []))}")
            logger.info(f"   🎯 Detection Methods: {results.get('detection_methods', [])}")
            
        except Exception as e:
            logger.error(f"💥 Raw data analysis failed: {str(e)}", exc_info=True)
        
        return results
    
    async def _execute_detection_phases(self, session: Session, 
                                       event_data: Dict, results: Dict) -> None:
        """Execute all detection phases on raw data"""
        
        # 1. Rule-based detection
        if self.config.get('rules_enabled', True):
            logger.info("🔍 Running rule-based detection...")
            rule_results = await self._process_rules_on_raw_data(session, event_data)
            if rule_results:
                self._merge_results(results, rule_results)
                logger.info(f"   📋 Rules checked: {len(rule_results.get('matched_rules', []))}")
        
        # 2. Threat intelligence
        if self.config.get('threat_intel_enabled', True) and event_data.get('process_hash'):
            logger.info("🔍 Running threat intelligence check...")
            threat_results = await self._check_threats_on_raw_data(session, event_data)
            if threat_results:
                self._merge_results(results, threat_results)
                logger.info(f"   🎯 Threats found: {len(threat_results.get('matched_threats', []))}")
        
        # Set final threat detection status
        results['threat_detected'] = bool(
            results.get('matched_rules') or 
            results.get('matched_threats')
        )
    
    async def _process_rules_on_raw_data(self, session: Session, event_data: Dict) -> Dict:
        """Process all active detection rules against raw data"""
        
        # Get platform from agent OS (simplified)
        platform = self._determine_platform(event_data.get('agent_hostname', ''))
        
        # Get active rules
        rules = DetectionRule.get_active_rules(session, platform)
        
        logger.info(f"📋 Checking {len(rules)} active rules...")
        
        results = {
            'detection_methods': ['rule_engine'],
            'matched_rules': [],
            'rule_details': [],
            'risk_score': 0
        }
        
        for rule in rules:
            if self._evaluate_rule_against_raw_data(event_data, rule):
                risk_score = self.SEVERITY_SCORES.get(rule.AlertSeverity, 50)
                
                results['matched_rules'].append(rule.RuleID)
                results['risk_score'] += risk_score
                results['rule_details'].append({
                    'rule_id': rule.RuleID,
                    'rule_name': rule.RuleName,
                    'rule_type': rule.RuleType,
                    'severity': rule.AlertSeverity,
                    'alert_title': rule.AlertTitle,
                    'alert_description': rule.AlertDescription,
                    'mitre_tactic': rule.MitreTactic,
                    'mitre_technique': rule.MitreTechnique,
                    'risk_score': risk_score
                })
                
                logger.warning(f"🚨 RULE MATCHED:")
                logger.warning(f"   📝 Rule: {rule.RuleName} (ID: {rule.RuleID})")
                logger.warning(f"   📋 Type: {rule.RuleType}")
                logger.warning(f"   ⚡ Severity: {rule.AlertSeverity}")
                logger.warning(f"   📊 Risk Score: {risk_score}")
                logger.warning(f"   🎯 Alert Title: {rule.AlertTitle}")
                
                # Special logging for notepad.exe detection
                if event_data.get('process_name') and 'notepad.exe' in event_data.get('process_name', '').lower():
                    logger.warning(f"🎯 NOTEPAD.EXE RULE MATCHED!")
                    logger.warning(f"   📝 Rule Name: {rule.RuleName}")
                    logger.warning(f"   📋 Alert: {rule.AlertTitle}")
                    logger.warning(f"   🔔 This should trigger notification!")
        
        return results if results['matched_rules'] else {}
    
    def _evaluate_rule_against_raw_data(self, event_data: Dict, rule: DetectionRule) -> bool:
        """Evaluate a single rule against raw event data"""
        try:
            condition = rule.get_rule_condition()
            if not condition:
                logger.debug(f"Rule {rule.RuleID} has no condition")
                return False
            
            logger.debug(f"🔍 Evaluating rule: {rule.RuleName}")
            logger.debug(f"   Condition: {condition}")
            
            # Check if rule applies to this event type
            if not rule.is_applicable_to_event_type(event_data.get('event_type', '')):
                logger.debug(f"   ❌ Rule not applicable to event type: {event_data.get('event_type')}")
                return False
            
            if isinstance(condition, dict):
                # Handle different condition formats
                if 'conditions' in condition:
                    result = self._evaluate_condition_group_raw_data(event_data, condition)
                else:
                    result = self._evaluate_simple_condition_raw_data(event_data, condition)
                
                logger.debug(f"   📊 Rule evaluation result: {result}")
                return result
            
            logger.debug(f"   ❌ Invalid condition format")
            return False
            
        except Exception as e:
            logger.error(f"Rule evaluation failed for {rule.RuleID}: {str(e)}")
            return False
    
    def _evaluate_condition_group_raw_data(self, event_data: Dict, condition_group: Dict) -> bool:
        """Evaluate a group of conditions against raw data"""
        logic = condition_group.get('logic', 'AND').upper()
        conditions = condition_group.get('conditions', [])
        results = []
        
        logger.debug(f"   🔍 Evaluating condition group with {len(conditions)} conditions (logic: {logic})")
        
        for cond in conditions:
            field = cond.get('field')
            operator = cond.get('operator', 'equals')
            value = cond.get('value')
            
            if not field:
                logger.debug(f"     ❌ Missing field in condition")
                continue
            
            # Get value from raw event data
            event_value = event_data.get(field)
            
            # Get operator function
            op_func = self.operators.get(operator)
            
            if op_func:
                condition_result = op_func(event_value, value)
                results.append(condition_result)
                
                logger.debug(f"     🔍 Field: {field}, Value: {event_value}, Expected: {value}, Operator: {operator}, Result: {condition_result}")
            else:
                logger.debug(f"     ❌ Unknown operator: {operator}")
        
        if not results:
            return False
        
        final_result = any(results) if logic == 'OR' else all(results)
        logger.debug(f"   📊 Final condition group result: {final_result}")
        return final_result
    
    def _evaluate_simple_condition_raw_data(self, event_data: Dict, condition: Dict) -> bool:
        """Evaluate a simple condition against raw data"""
        logger.debug(f"   🔍 Evaluating simple condition: {condition}")
        
        # Handle direct field matching (e.g., {"process_name": "notepad.exe"})
        for field, expected_value in condition.items():
            if field == 'logic':
                continue
            
            event_value = event_data.get(field)
            
            # Default to case-insensitive equals
            if isinstance(expected_value, str) and isinstance(event_value, str):
                result = expected_value.lower() == event_value.lower()
            else:
                result = str(expected_value) == str(event_value)
            
            logger.debug(f"     🔍 Field: {field}, Event: {event_value}, Expected: {expected_value}, Result: {result}")
            
            if result:
                return True
        
        return False
    
    async def _check_threats_on_raw_data(self, session: Session, event_data: Dict) -> Dict:
        """Check raw event data against threat intelligence"""
        process_hash = event_data.get('process_hash')
        if not process_hash:
            return {}
        
        threat = Threat.check_hash(session, process_hash)
        if not threat:
            return {}
        
        risk_score = self.SEVERITY_SCORES.get(threat.Severity, 50)
        
        logger.warning(f"🚨 THREAT INTELLIGENCE MATCH:")
        logger.warning(f"   🎯 Threat: {threat.ThreatName}")
        logger.warning(f"   📋 Hash: {process_hash}")
        logger.warning(f"   ⚡ Severity: {threat.Severity}")
        logger.warning(f"   📊 Risk Score: {risk_score}")
        
        return {
            'detection_methods': ['threat_intel'],
            'matched_threats': [threat.ThreatID],
            'threat_details': [{
                'threat_id': threat.ThreatID,
                'threat_name': threat.ThreatName,
                'threat_type': threat.ThreatType,
                'threat_category': threat.ThreatCategory,
                'severity': threat.Severity,
                'risk_score': risk_score,
                'confidence': float(threat.Confidence) if threat.Confidence else 0.8
            }],
            'risk_score': risk_score
        }
    
    def _determine_platform(self, hostname: str) -> str:
        """Determine platform from hostname or other indicators"""
        # Simple heuristic - can be enhanced
        return 'Windows'  # Default for now
    
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
    
    def _init_results(self, event_data: Dict) -> Dict:
        """Initialize results dictionary"""
        return {
            'agent_id': event_data.get('agent_id'),
            'agent_hostname': event_data.get('agent_hostname'),
            'threat_detected': False,
            'threat_level': 'None',
            'risk_score': 0,
            'detection_methods': [],
            'matched_rules': [],
            'matched_threats': [],
            'rule_details': [],
            'threat_details': [],
            'event_type': event_data.get('event_type'),
            'process_name': event_data.get('process_name'),
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
        if a is None or b is None:
            return a == b
        return str(a) == str(b)
    
    def _op_iequals(self, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return a == b
        return str(a).lower() == str(b).lower()
    
    def _op_contains(self, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return False
        return str(b) in str(a)
    
    def _op_icontains(self, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return False
        return str(b).lower() in str(a).lower()
    
    def _op_not_equals(self, a: Any, b: Any) -> bool:
        return not self._op_equals(a, b)
    
    def _op_not_contains(self, a: Any, b: Any) -> bool:
        return not self._op_contains(a, b)
    
    def _op_starts_with(self, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return False
        return str(a).startswith(str(b))
    
    def _op_ends_with(self, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return False
        return str(a).endswith(str(b))
    
    def _op_regex(self, a: Any, pattern: str) -> bool:
        if a is None or pattern is None:
            return False
        try:
            return bool(re.search(pattern, str(a), re.IGNORECASE))
        except re.error:
            return False
    
    def _op_in(self, a: Any, items: List) -> bool:
        if a is None or not items:
            return False
        return str(a) in [str(i) for i in items]
    
    def _op_not_in(self, a: Any, items: List) -> bool:
        return not self._op_in(a, items)
    
    def _op_exists(self, a: Any, _: Any) -> bool:
        return a is not None and str(a).strip() != ""
    
    def _op_not_exists(self, a: Any, _: Any) -> bool:
        return not self._op_exists(a, _)
    
    # Legacy method for backward compatibility
    async def analyze_event_and_create_alerts(self, session: Session, event) -> Dict:
        """Legacy method - converts Event object to raw data and analyzes"""
        try:
            # Convert Event object to raw data format
            event_data = {
                'agent_id': str(event.AgentID),
                'event_type': event.EventType,
                'event_action': event.EventAction,
                'event_timestamp': event.EventTimestamp,
                'severity': event.Severity,
                'process_name': event.ProcessName,
                'process_path': event.ProcessPath,
                'command_line': event.CommandLine,
                'process_hash': event.ProcessHash,
                'file_name': event.FileName,
                'file_path': event.FilePath,
                'file_hash': event.FileHash
            }
            
            # Run analysis on converted data
            return await self.analyze_raw_event_data(session, event_data)
            
        except Exception as e:
            logger.error(f"Legacy analysis failed: {e}")
            return {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'error': str(e)
            }

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
        logger.info("🔍 Detection Engine singleton created - Raw Data Analysis Mode")
    return _detection_engine_instance

# Also create the detection_engine instance for backward compatibility
detection_engine = get_detection_service()