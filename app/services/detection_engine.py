# app/services/detection_engine.py - FIXED: Complete Rule Data Mapping
"""
Detection Engine - FIXED VERSION
Đảm bảo tất cả dữ liệu từ DetectionRules table được map đầy đủ
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
    """Detection engine with complete DetectionRules data mapping"""
    
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
        logger.info("🔍 Detection Engine - Complete Rule Data Mapping Mode")
        
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
        FIXED: Analyze RAW event data with complete DetectionRules mapping
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
                    logger.warning(f"🎯 NOTEPAD.EXE DETECTED - Running complete rule analysis...")
            
            # Execute detection phases with enhanced data mapping
            await self._execute_detection_phases_enhanced(session, event_data, results)
            
            # Finalize results
            self._finalize_results(results)
            
            logger.info(f"🔍 DETECTION COMPLETE:")
            logger.info(f"   🚨 Threat Detected: {results['threat_detected']}")
            logger.info(f"   📊 Risk Score: {results['risk_score']}")
            logger.info(f"   📋 Rules Matched: {len(results.get('matched_rules', []))}")
            logger.info(f"   🎯 Detection Methods: {results.get('detection_methods', [])}")
            
            # Enhanced logging for rule details
            if results.get('rule_details'):
                logger.warning(f"📝 RULE DETAILS EXTRACTED:")
                for rule_detail in results['rule_details']:
                    logger.warning(f"   📋 Rule: {rule_detail.get('rule_name')} (ID: {rule_detail.get('rule_id')})")
                    logger.warning(f"   📝 Alert: {rule_detail.get('alert_title')}")
                    logger.warning(f"   ⚡ Severity: {rule_detail.get('alert_severity')}")
                    logger.warning(f"   🎯 MITRE: {rule_detail.get('mitre_tactic')}/{rule_detail.get('mitre_technique')}")
            
        except Exception as e:
            logger.error(f"💥 Raw data analysis failed: {str(e)}", exc_info=True)
        
        return results
    
    async def _execute_detection_phases_enhanced(self, session: Session, 
                                               event_data: Dict, results: Dict) -> None:
        """Execute detection phases with enhanced rule data extraction"""
        
        # 1. Enhanced rule-based detection
        if self.config.get('rules_enabled', True):
            logger.info("🔍 Running enhanced rule-based detection...")
            rule_results = await self._process_rules_with_complete_data(session, event_data)
            if rule_results:
                self._merge_results(results, rule_results)
                logger.info(f"   📋 Rules processed: {len(rule_results.get('rule_details', []))}")
        
        # 2. Threat intelligence (unchanged)
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
    
    async def _process_rules_with_complete_data(self, session: Session, event_data: Dict) -> Dict:
        """
        FIXED: Process rules with COMPLETE DetectionRules data extraction
        """
        # Get platform from agent OS
        platform = self._determine_platform(event_data)
        # Get active rules
        rules = DetectionRule.get_active_rules(session, platform)
        logger.info(f"📋 Checking {len(rules)} active rules with complete data mapping...")
        logger.info(f"   🎯 Platform: {platform}")
        logger.info(f"   📊 Event type: {event_data.get('event_type')}")
        logger.info(f"   🖥️ Process name: {event_data.get('process_name')}")
        
        results = {
            'detection_methods': ['rule_engine'],
            'matched_rules': [],
            'rule_details': [],
            'risk_score': 0
        }
        
        for rule in rules:
            logger.debug(f"🔍 Checking rule: {rule.RuleName} (ID: {rule.RuleID})")
            
            if self._evaluate_rule_against_raw_data(event_data, rule):
                risk_score = self.SEVERITY_SCORES.get(rule.AlertSeverity, 50)
                results['matched_rules'].append(rule.RuleID)
                results['risk_score'] += risk_score
                complete_rule_data = self._extract_complete_rule_data(rule, risk_score)
                results['rule_details'].append(complete_rule_data)
                logger.warning(f"🚨 RULE MATCHED: {rule.RuleName} (ID: {rule.RuleID}) for event: {event_data}")
            else:
                logger.debug(f"   ❌ Rule {rule.RuleName} (ID: {rule.RuleID}) did not match")
        
        logger.info(f"📊 Rule evaluation complete:")
        logger.info(f"   ✅ Matched rules: {len(results['matched_rules'])}")
        logger.info(f"   📊 Risk score: {results['risk_score']}")
        
        return results if results['matched_rules'] else {}
    
    def _extract_complete_rule_data(self, rule: DetectionRule, risk_score: int) -> Dict:
        """
        FIXED: Extract COMPLETE data from DetectionRules table
        Đảm bảo tất cả columns được map đầy đủ
        """
        try:
            # Get rule condition as dict
            rule_condition = rule.get_rule_condition()
            
            # Extract COMPLETE DetectionRules table data
            complete_data = {
                # ===== CORE RULE IDENTIFICATION =====
                'rule_id': rule.RuleID,                    # DetectionRules.RuleID
                'rule_name': rule.RuleName,                # DetectionRules.RuleName
                'rule_type': rule.RuleType,                # DetectionRules.RuleType
                'rule_category': rule.RuleCategory,        # DetectionRules.RuleCategory
                'rule_condition': rule_condition,          # DetectionRules.RuleCondition (JSON)
                
                # ===== ALERT CONFIGURATION =====
                'alert_title': rule.AlertTitle,            # DetectionRules.AlertTitle
                'alert_description': rule.AlertDescription, # DetectionRules.AlertDescription
                'alert_severity': rule.AlertSeverity,      # DetectionRules.AlertSeverity
                'alert_type': rule.AlertType,              # DetectionRules.AlertType
                
                # ===== MITRE ATT&CK MAPPING =====
                'mitre_tactic': rule.MitreTactic,          # DetectionRules.MitreTactic
                'mitre_technique': rule.MitreTechnique,    # DetectionRules.MitreTechnique
                
                # ===== RULE METADATA =====
                'platform': rule.Platform,                # DetectionRules.Platform
                'priority': rule.Priority,                # DetectionRules.Priority
                'is_active': rule.IsActive,               # DetectionRules.IsActive
                'test_mode': rule.TestMode,               # DetectionRules.TestMode
                
                # ===== TIMESTAMPS =====
                'created_at': rule.CreatedAt.isoformat() if rule.CreatedAt else None,  # DetectionRules.CreatedAt
                'updated_at': rule.UpdatedAt.isoformat() if rule.UpdatedAt else None,  # DetectionRules.UpdatedAt
                
                # ===== CALCULATED FIELDS =====
                'risk_score': risk_score,
                'condition_summary': rule.get_condition_summary() if hasattr(rule, 'get_condition_summary') else "Rule condition",
                
                # ===== ADDITIONAL METADATA =====
                'detection_timestamp': datetime.now().isoformat(),
                'rule_matched': True,
                'confidence': self._calculate_rule_confidence(rule, rule_condition),
                
                # ===== DISPLAY CONFIGURATION =====
                'display_config': self._generate_display_config(rule),
                
                # ===== RESPONSE CONFIGURATION =====
                'response_config': self._generate_response_config(rule)
            }
            
            logger.debug(f"📋 Complete rule data extracted for rule {rule.RuleID}: {len(complete_data)} fields")
            return complete_data
            
        except Exception as e:
            logger.error(f"💥 Failed to extract complete rule data for rule {rule.RuleID}: {e}")
            # Return minimal data as fallback
            return {
                'rule_id': rule.RuleID,
                'rule_name': rule.RuleName or 'Unknown Rule',
                'alert_title': rule.AlertTitle or 'Security Alert',
                'alert_severity': rule.AlertSeverity or 'Medium',
                'risk_score': risk_score,
                'error': 'Failed to extract complete data'
            }
    
    def _calculate_rule_confidence(self, rule: DetectionRule, rule_condition: Dict) -> float:
        """Calculate confidence score for rule match"""
        try:
            base_confidence = 0.8
            
            # Increase confidence for specific conditions
            if rule_condition and isinstance(rule_condition, dict):
                # More specific conditions = higher confidence
                if len(rule_condition) > 2:
                    base_confidence += 0.1
                
                # Multiple conditions with AND logic = higher confidence
                if rule_condition.get('logic') == 'AND' and rule_condition.get('conditions'):
                    base_confidence += 0.05
            
            # Adjust based on rule metadata
            if rule.Priority and rule.Priority > 75:
                base_confidence += 0.05
            
            if not rule.TestMode:
                base_confidence += 0.05
            
            return min(1.0, base_confidence)
            
        except Exception:
            return 0.8  # Default confidence
    
    def _generate_display_config(self, rule: DetectionRule) -> Dict:
        """Generate display configuration based on rule properties"""
        try:
            severity = rule.AlertSeverity or 'Medium'
            
            return {
                'show_popup': True,
                'auto_display': True,
                'play_sound': severity in ['High', 'Critical'],
                'require_acknowledgment': severity in ['High', 'Critical'],
                'auto_escalate': severity == 'Critical',
                'highlight_color': self._get_severity_color(severity),
                'icon_type': self._get_severity_icon(severity),
                'display_duration': self._get_display_duration(severity),
                'can_dismiss': severity not in ['Critical'],
                'show_details': True,
                'show_mitre_info': bool(rule.MitreTactic or rule.MitreTechnique)
            }
        except Exception:
            return {'show_popup': True, 'auto_display': True}
    
    def _generate_response_config(self, rule: DetectionRule) -> Dict:
        """Generate response configuration based on rule properties"""
        try:
            severity = rule.AlertSeverity or 'Medium'
            
            available_actions = ['acknowledge', 'investigate']
            
            if severity in ['High', 'Critical']:
                available_actions.extend(['isolate', 'quarantine'])
            
            if severity not in ['Critical']:
                available_actions.append('dismiss')
            
            if severity == 'Critical':
                available_actions.append('escalate')
            
            return {
                'available_actions': available_actions,
                'default_action': 'investigate' if severity in ['High', 'Critical'] else 'acknowledge',
                'timeout_seconds': 300 if severity == 'Critical' else 600,
                'auto_action': None,  # No automatic actions
                'escalation_enabled': severity == 'Critical',
                'require_justification': severity in ['High', 'Critical'],
                'allow_bulk_action': True,
                'response_required': severity in ['High', 'Critical']
            }
        except Exception:
            return {'available_actions': ['acknowledge'], 'default_action': 'acknowledge'}
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity"""
        colors = {
            'Critical': '#FF0000',  # Red
            'High': '#FF6600',      # Orange
            'Medium': '#FFFF00',    # Yellow
            'Low': '#00FF00',       # Green
            'Info': '#0099FF'       # Blue
        }
        return colors.get(severity, '#FFFF00')
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get icon type for severity"""
        icons = {
            'Critical': 'critical_alert',
            'High': 'warning',
            'Medium': 'info',
            'Low': 'notification',
            'Info': 'info'
        }
        return icons.get(severity, 'info')
    
    def _get_display_duration(self, severity: str) -> int:
        """Get display duration in seconds"""
        durations = {
            'Critical': 0,    # Persistent
            'High': 300,      # 5 minutes
            'Medium': 180,    # 3 minutes
            'Low': 120,       # 2 minutes
            'Info': 60        # 1 minute
        }
        return durations.get(severity, 180)
    
    def _evaluate_rule_against_raw_data(self, event_data: Dict, rule: DetectionRule) -> bool:
        """Evaluate a single rule against raw event data"""
        try:
            condition = rule.get_rule_condition()
            if not condition:
                logger.debug(f"   ❌ Rule {rule.RuleID} has no condition")
                return False
            
            logger.debug(f"   🔍 Evaluating rule {rule.RuleName} (ID: {rule.RuleID})")
            logger.debug(f"   📋 Condition: {condition}")
            logger.debug(f"   📊 Event data: {event_data}")
            
            # BỎ QUA RULE QUÁ RỘNG: chỉ có event_type hoặc event_type + logic
            if isinstance(condition, dict):
                keys = set(condition.keys())
                if keys == {"event_type"} or keys == {"event_type", "logic"}:
                    logger.warning(f"[SECURITY] Bỏ qua rule quá rộng (RuleID={rule.RuleID}): chỉ có event_type")
                    return False
            
            # Kiểm tra rule có áp dụng cho event_type không
            if not rule.is_applicable_to_event_type(event_data.get('event_type', '')):
                logger.debug(f"   ❌ Rule {rule.RuleID} not applicable to event type: {event_data.get('event_type')}")
                return False
            
            # Đánh giá condition
            if isinstance(condition, dict):
                if 'conditions' in condition:
                    result = self._evaluate_condition_group_raw_data(event_data, condition)
                    logger.debug(f"   📊 Condition group result: {result}")
                    return result
                else:
                    result = self._evaluate_simple_condition_raw_data(event_data, condition)
                    logger.debug(f"   📊 Simple condition result: {result}")
                    return result
            
            logger.debug(f"   ❌ Rule {rule.RuleID} condition is not a dict: {type(condition)}")
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
        """FIXED: Evaluate simple condition with proper logic handling"""
        try:
            # Get logic operator (default to case-insensitive equals)
            logic = condition.get('logic', 'EQUALS').upper()
            
            # Process each field except logic
            for field, expected_value in condition.items():
                if field == 'logic':
                    continue
                
                event_value = event_data.get(field)
                
                # Handle different logic operators
                if logic == 'EQUALS':
                    if isinstance(expected_value, str) and isinstance(event_value, str):
                        if expected_value.lower() != event_value.lower():
                            logger.debug(f"   ❌ {field}: '{event_value}' != '{expected_value}' (EQUALS)")
                            return False
                    else:
                        if str(expected_value) != str(event_value):
                            logger.debug(f"   ❌ {field}: '{event_value}' != '{expected_value}' (EQUALS)")
                            return False
                
                elif logic == 'CONTAINS':
                    if isinstance(expected_value, str) and isinstance(event_value, str):
                        if expected_value.lower() not in event_value.lower():
                            logger.debug(f"   ❌ {field}: '{event_value}' does not contain '{expected_value}' (CONTAINS)")
                            return False
                    else:
                        if str(expected_value) not in str(event_value):
                            logger.debug(f"   ❌ {field}: '{event_value}' does not contain '{expected_value}' (CONTAINS)")
                            return False
                
                elif logic == 'STARTS_WITH':
                    if isinstance(expected_value, str) and isinstance(event_value, str):
                        if not event_value.lower().startswith(expected_value.lower()):
                            logger.debug(f"   ❌ {field}: '{event_value}' does not start with '{expected_value}' (STARTS_WITH)")
                            return False
                    else:
                        if not str(event_value).startswith(str(expected_value)):
                            logger.debug(f"   ❌ {field}: '{event_value}' does not start with '{expected_value}' (STARTS_WITH)")
                            return False
                
                elif logic == 'ENDS_WITH':
                    if isinstance(expected_value, str) and isinstance(event_value, str):
                        if not event_value.lower().endswith(expected_value.lower()):
                            logger.debug(f"   ❌ {field}: '{event_value}' does not end with '{expected_value}' (ENDS_WITH)")
                            return False
                    else:
                        if not str(event_value).endswith(str(expected_value)):
                            logger.debug(f"   ❌ {field}: '{event_value}' does not end with '{expected_value}' (ENDS_WITH)")
                            return False
                
                else:
                    # Default case-insensitive comparison
                    if isinstance(expected_value, str) and isinstance(event_value, str):
                        if expected_value.lower() != event_value.lower():
                            logger.debug(f"   ❌ {field}: '{event_value}' != '{expected_value}' (DEFAULT)")
                            return False
                    else:
                        if str(expected_value) != str(event_value):
                            logger.debug(f"   ❌ {field}: '{event_value}' != '{expected_value}' (DEFAULT)")
                            return False
                
                logger.debug(f"   ✅ {field}: '{event_value}' matches '{expected_value}' (logic: {logic})")
            
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating simple condition: {e}")
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
    
    def _determine_platform(self, agent_data: Dict) -> str:
        """Determine platform from agent OS"""
        operating_system = agent_data.get('agent_os', '')
        if not operating_system:
            operating_system = agent_data.get('operating_system', '')
        os_lower = operating_system.lower()
        if any(keyword in os_lower for keyword in ['linux', 'ubuntu', 'centos', 'rhel', 'debian']):
            return 'Linux'
        elif 'windows' in os_lower:
            return 'Windows'
        elif any(keyword in os_lower for keyword in ['mac', 'darwin', 'osx']):
            return 'macOS'
        return 'All'
    
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
    
    # Operator implementations (unchanged)
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
        logger.info("🔍 Detection Engine singleton created - Complete Rule Data Mapping Mode")
    return _detection_engine_instance

# Also create the detection_engine instance for backward compatibility
detection_engine = get_detection_service()