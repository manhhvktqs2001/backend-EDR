# app/services/rule_engine.py - STANDARD RULE ENGINE
"""
Rule Engine - STANDARD VERSION
Match rules với JSON condition từ database
"""

import logging
import json
import re
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from ..models.detection_rule import DetectionRule
from ..models.event import Event
from ..models.alert import Alert

logger = logging.getLogger(__name__)

class RuleEngine:
    """Standard Rule Engine for EDR detection system"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._init_operators()
        
    def _init_operators(self):
        """Initialize comparison operators"""
        self.operators = {
            'equals': self._op_equals,
            'not_equals': self._op_not_equals,
            'contains': self._op_contains,
            'contains_any': self._op_contains_any,
            'starts_with': self._op_starts_with,
            'ends_with': self._op_ends_with,
            'regex': self._op_regex,
            'greater_than': self._op_greater_than,
            'less_than': self._op_less_than,
            'in': self._op_in,
            'not_in': self._op_not_in,
            'exists': self._op_exists,
            'not_exists': self._op_not_exists
        }
    
    async def process_event(self, session: Session, event_data: Dict) -> List[Alert]:
        """
        Process event against all active rules
        Returns list of generated alerts
        """
        alerts = []
        
        try:
            # Get active rules for platform
            platform = self._determine_platform(event_data)
            rules = await self._get_active_rules(session, platform, event_data.get('event_type'))
            
            self.logger.info(f"🔍 Processing event against {len(rules)} active rules")
            self.logger.info(f"   📋 Event type: {event_data.get('event_type')}")
            self.logger.info(f"   🎯 Platform: {platform}")
            self.logger.info(f"   🖥️ Process: {event_data.get('process_name', 'N/A')}")
            
            # DEBUG: Log từng rule được tìm thấy
            for i, rule in enumerate(rules):
                self.logger.debug(f"   📋 Rule {i+1}: {rule.RuleName} (ID: {rule.RuleID}, Type: {rule.RuleType}, Active: {rule.IsActive})")
                self.logger.debug(f"      Platform: {rule.Platform}, TestMode: {rule.TestMode}")
                self.logger.debug(f"      Condition: {rule.RuleCondition[:100]}..." if rule.RuleCondition else "No condition")
            
            for rule in rules:
                self.logger.info(f"🔍 Evaluating rule: {rule.RuleName} (ID: {rule.RuleID})")
                if await self._evaluate_rule(rule, event_data):
                    alert = await self._create_alert(rule, event_data, session)
                    if alert:
                        alerts.append(alert)
                        self.logger.warning(f"🚨 RULE MATCHED: {rule.RuleName} (ID: {rule.RuleID})")
                        self.logger.warning(f"   📝 Alert created: {alert.AlertID}")
                        self.logger.warning(f"   📋 Title: {alert.Title}")
                        self.logger.warning(f"   ⚡ Severity: {alert.Severity}")
                else:
                    self.logger.debug(f"❌ Rule {rule.RuleName} (ID: {rule.RuleID}) did not match")
            
            self.logger.info(f"📊 Rule processing complete: {len(alerts)} alerts generated")
            
        except Exception as e:
            self.logger.error(f"❌ Rule processing failed: {e}", exc_info=True)
        
        return alerts
    
    async def _get_active_rules(self, session: Session, platform: str, event_type: str) -> List[DetectionRule]:
        """Get active rules for platform and event type"""
        try:
            # Get all active rules
            rules = DetectionRule.get_active_rules(session, platform)
            
            self.logger.debug(f"📋 Found {len(rules)} active rules for platform '{platform}'")
            
            # Filter by event type applicability
            applicable_rules = []
            for rule in rules:
                if self._is_rule_applicable_to_event(rule, event_type):
                    applicable_rules.append(rule)
                    self.logger.debug(f"   ✅ Rule {rule.RuleName} (ID: {rule.RuleID}) applicable to {event_type}")
                else:
                    self.logger.debug(f"   ❌ Rule {rule.RuleName} (ID: {rule.RuleID}) NOT applicable to {event_type}")
            
            # Sort by priority (highest first)
            applicable_rules.sort(key=lambda r: r.Priority, reverse=True)
            
            self.logger.debug(f"📋 Found {len(applicable_rules)} applicable rules for {event_type}")
            
            return applicable_rules
            
        except Exception as e:
            self.logger.error(f"❌ Error getting active rules: {e}")
            return []
    
    def _is_rule_applicable_to_event(self, rule: DetectionRule, event_type: str) -> bool:
        """Check if rule applies to event type"""
        try:
            condition = rule.get_rule_condition()
            if not condition:
                return True  # No condition means applies to all
            
            # Check explicit event type in condition
            rule_event_type = condition.get('event_type')
            if rule_event_type:
                return rule_event_type.lower() == event_type.lower()
            
            # Check based on condition fields
            if any(field in condition for field in ['process_name', 'process_path', 'command_line']):
                return event_type.lower() == 'process'
            elif any(field in condition for field in ['file_name', 'file_path', 'file_hash']):
                return event_type.lower() == 'file'
            elif any(field in condition for field in ['source_ip', 'destination_ip', 'protocol']):
                return event_type.lower() == 'network'
            elif any(field in condition for field in ['registry_key', 'registry_value']):
                return event_type.lower() == 'registry'
            elif any(field in condition for field in ['login_user', 'login_type', 'login_result']):
                return event_type.lower() == 'authentication'
            
            return True  # Default to applicable
            
        except Exception as e:
            self.logger.error(f"❌ Error checking rule applicability: {e}")
            return True
    
    async def _evaluate_rule(self, rule: DetectionRule, event_data: Dict) -> bool:
        """Evaluate single rule against event data"""
        try:
            condition = rule.get_rule_condition()
            if not condition:
                self.logger.debug(f"Rule {rule.RuleID} has no condition")
                return False
            
            self.logger.debug(f"🔍 Evaluating rule: {rule.RuleName} (ID: {rule.RuleID})")
            self.logger.debug(f"   📋 Condition: {condition}")
            
            # Handle different rule types
            if rule.RuleType == 'Behavioral':
                return await self._evaluate_behavioral_rule(condition, event_data)
            elif rule.RuleType == 'Signature':
                return await self._evaluate_signature_rule(condition, event_data)
            elif rule.RuleType == 'Threshold':
                return await self._evaluate_threshold_rule(condition, event_data)
            elif rule.RuleType == 'Correlation':
                return await self._evaluate_correlation_rule(condition, event_data)
            else:
                self.logger.warning(f"Unknown rule type: {rule.RuleType}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error evaluating rule {rule.RuleID}: {e}")
            return False
    
    async def _evaluate_behavioral_rule(self, condition: Dict, event_data: Dict) -> bool:
        """Evaluate behavioral rule"""
        try:
            # Check if event type matches
            if 'event_type' in condition:
                event_type_rule = condition['event_type']
                event_type_event = event_data.get('event_type', '')
                self.logger.debug(f"   [DEBUG] So sánh event_type: rule={event_type_rule} vs event={event_type_event}")
                if event_type_rule.lower() != event_type_event.lower():
                    self.logger.warning(f"   [WARNING] Event type mismatch: {event_type_event} != {event_type_rule}")
                    return False
                else:
                    self.logger.debug(f"   [DEBUG] ✅ Event type match: {event_type_event} == {event_type_rule}")
            
            # Evaluate conditions
            results = []
            conditions = condition.get('conditions', [])
            self.logger.debug(f"   [DEBUG] Evaluating {len(conditions)} conditions...")
            
            for i, cond in enumerate(conditions):
                field = cond['field']
                operator = cond['operator']
                value = cond['value']
                field_value = self._get_field_value(event_data, field)
                
                self.logger.debug(f"   [DEBUG] Condition {i+1}: {field} {operator} {value}")
                self.logger.debug(f"      [DEBUG] Field value from event: {field_value}")
                self.logger.debug(f"      [DEBUG] Expected value from rule: {value}")
                
                result = self._evaluate_condition(field_value, operator, value)
                results.append(result)
                
                self.logger.debug(f"      [DEBUG] Result: {result}")
                
                if not result:
                    self.logger.warning(f"      [WARNING] Condition {i+1} FAILED: {field} {operator} {value}")
                else:
                    self.logger.debug(f"      [DEBUG] ✅ Condition {i+1} PASSED: {field} {operator} {value}")
            
            # Apply logic (AND/OR)
            logic = condition.get('logic', 'AND')
            if logic == 'AND':
                final_result = all(results)
            else:  # OR
                final_result = any(results)
                
            self.logger.debug(f"   [DEBUG] Logic {logic}: {results} = {final_result}")
            
            if not final_result:
                self.logger.warning(f"   [WARNING] Rule không match. Kết quả: {results}")
            else:
                self.logger.info(f"   [INFO] ✅ Rule MATCHED! Kết quả: {results}")
                
            return final_result
            
        except Exception as e:
            self.logger.error(f"❌ Error evaluating behavioral rule: {e}")
            return False
    
    async def _evaluate_signature_rule(self, condition: Dict, event_data: Dict) -> bool:
        """Evaluate signature rule"""
        try:
            # Simple signature matching
            for field, value in condition.items():
                if field in ['event_type', 'logic', 'conditions', 'threshold']:
                    continue
                
                field_value = self._get_field_value(event_data, field)
                if not self._evaluate_condition(field_value, 'equals', value):
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error evaluating signature rule: {e}")
            return False
    
    async def _evaluate_threshold_rule(self, condition: Dict, event_data: Dict) -> bool:
        """Evaluate threshold rule"""
        try:
            threshold = condition.get('threshold', {})
            count = threshold.get('count', 10)
            time_window = threshold.get('time_window', 300)  # seconds
            
            # This would require database query to count events in time window
            # For now, return False - implement later
            self.logger.debug(f"Threshold rule not implemented yet")
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Error evaluating threshold rule: {e}")
            return False
    
    async def _evaluate_correlation_rule(self, condition: Dict, event_data: Dict) -> bool:
        """Evaluate correlation rule"""
        try:
            # Correlation rules require multiple events
            # For now, return False - implement later
            self.logger.debug(f"Correlation rule not implemented yet")
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Error evaluating correlation rule: {e}")
            return False
    
    def _evaluate_condition(self, field_value: Any, operator: str, expected_value: Any) -> bool:
        """Evaluate single condition"""
        try:
            if operator not in self.operators:
                self.logger.warning(f"Unknown operator: {operator}")
                return False
            
            result = self.operators[operator](field_value, expected_value)
            self.logger.debug(f"      Condition: {field_value} {operator} {expected_value} = {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Error evaluating condition: {e}")
            return False
    
    def _get_field_value(self, event_data: Dict, field_name: str) -> Any:
        """Get field value from event data"""
        # Map field names to event data keys
        field_mapping = {
            'process_name': 'process_name',
            'process_path': 'process_path',
            'command_line': 'command_line',
            'process_user': 'process_user',
            'process_hash': 'process_hash',
            'file_name': 'file_name',
            'file_path': 'file_path',
            'file_hash': 'file_hash',
            'file_extension': 'file_extension',
            'source_ip': 'source_ip',
            'destination_ip': 'destination_ip',
            'source_port': 'source_port',
            'destination_port': 'destination_port',
            'protocol': 'protocol',
            'registry_key': 'registry_key',
            'registry_value': 'registry_value_name',
            'login_user': 'login_user',
            'login_type': 'login_type',
            'login_result': 'login_result'
        }
        
        mapped_field = field_mapping.get(field_name, field_name)
        value = event_data.get(mapped_field)
        
        self.logger.debug(f"      [DEBUG] Field mapping: {field_name} -> {mapped_field} = {value}")
        
        # Log available fields for debugging
        if value is None:
            available_fields = list(event_data.keys())
            self.logger.debug(f"      [DEBUG] Available fields in event: {available_fields}")
        
        return value
    
    async def _create_alert(self, rule: DetectionRule, event_data: Dict, session: Session) -> Optional[Alert]:
        """Create alert from matched rule"""
        try:
            # Calculate risk score
            risk_score = self._calculate_risk_score(rule, event_data)
            
            # Create alert
            alert = Alert.create_alert(
                agent_id=event_data.get('agent_id'),
                alert_type=rule.AlertType,
                title=rule.AlertTitle,
                severity=rule.AlertSeverity,
                detection_method=rule.RuleType,
                description=rule.AlertDescription if rule.AlertDescription else f"Rule {rule.RuleName} triggered",
                risk_score=risk_score,
                confidence=0.8,
                mitre_tactic=rule.MitreTactic,
                mitre_technique=rule.MitreTechnique
            )
            
            # Add rule reference
            alert.RuleID = rule.RuleID
            
            # Add event reference if available
            if 'event_id' in event_data:
                alert.EventID = event_data['event_id']
            
            # Add response action
            alert.add_response_action(f"Rule {rule.RuleName} triggered at {datetime.now().isoformat()}")
            
            # Save to database
            try:
                session.add(alert)
                session.commit()
                session.refresh(alert)
            except Exception as db_exc:
                self.logger.error(f"❌ DB commit failed when saving alert: {db_exc}")
                import traceback
                self.logger.error(traceback.format_exc())
                session.rollback()
                return None
            
            self.logger.info(f"✅ Alert created: {alert.AlertID} - {alert.Title}")
            
            return alert
            
        except Exception as e:
            self.logger.error(f"❌ Error creating alert: {e}")
            session.rollback()
            return None
    
    def _calculate_risk_score(self, rule: DetectionRule, event_data: Dict) -> int:
        """Calculate risk score for alert"""
        # Base score from rule severity
        severity_scores = {
            'Critical': 100,
            'High': 80,
            'Medium': 60,
            'Low': 40
        }
        
        base_score = severity_scores.get(rule.AlertSeverity, 50)
        
        # Add bonus for suspicious indicators
        bonus = 0
        if event_data.get('process_name') in ['cmd.exe', 'powershell.exe']:
            bonus += 10
        if event_data.get('command_line') and any(indicator in event_data['command_line'].lower() 
                                                for indicator in ['download', 'curl', 'wget', 'certutil']):
            bonus += 20
        
        return min(100, base_score + bonus)
    
    def _determine_platform(self, event_data: Dict) -> str:
        """Determine platform from event data"""
        # Check agent OS info
        agent_os = event_data.get('agent_os', '').lower()
        if 'windows' in agent_os:
            return 'Windows'
        elif 'linux' in agent_os:
            return 'Linux'
        else:
            return 'All'  # Default to all platforms
    
    # Operator implementations
    def _op_equals(self, a: Any, b: Any) -> bool:
        """Equals operator (case insensitive)"""
        if a is None or b is None:
            return a == b
        return str(a).lower() == str(b).lower()
    
    def _op_not_equals(self, a: Any, b: Any) -> bool:
        """Not equals operator"""
        return not self._op_equals(a, b)
    
    def _op_contains(self, a: Any, b: Any) -> bool:
        """Contains operator (case insensitive)"""
        if a is None or b is None:
            return False
        return str(b).lower() in str(a).lower()
    
    def _op_contains_any(self, a: Any, b: Any) -> bool:
        """Contains any operator"""
        if a is None or not isinstance(b, list):
            return False
        a_str = str(a).lower()
        return any(str(item).lower() in a_str for item in b)
    
    def _op_starts_with(self, a: Any, b: Any) -> bool:
        """Starts with operator (case insensitive)"""
        if a is None or b is None:
            return False
        return str(a).lower().startswith(str(b).lower())
    
    def _op_ends_with(self, a: Any, b: Any) -> bool:
        """Ends with operator (case insensitive)"""
        if a is None or b is None:
            return False
        return str(a).lower().endswith(str(b).lower())
    
    def _op_regex(self, a: Any, pattern: str) -> bool:
        """Regex operator"""
        if a is None:
            return False
        try:
            return bool(re.search(pattern, str(a), re.IGNORECASE))
        except re.error:
            return False
    
    def _op_greater_than(self, a: Any, b: Any) -> bool:
        """Greater than operator"""
        try:
            return float(a) > float(b)
        except (ValueError, TypeError):
            return False
    
    def _op_less_than(self, a: Any, b: Any) -> bool:
        """Less than operator"""
        try:
            return float(a) < float(b)
        except (ValueError, TypeError):
            return False
    
    def _op_in(self, a: Any, items: list) -> bool:
        """In operator (case insensitive)"""
        if a is None or not isinstance(items, list):
            return False
        a_str = str(a).lower()
        return a_str in [str(item).lower() for item in items]
    
    def _op_not_in(self, a: Any, items: list) -> bool:
        """Not in operator"""
        return not self._op_in(a, items)
    
    def _op_exists(self, a: Any, _: Any) -> bool:
        """Exists operator"""
        return a is not None and a != ""
    
    def _op_not_exists(self, a: Any, _: Any) -> bool:
        """Not exists operator"""
        return a is None or a == ""

# Global instance
rule_engine = RuleEngine() 