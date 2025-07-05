# app/services/event_service.py - FIXED: Detection BEFORE Insert
"""
Event Service - FIXED VERSION
Detection engine chạy TRƯỚC khi insert vào DB (đúng flow EDR)
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
import time
import json
import uuid
import redis

from ..models.event import Event
from ..models.agent import Agent
from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse,
    GeneratedAlert
)
from ..config import config
from ..models.alert import Alert
from ..services.agent_communication_service import agent_communication_service
from ..services.action_settings_service import action_settings_service
from ..services.rule_engine import rule_engine

logger = logging.getLogger(__name__)

class EventService:
    """FIXED Event service - Detection BEFORE database insert"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        
        # Performance counters
        self.stats = {
            'events_processed': 0,
            'events_detected': 0,
            'rules_matched': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        
        logger.info("📥 FIXED Event Service - Detection BEFORE Insert")
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                          client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """FIXED: Event processing với detection TRƯỚC insert"""
        start_time = time.time()
        try:
            # 1. FAST VALIDATION
            if not self._validate_event_fast(event_data):
                return False, None, "Invalid event data"
            # 2. GET AGENT (with caching)
            agent = self._get_agent_fast(session, event_data.agent_id)
            if not agent:
                return False, None, f"Agent {event_data.agent_id} not found"
            logger.info(f"📥 EVENT RECEIVED:")
            logger.info(f"   🎯 Agent: {agent.HostName}")
            logger.info(f"   📋 Type: {event_data.event_type}")
            logger.info(f"   🔧 Action: {event_data.event_action}")
            if event_data.process_name:
                logger.info(f"   🖥️ Process: {event_data.process_name}")
            # 3. ⚡ RUN DETECTION FIRST (BEFORE DB INSERT)
            logger.info("🔍 RUNNING DETECTION ENGINE...")
            detection_result = await self._run_detection_on_raw_data(session, event_data, agent)
            # 4. CREATE EVENT OBJECT (with detection results)
            event = self._create_event_with_detection_results(event_data, agent, detection_result)
            if not event:
                return False, None, "Event creation failed"
            # 5. INSERT TO DATABASE (AFTER detection)
            session.add(event)
            session.flush()  # Get EventID
            session.commit()  # Commit the event
            alerts_generated = []
            action_command = None
            # Chỉ tạo alert nếu có rule_details (tức là match rule)
            if detection_result.get('rule_details'):
                rule_info = detection_result['rule_details'][0]
                
                # Ensure we have valid values for all required fields
                alert_title = rule_info.get('alert_title')
                if not alert_title:
                    alert_title = 'Security Alert'
                
                alert_description = rule_info.get('alert_description')
                if not alert_description:
                    alert_description = 'Suspicious activity detected'
                
                alert_severity = rule_info.get('alert_severity')
                if not alert_severity:
                    alert_severity = 'Medium'
                
                alert_risk_score = rule_info.get('risk_score')
                if alert_risk_score is None:
                    alert_risk_score = 80
                
                # Debug logging for GeneratedAlert creation
                logger.debug(f"Creating GeneratedAlert:")
                logger.debug(f"  Title: {alert_title}")
                logger.debug(f"  Description: {alert_description}")
                logger.debug(f"  Severity: {alert_severity}")
                logger.debug(f"  Risk Score: {alert_risk_score}")
                
                try:
                    alert = GeneratedAlert(
                        id=event.EventID,
                        title=alert_title,
                        description=alert_description,
                        severity=alert_severity,
                        risk_score=alert_risk_score,
                        timestamp=datetime.now().isoformat(),
                        detection_method='rule_engine'
                    )
                    alerts_generated.append(alert)
                    logger.debug(f"✅ GeneratedAlert created successfully")
                except Exception as e:
                    logger.error(f"❌ Failed to create GeneratedAlert: {e}")
                    logger.error(f"  Title: {alert_title}")
                    logger.error(f"  Description: {alert_description}")
                    logger.error(f"  Severity: {alert_severity}")
                    logger.error(f"  Risk Score: {alert_risk_score}")
                    # Create a fallback alert with safe values
                    fallback_alert = GeneratedAlert(
                        id=event.EventID,
                        title="Security Alert",
                        description="Suspicious activity detected",
                        severity="Medium",
                        risk_score=80,
                        timestamp=datetime.now().isoformat(),
                        detection_method='rule_engine'
                    )
                    alerts_generated.append(fallback_alert)
            # 7. Nếu không match rule, không trả về alert/action
            # Convert GeneratedAlert objects to dictionaries for response
            alerts_dict = []
            for alert in alerts_generated:
                alert_dict = {
                    'id': alert.id,
                    'title': alert.title,
                    'description': alert.description,
                    'severity': alert.severity,
                    'risk_score': alert.risk_score,
                    'timestamp': alert.timestamp,
                    'detection_method': alert.detection_method
                }
                alerts_dict.append(alert_dict)
                logger.debug(f"✅ Converted alert to dict: {alert_dict}")
            
            logger.info(f"📊 Final response: {len(alerts_dict)} alerts, threat_detected={bool(alerts_generated)}")
            
            try:
                response = EventSubmissionResponse(
                    success=True,
                    event_id=str(event.EventID),  # Convert to string
                    threat_detected=bool(alerts_generated),
                    risk_score=detection_result.get('risk_score', 0),
                    alerts_generated=alerts_dict,
                    action_command=action_command,
                    message="Event processed with detection engine"
                )
                logger.debug(f"✅ EventSubmissionResponse created successfully")
            except Exception as e:
                logger.error(f"❌ Failed to create EventSubmissionResponse: {e}")
                logger.error(f"  event_id: {event.EventID} (type: {type(event.EventID)})")
                logger.error(f"  alerts_dict: {alerts_dict}")
                raise
            processing_time = time.time() - start_time
            logger.info(f"✅ Event processed in {processing_time:.3f}s")
            return True, response, None
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Event submission failed after {processing_time:.3f}s: {e}")
            return False, None, str(e)
    
    async def _run_detection_on_raw_data(self, session: Session, 
                                        event_data: EventSubmissionRequest, 
                                        agent: Agent) -> Dict:
        """INTEGRATED: Run detection on RAW event data using RuleEngine"""
        try:
            # Convert raw event data to detection format
            detection_data = {
                'agent_id': str(agent.AgentID),
                'agent_hostname': agent.HostName,
                'agent_os': agent.OperatingSystem,
                'operating_system': agent.OperatingSystem,
                'event_type': event_data.event_type.value if hasattr(event_data.event_type, 'value') else str(event_data.event_type),
                'event_action': event_data.event_action,
                'event_timestamp': event_data.event_timestamp,
                'severity': event_data.severity.value if hasattr(event_data.severity, 'value') else str(event_data.severity),
                
                # Process data
                'process_id': event_data.process_id,
                'process_name': event_data.process_name,
                'process_path': event_data.process_path,
                'command_line': event_data.command_line,
                'parent_pid': event_data.parent_pid,
                'parent_process_name': event_data.parent_process_name,
                'process_user': event_data.process_user,
                'process_hash': event_data.process_hash,
                
                # File data
                'file_name': event_data.file_name,
                'file_path': event_data.file_path,
                'file_hash': event_data.file_hash,
                'file_size': event_data.file_size,
                'file_extension': event_data.file_extension,
                'file_operation': event_data.file_operation,
                
                # Network data
                'source_ip': event_data.source_ip,
                'destination_ip': event_data.destination_ip,
                'source_port': event_data.source_port,
                'destination_port': event_data.destination_port,
                'protocol': event_data.protocol,
                'direction': event_data.direction,
                
                # Registry data
                'registry_key': event_data.registry_key,
                'registry_value_name': event_data.registry_value_name,
                'registry_value_data': event_data.registry_value_data,
                'registry_operation': event_data.registry_operation,
                
                # Authentication data
                'login_user': event_data.login_user,
                'login_type': event_data.login_type,
                'login_result': event_data.login_result,
                
                # Raw data
                'raw_event_data': event_data.raw_event_data
            }
            
            # Run INTEGRATED RuleEngine on raw data
            logger.info("🔍 Running INTEGRATED RuleEngine on raw event data...")
            logger.info(f"   📋 Event: {detection_data.get('event_type')} - {detection_data.get('process_name', 'N/A')}")
            logger.info(f"   🎯 Agent: {agent.HostName} ({agent.OperatingSystem})")
            
            alerts = await rule_engine.process_event(session, detection_data)
            
            # Convert alerts to detection result format
            result = {
                'threat_detected': len(alerts) > 0,
                'threat_level': 'Malicious' if alerts else 'None',
                'risk_score': max([alert.RiskScore for alert in alerts], default=0),
                'detection_methods': ['rule_engine'] if alerts else [],
                'matched_rules': [alert.RuleID for alert in alerts if alert.RuleID],
                'rule_details': []
            }
            
            # Add rule details for each alert
            for alert in alerts:
                # Debug logging
                logger.debug(f"Creating rule detail for alert {alert.AlertID}:")
                logger.debug(f"  Title: {alert.Title}")
                logger.debug(f"  Description: {alert.Description}")
                logger.debug(f"  Severity: {alert.Severity}")
                
                rule_detail = {
                    'rule_id': alert.RuleID,
                    'rule_name': f"Rule {alert.RuleID}",
                    'alert_title': alert.Title,
                    'alert_description': alert.Description if alert.Description else f"Rule {alert.RuleID} triggered",
                    'alert_severity': alert.Severity,
                    'alert_type': alert.AlertType,
                    'risk_score': alert.RiskScore,
                    'mitre_tactic': alert.MitreTactic,
                    'mitre_technique': alert.MitreTechnique
                }
                result['rule_details'].append(rule_detail)
            
            if result.get('threat_detected', False):
                logger.warning(f"🚨 THREAT DETECTED by INTEGRATED RuleEngine:")
                logger.warning(f"   📊 Risk Score: {result.get('risk_score', 0)}")
                logger.warning(f"   📋 Rules Matched: {len(result.get('matched_rules', []))}")
                logger.warning(f"   🎯 Alerts Generated: {len(alerts)}")
                
                # Log rule details
                for rule_detail in result.get('rule_details', []):
                    logger.warning(f"     📝 Rule: {rule_detail.get('rule_name')} (Severity: {rule_detail.get('alert_severity')})")
            else:
                logger.info(f"✅ No threats detected by RuleEngine")
            
            return result
            
        except Exception as e:
            logger.error(f"💥 INTEGRATED RuleEngine detection failed: {str(e)}")
            return {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'error': str(e)
            }
    
    def _create_event_with_detection_results(self, event_data: EventSubmissionRequest, 
                                           agent: Agent, detection_result: Dict) -> Optional[Event]:
        """Create event object với detection results đã có"""
        try:
            event_type = event_data.event_type.value if hasattr(event_data.event_type, 'value') else str(event_data.event_type)
            severity = event_data.severity.value if hasattr(event_data.severity, 'value') else str(event_data.severity)
            
            event = Event.create_event(
                agent_id=str(agent.AgentID),
                event_type=event_type,
                event_action=event_data.event_action[:50],
                event_timestamp=event_data.event_timestamp,
                Severity=severity
            )
            
            # Set detection results
            event.Analyzed = True
            event.AnalyzedAt = datetime.now()
            event.ThreatLevel = detection_result.get('threat_level', 'None')
            event.RiskScore = detection_result.get('risk_score', 0)
            
            # Set event-specific fields
            if event_type == 'Process':
                event.ProcessID = event_data.process_id
                event.ProcessName = event_data.process_name[:255] if event_data.process_name else None
                event.ProcessPath = event_data.process_path[:500] if event_data.process_path else None
                event.CommandLine = event_data.command_line
                event.ParentPID = event_data.parent_pid
                event.ParentProcessName = event_data.parent_process_name[:255] if event_data.parent_process_name else None
                event.ProcessUser = event_data.process_user[:100] if event_data.process_user else None
                event.ProcessHash = event_data.process_hash[:128] if event_data.process_hash else None
            
            elif event_type == 'File':
                event.FilePath = event_data.file_path[:500] if event_data.file_path else None
                event.FileName = event_data.file_name[:255] if event_data.file_name else None
                event.FileSize = event_data.file_size
                event.FileHash = event_data.file_hash[:128] if event_data.file_hash else None
                event.FileExtension = event_data.file_extension[:10] if event_data.file_extension else None
                event.FileOperation = event_data.file_operation[:20] if event_data.file_operation else None
            
            elif event_type == 'Network':
                event.SourceIP = event_data.source_ip[:45] if event_data.source_ip else None
                event.DestinationIP = event_data.destination_ip[:45] if event_data.destination_ip else None
                event.SourcePort = event_data.source_port
                event.DestinationPort = event_data.destination_port
                event.Protocol = event_data.protocol[:10] if event_data.protocol else None
                event.Direction = event_data.direction[:10] if event_data.direction else None
            
            elif event_type == 'Registry':
                event.RegistryKey = event_data.registry_key[:500] if event_data.registry_key else None
                event.RegistryValueName = event_data.registry_value_name[:255] if event_data.registry_value_name else None
                event.RegistryValueData = event_data.registry_value_data
                event.RegistryOperation = event_data.registry_operation[:20] if event_data.registry_operation else None
            
            elif event_type == 'Authentication':
                event.LoginUser = event_data.login_user[:100] if event_data.login_user else None
                event.LoginType = event_data.login_type[:50] if event_data.login_type else None
                event.LoginResult = event_data.login_result[:20] if event_data.login_result else None
            
            # Raw event data
            if event_data.raw_event_data:
                event.RawEventData = json.dumps(event_data.raw_event_data)
            
            return event
            
        except Exception as e:
            logger.error(f"Event creation failed: {e}")
            return None
    
    async def _create_alert_from_detection(self, session: Session, event: Event, 
                                         detection_result: Dict) -> Optional:
        """Create alert from detection results"""
        try:
            from .alert_service import get_alert_service
            from ..services.agent_communication_service import agent_communication_service
            alert_service = get_alert_service()
            alert = await alert_service.create_alert_from_detection(
                session=session,
                event_id=event.EventID,
                detection_result=detection_result,
                agent_id=str(event.AgentID)
            )
            
            # --- ĐIỀU KIỆN KIÊN QUYẾT: chỉ khi match rule mới thực hiện action hoặc alert ---
            rule_matched = False
            if hasattr(detection_result, 'get'):
                if detection_result.get('matched_rules') or detection_result.get('rule_details'):
                    rule_matched = True
            if not rule_matched:
                logger.debug(f"[ACTION] No rule matched for event {event.EventID}, skipping action processing")
                return alert
            # --- END: chỉ khi match rule mới thực hiện action hoặc alert ---
            
            # Lấy action_settings mới nhất từ Redis
            action_settings = self.get_action_settings_for_agent(str(event.AgentID))
            mode = action_settings.get('globalActionMode', 'alert_only')
            logger.warning(f"[ACTION] Action mode for agent {event.AgentID}: {mode}")
            
            if mode == 'alert_only':
                logger.warning(f"[ACTION] Alert-only mode: only creating alert, no action will be performed.")
                return alert
            
            # Nếu alert_and_action, xác định loại event và thực hiện action phù hợp
            event_actions = action_settings.get('eventActions', [])
            logger.warning(f"[ACTION] Processing {len(event_actions)} event actions for agent {event.AgentID}")
            
            # Xác định event type từ event data
            event_type = self._determine_event_type(event)
            logger.warning(f"[ACTION] Determined event type: {event_type}")
            
            # Tìm action settings cho event type này
            matching_action = None
            for ea in event_actions:
                if ea.get('event_type') == event_type and ea.get('enabled', False):
                    matching_action = ea
                    break
            
            if not matching_action:
                logger.warning(f"[ACTION] No enabled action found for event type {event_type}")
                return alert
            
            # Kiểm tra severity
            event_severity = self._get_event_severity(event, detection_result)
            allowed_severities = matching_action.get('severity', [])
            
            if allowed_severities and event_severity not in allowed_severities:
                logger.warning(f"[ACTION] Event severity {event_severity} not in allowed severities {allowed_severities} for {event_type}")
                return alert
            
            # Thực hiện action dựa trên event type và action type
            action_type = matching_action.get('action')
            action_config = matching_action.get('config', {})
            
            logger.warning(f"[ACTION] Executing action: {action_type} for {event_type} with severity {event_severity}")
            
            success = await self._execute_action(
                session=session,
                agent_id=str(event.AgentID),
                event=event,
                action_type=action_type,
                action_config=action_config,
                event_type=event_type
            )
            
            if success:
                logger.warning(f"[ACTION] Successfully executed {action_type} for {event_type}")
            else:
                logger.error(f"[ACTION] Failed to execute {action_type} for {event_type}")
            
            return alert
            
        except Exception as e:
            logger.error(f"[ACTION] Error in _create_alert_from_detection: {str(e)}")
            return alert
    
    def _determine_event_type(self, event: Event) -> str:
        """Determine event type from event data"""
        try:
            # Check process-related fields
            if (hasattr(event, 'ProcessID') and event.ProcessID) or \
               (hasattr(event, 'process_id') and event.process_id) or \
               (hasattr(event, 'ProcessName') and event.ProcessName) or \
               (hasattr(event, 'process_name') and event.process_name):
                return 'Process'
            
            # Check network-related fields
            if (hasattr(event, 'SourceIP') and event.SourceIP) or \
               (hasattr(event, 'source_ip') and event.source_ip) or \
               (hasattr(event, 'DestinationIP') and event.DestinationIP) or \
               (hasattr(event, 'destination_ip') and event.destination_ip) or \
               (hasattr(event, 'SourcePort') and event.SourcePort) or \
               (hasattr(event, 'source_port') and event.source_port):
                return 'Network'
            
            # Check file-related fields
            if (hasattr(event, 'FilePath') and event.FilePath) or \
               (hasattr(event, 'file_path') and event.file_path) or \
               (hasattr(event, 'FileName') and event.FileName) or \
               (hasattr(event, 'file_name') and event.file_name):
                return 'File'
            
            # Check registry-related fields (Windows)
            if (hasattr(event, 'RegistryKey') and event.RegistryKey) or \
               (hasattr(event, 'registry_key') and event.registry_key):
                return 'Registry'
            
            # Default based on event type
            event_type = getattr(event, 'EventType', '').lower()
            if 'process' in event_type:
                return 'Process'
            elif 'network' in event_type:
                return 'Network'
            elif 'file' in event_type:
                return 'File'
            elif 'registry' in event_type:
                return 'Registry'
            
            # Fallback to Process if uncertain
            return 'Process'
            
        except Exception as e:
            logger.error(f"[ACTION] Error determining event type: {str(e)}")
            return 'Process'
    
    def _get_event_severity(self, event: Event, detection_result: Dict) -> str:
        """Get event severity from event or detection result"""
        try:
            # Try to get from detection result first
            if detection_result.get('rule_details'):
                primary_rule = detection_result['rule_details'][0]
                severity = primary_rule.get('alert_severity')
                if severity:
                    return severity
            
            # Try to get from event
            severity = getattr(event, 'Severity', None) or getattr(event, 'severity', None)
            if severity:
                return severity
            
            # Try to get from detection result risk score
            risk_score = detection_result.get('risk_score', 0)
            if risk_score >= 90:
                return 'Critical'
            elif risk_score >= 70:
                return 'High'
            elif risk_score >= 50:
                return 'Medium'
            else:
                return 'Low'
                
        except Exception as e:
            logger.error(f"[ACTION] Error getting event severity: {str(e)}")
            return 'Medium'
    
    async def _execute_action(self, session: Session, agent_id: str, event: Event, 
                            action_type: str, action_config: Dict, event_type: str) -> bool:
        """Execute specific action based on action type"""
        try:
            from ..services.agent_communication_service import agent_communication_service
            
            action_cmd = None
            
            if event_type == 'Process' and action_type == 'kill_process':
                process_id = (
                    getattr(event, 'ProcessID', None) or
                    getattr(event, 'process_id', None) or
                    (event.RawData.get('process_id') if hasattr(event, 'RawData') and isinstance(event.RawData, dict) else None)
                )
                process_name = (
                    getattr(event, 'ProcessName', None) or
                    getattr(event, 'process_name', None) or
                    (event.RawData.get('process_name') if hasattr(event, 'RawData') and isinstance(event.RawData, dict) else None)
                )
                
                if not process_id:
                    logger.warning(f"[ACTION] No process_id found for kill_process action")
                    return False
                
                action_cmd = {
                    'type': 'kill_process',
                    'process_id': process_id,
                    'process_name': process_name,
                    'force_kill': action_config.get('force_kill', True),
                    'timeout_seconds': action_config.get('timeout_seconds', 30)
                }
                
            elif event_type == 'Network' and action_type == 'block_network':
                ip = (
                    getattr(event, 'DestinationIP', None) or
                    getattr(event, 'destination_ip', None) or
                    getattr(event, 'SourceIP', None) or
                    getattr(event, 'source_ip', None)
                )
                
                if not ip:
                    logger.warning(f"[ACTION] No IP found for block_network action")
                    return False
                
                action_cmd = {
                    'type': 'block_network',
                    'ip': ip,
                    'block_duration_hours': action_config.get('block_duration_hours', 24),
                    'block_direction': action_config.get('block_direction', 'both')
                }
                
            elif event_type == 'File' and action_type == 'quarantine_file':
                file_path = (
                    getattr(event, 'FilePath', None) or
                    getattr(event, 'file_path', None) or
                    (event.RawData.get('file_path') if hasattr(event, 'RawData') and isinstance(event.RawData, dict) else None)
                )
                
                if not file_path:
                    logger.warning(f"[ACTION] No file_path found for quarantine_file action")
                    return False
                
                action_cmd = {
                    'type': 'quarantine_file',
                    'file_path': file_path,
                    'backup': action_config.get('backup', False),
                    'quarantine_location': action_config.get('quarantine_location', '/var/quarantine')
                }
                
            elif event_type == 'Registry' and action_type == 'block_registry':
                registry_key = (
                    getattr(event, 'RegistryKey', None) or
                    getattr(event, 'registry_key', None)
                )
                
                if not registry_key:
                    logger.warning(f"[ACTION] No registry_key found for block_registry action")
                    return False
                
                action_cmd = {
                    'type': 'block_registry',
                    'registry_key': registry_key,
                    'block_duration_hours': action_config.get('block_duration_hours', 24)
                }
            
            if action_cmd:
                # Add metadata to action command
                action_cmd.update({
                    'event_id': event.EventID,
                    'event_type': event_type,
                    'timestamp': datetime.now().isoformat(),
                    'agent_id': agent_id
                })
                
                # Send action command to agent
                success = await agent_communication_service.send_action_command(
                    session=session,
                    agent_id=agent_id,
                    action=action_cmd
                )
                
                if success:
                    logger.warning(f"[ACTION] Successfully queued action command: {action_cmd}")
                    return True
                else:
                    logger.error(f"[ACTION] Failed to queue action command: {action_cmd}")
                    return False
            else:
                logger.warning(f"[ACTION] Unsupported action type: {action_type} for event type: {event_type}")
                return False
                
        except Exception as e:
            logger.error(f"[ACTION] Error executing action {action_type}: {str(e)}")
            return False
    
    async def _send_detection_notifications(self, session: Session, agent: Agent, 
                                          detection_result: Dict, alerts: List[GeneratedAlert]):
        """Send notifications for detected threats"""
        try:
            from ..services.agent_communication_service import agent_communication_service
            
            # Create notification data
            notification = {
                'type': 'realtime_detection',
                'category': 'security_threat',
                'agent_id': str(agent.AgentID),
                'agent_hostname': agent.HostName,
                'threat_detected': detection_result.get('threat_detected', False),
                'risk_score': detection_result.get('risk_score', 0),
                'threat_level': detection_result.get('threat_level', 'None'),
                'detection_methods': detection_result.get('detection_methods', []),
                'matched_rules': detection_result.get('matched_rules', []),
                'alerts_generated': [alert.dict() for alert in alerts],
                'timestamp': datetime.now().isoformat(),
                
                # Display settings
                'title': f"🚨 Security Threat Detected",
                'message': f"Risk Score: {detection_result.get('risk_score', 0)} | {len(alerts)} alerts generated",
                'severity': self._determine_notification_severity(detection_result.get('risk_score', 0)),
                'display_popup': True,
                'play_sound': detection_result.get('risk_score', 0) >= 70,
                'requires_acknowledgment': detection_result.get('risk_score', 0) >= 80,
                'auto_escalate': detection_result.get('risk_score', 0) >= 90
            }
            
            # Send notification
            success = await agent_communication_service.send_realtime_notification(
                session=session,
                agent_id=str(agent.AgentID),
                notification=notification
            )
            
            if success:
                self.stats['notifications_sent'] += 1
                logger.warning(f"📤 NOTIFICATION SENT to {agent.HostName}")
            else:
                logger.error(f"❌ NOTIFICATION FAILED for {agent.HostName}")
            
        except Exception as e:
            logger.error(f"💥 Notification sending failed: {str(e)}")
    
    def _determine_notification_severity(self, risk_score: int) -> str:
        """Determine notification severity from risk score"""
        if risk_score >= 90:
            return "Critical"
        elif risk_score >= 70:
            return "High"
        elif risk_score >= 50:
            return "Medium"
        else:
            return "Low"
    
    # Helper methods (unchanged from original)
    def _validate_event_fast(self, event_data: EventSubmissionRequest) -> bool:
        """Fast event validation"""
        try:
            if not event_data.agent_id or not event_data.event_type or not event_data.event_action:
                return False
            
            try:
                uuid.UUID(event_data.agent_id)
            except ValueError:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _get_agent_fast(self, session: Session, agent_id: str) -> Optional[Agent]:
        """Fast agent lookup with caching"""
        # Simple implementation - can add caching later
        return Agent.get_by_id(session, agent_id)
    
    async def submit_event_batch(self, session: Session, batch_data: EventBatchRequest,
                                client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """Batch event submission with detection BEFORE insert"""
        start_time = time.time()
        batch_size = len(batch_data.events)
        
        if batch_size > self.max_batch_size:
            return False, None, f"Batch size {batch_size} exceeds maximum {self.max_batch_size}"
        
        logger.info(f"🚀 PROCESSING BATCH: {batch_size} events from {client_ip}")
        
        processed_events = 0
        failed_events = 0
        threats_detected = 0
        alerts_generated = []
        errors = []
        
        try:
            for i, event_data in enumerate(batch_data.events):
                try:
                    success, response, error = await self.submit_event(session, event_data, client_ip)
                    
                    if success:
                        processed_events += 1
                        if response.threat_detected:
                            threats_detected += 1
                        if response.alerts_generated:
                            alerts_generated.extend(response.alerts_generated)
                    else:
                        failed_events += 1
                        errors.append(f"Event {i}: {error}")
                        
                except Exception as e:
                    failed_events += 1
                    error_msg = f"Event {i} processing failed: {str(e)}"
                    errors.append(error_msg)
                    logger.error(f"❌ {error_msg}")
            
            processing_time = time.time() - start_time
            
            logger.info(f"✅ BATCH COMPLETED:")
            logger.info(f"   Total: {batch_size}")
            logger.info(f"   Successful: {processed_events}")
            logger.info(f"   Failed: {failed_events}")
            logger.info(f"   Threats Detected: {threats_detected}")
            logger.info(f"   Alerts Generated: {len(alerts_generated)}")
            logger.info(f"   Time: {processing_time:.3f}s")
            
            batch_response = EventBatchResponse(
                success=failed_events == 0,
                message=f"Batch processed: {processed_events}/{batch_size} successful",
                total_events=batch_size,
                processed_events=processed_events,
                failed_events=failed_events,
                threats_detected=threats_detected,
                alerts_generated=alerts_generated,
                errors=errors if errors else []
            )
            
            return True, batch_response, None
                
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Batch processing failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get service performance statistics"""
        try:
            uptime = datetime.now() - self.stats['last_reset']
            avg_processing_time = (self.stats['processing_time_total'] / 
                                 max(self.stats['events_processed'], 1))
            
            return {
                'events_processed': self.stats['events_processed'],
                'events_detected': self.stats['events_detected'],
                'rules_matched': self.stats['rules_matched'],
                'alerts_created': self.stats['alerts_created'],
                'notifications_sent': self.stats['notifications_sent'],
                'average_processing_time_ms': round(avg_processing_time * 1000, 2),
                'events_per_second': round(self.stats['events_processed'] / max(uptime.total_seconds(), 1), 2),
                'detection_rate': round((self.stats['events_detected'] / max(self.stats['events_processed'], 1)) * 100, 2),
                'rule_match_rate': round((self.stats['rules_matched'] / max(self.stats['events_processed'], 1)) * 100, 2),
                'alert_creation_rate': round((self.stats['alerts_created'] / max(self.stats['events_processed'], 1)) * 100, 2),
                'notification_success_rate': round((self.stats['notifications_sent'] / max(self.stats['alerts_created'], 1)) * 100, 2),
                'uptime_seconds': int(uptime.total_seconds())
            }
        except Exception as e:
            logger.error(f"Performance stats failed: {e}")
            return {}
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_processed': 0,
            'events_detected': 0,
            'rules_matched': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        logger.info("📊 Statistics reset")

    def get_action_settings_for_agent(self, agent_id):
        """Get action settings for agent using the new service"""
        try:
            from .action_settings_service import action_settings_service
            return action_settings_service.get_action_settings(agent_id)
        except Exception as e:
            logger.error(f"Failed to get action settings for agent {agent_id}: {str(e)}")
            # Return default settings
            return {
                'globalActionMode': 'alert_only',
                'eventActions': []
            }

    async def process_event_with_action_settings(self, session: Session, event_data: Dict, agent_id: str) -> Dict[str, Any]:
        """Process event with action settings from Redis cache"""
        try:
            # Get action settings from Redis cache
            action_settings = action_settings_service.get_action_settings(agent_id)
            
            # Extract event information
            event_type = event_data.get('event_type', 'Unknown')
            severity = event_data.get('severity', 'Medium')
            
            # Check conditions: enabled AND event_type match AND severity match
            conditions_met = False
            action_command = None
            rule_matched = False
            matched_rule = None
            
            # --- NEW: Check for matched rule in event_data (from detection engine) ---
            rule_details = event_data.get('rule_details')
            if rule_details and isinstance(rule_details, list) and len(rule_details) > 0:
                rule_matched = True
                matched_rule = rule_details[0]
            
            if action_settings:
                global_action_mode = action_settings.get('globalActionMode', 'alert_only')
                event_actions = action_settings.get('eventActions', [])
                
                # Check if any event action matches current event
                for event_action in event_actions:
                    if (event_action.get('enabled', False) and 
                        event_action.get('eventType') == event_type and
                        event_action.get('severity') == severity):
                        conditions_met = True
                        break
                
                # If conditions met, create action command
                if conditions_met:
                    action_command = {
                        'type': 'kill_process',  # Default action type
                        'event_type': event_type,
                        'event_id': event_data.get('event_id', 'unknown'),
                        'severity': severity,
                        'conditions_met': True,
                        'global_mode': global_action_mode,
                        'timestamp': datetime.now().isoformat()
                    }
                    # Add specific action data based on event type
                    if event_type == 'Process':
                        action_command.update({
                            'type': 'kill_process',
                            'process_id': event_data.get('process_id'),
                            'process_name': event_data.get('process_name', 'Unknown'),
                            'force_kill': True,
                            'timeout_seconds': 30
                        })
                    elif event_type == 'Network':
                        action_command.update({
                            'type': 'block_network',
                            'ip': event_data.get('remote_ip'),
                            'block_duration_hours': 24,
                            'block_direction': 'both'
                        })
                    elif event_type == 'File':
                        action_command.update({
                            'type': 'quarantine_file',
                            'file_path': event_data.get('file_path'),
                            'backup': True,
                            'quarantine_location': 'C:\\EDR_Quarantine'
                        })
                    elif event_type == 'Registry':
                        action_command.update({
                            'type': 'block_registry',
                            'registry_key': event_data.get('registry_key'),
                            'block_duration_hours': 24
                        })
            # --- END NEW ---
            response = {
                'success': True,
                'threat_detected': rule_matched,
                'risk_score': event_data.get('risk_score', 80),
            }
            # Chỉ gửi alert nếu match rule
            if rule_matched and matched_rule:
                response['alerts_generated'] = [
                    {
                        'title': matched_rule.get('alert_title', f'Threat Detected: {event_type}'),
                        'description': matched_rule.get('alert_description', f'Suspicious {event_type} activity detected'),
                        'severity': matched_rule.get('alert_severity', severity),
                        'risk_score': event_data.get('risk_score', 80),
                        'timestamp': datetime.now().isoformat(),
                        'event_type': event_type,
                        'event_id': event_data.get('event_id', 'unknown')
                    }
                ]
            # Add action command if conditions met
            if action_command:
                response['action_command'] = action_command
                logger.warning(f"🚨 THREAT DETECTED WITH ACTION: {event_type} - Severity: {severity}")
                logger.warning(f"   🎯 Agent: {agent_id}")
                logger.warning(f"   🔧 Action: {action_command.get('type')}")
                logger.warning(f"   ✅ Conditions Met: {conditions_met}")
            elif rule_matched:
                logger.warning(f"🚨 THREAT DETECTED (ALERT ONLY): {event_type} - Severity: {severity}")
                logger.warning(f"   🎯 Agent: {agent_id}")
                logger.warning(f"   ℹ️ No action conditions met")
            return response
        except Exception as e:
            logger.error(f"Error processing event with action settings: {e}")
            return {
                'success': True,
                'threat_detected': False,
                'risk_score': 0,
                'error': str(e)
            }

    async def store_event(self, session: Session, event_data: Dict) -> bool:
        """Store event in database"""
        try:
            # Convert all datetime values in event_data to string before dumping
            def convert_dt(obj):
                if isinstance(obj, dict):
                    return {k: convert_dt(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_dt(i) for i in obj]
                elif isinstance(obj, datetime):
                    return obj.isoformat()
                else:
                    return obj
            event_data_serializable = convert_dt(event_data)

            # Map network fields if present
            source_ip = event_data.get('source_ip') or event_data.get('SourceIP')
            destination_ip = event_data.get('destination_ip') or event_data.get('DestinationIP')
            source_port = event_data.get('source_port') or event_data.get('SourcePort')
            destination_port = event_data.get('destination_port') or event_data.get('DestinationPort')
            protocol = event_data.get('protocol') or event_data.get('Protocol')
            direction = event_data.get('direction') or event_data.get('Direction')

            # Parse EventTimestamp
            ts = event_data.get('timestamp') or event_data.get('event_timestamp')
            if ts:
                try:
                    event_timestamp = datetime.fromisoformat(ts)
                except Exception:
                    event_timestamp = datetime.now()
            else:
                event_timestamp = datetime.now()

            event = Event(
                AgentID=event_data.get('agent_id'),
                EventType=event_data.get('event_type'),
                EventAction=event_data.get('event_action'),
                EventTimestamp=event_timestamp,
                Severity=event_data.get('severity', 'Info'),
                ProcessID=event_data.get('process_id'),
                ProcessName=event_data.get('process_name'),
                ProcessPath=event_data.get('process_path'),
                CommandLine=event_data.get('command_line'),
                ParentPID=event_data.get('parent_pid'),
                ParentProcessName=event_data.get('parent_process_name'),
                ProcessUser=event_data.get('process_user'),
                ProcessHash=event_data.get('process_hash'),
                FilePath=event_data.get('file_path'),
                FileName=event_data.get('file_name'),
                FileSize=event_data.get('file_size'),
                FileHash=event_data.get('file_hash'),
                FileExtension=event_data.get('file_extension'),
                FileOperation=event_data.get('file_operation'),
                SourceIP=source_ip,
                DestinationIP=destination_ip,
                SourcePort=source_port,
                DestinationPort=destination_port,
                Protocol=protocol,
                Direction=direction,
                RegistryKey=event_data.get('registry_key'),
                RegistryValueName=event_data.get('registry_value_name'),
                RegistryValueData=event_data.get('registry_value_data'),
                RegistryOperation=event_data.get('registry_operation'),
                LoginUser=event_data.get('login_user'),
                LoginType=event_data.get('login_type'),
                LoginResult=event_data.get('login_result'),
                ThreatLevel=event_data.get('threat_level', 'None'),
                RiskScore=event_data.get('risk_score', 0),
                Analyzed=event_data.get('analyzed', False),
                AnalyzedAt=None,
                RawEventData=json.dumps(event_data_serializable),
                CreatedAt=datetime.now()
            )
            session.add(event)
            session.commit()
            logger.info(f"✅ Event stored in database: {event.EventID}")
            return True
        except Exception as e:
            logger.error(f"Error storing event: {e}")
            session.rollback()
            return False

def get_event_service() -> EventService:
    """Get the global event service instance"""
    return event_service

# Create global service instance
event_service = EventService()