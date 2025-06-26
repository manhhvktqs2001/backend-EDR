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

from ..models.event import Event
from ..models.agent import Agent
from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse,
    GeneratedAlert
)
from ..config import config

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
            
            # 6. CREATE ALERTS if detected
            alerts_generated = []
            if detection_result.get('threat_detected', False):
                alert = await self._create_alert_from_detection(session, event, detection_result)
                if alert:
                    generated_alert = GeneratedAlert(
                        id=alert.AlertID,
                        title=alert.Title,
                        description=alert.Description or f"Alert generated for {event_data.event_type} event",
                        severity=alert.Severity,
                        risk_score=alert.RiskScore,
                        timestamp=alert.FirstDetected.isoformat() if alert.FirstDetected else datetime.now().isoformat(),
                        detection_method=alert.DetectionMethod
                    )
                    alerts_generated.append(generated_alert)
            
            # 7. SEND NOTIFICATIONS (if threats detected)
            if detection_result.get('threat_detected', False):
                await self._send_detection_notifications(session, agent, detection_result, alerts_generated)
            
            # 8. COMMIT ALL CHANGES
            session.commit()
            
            # 9. UPDATE STATS
            processing_time = time.time() - start_time
            self.stats['events_processed'] += 1
            self.stats['processing_time_total'] += processing_time
            
            if detection_result.get('threat_detected', False):
                self.stats['events_detected'] += 1
                self.stats['rules_matched'] += len(detection_result.get('matched_rules', []))
                self.stats['alerts_created'] += len(alerts_generated)
            
            # 10. RESPONSE
            threat_detected = detection_result.get('threat_detected', False)
            risk_score = detection_result.get('risk_score', 0)
            
            logger.info(f"✅ EVENT PROCESSED:")
            logger.info(f"   📋 Event ID: {event.EventID}")
            logger.info(f"   🚨 Threat Detected: {threat_detected}")
            logger.info(f"   📊 Risk Score: {risk_score}")
            logger.info(f"   📋 Alerts: {len(alerts_generated)}")
            logger.info(f"   ⏱️ Time: {processing_time*1000:.1f}ms")
            
            response = EventSubmissionResponse(
                success=True,
                event_id=event.EventID,
                message=f"Event processed successfully",
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=alerts_generated
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Event processing failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    async def _run_detection_on_raw_data(self, session: Session, 
                                        event_data: EventSubmissionRequest, 
                                        agent: Agent) -> Dict:
        """FIXED: Run detection on RAW event data (before DB insert)"""
        try:
            # Import detection service
            from .detection_engine import get_detection_service
            detection_service = get_detection_service()
            
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
            
            # Run detection on raw data
            logger.info("🔍 Analyzing raw event data...")
            result = await detection_service.analyze_raw_event_data(session, detection_data)
            
            if result.get('threat_detected', False):
                logger.warning(f"🚨 THREAT DETECTED in raw data:")
                logger.warning(f"   📊 Risk Score: {result.get('risk_score', 0)}")
                logger.warning(f"   📋 Rules Matched: {len(result.get('matched_rules', []))}")
                logger.warning(f"   🎯 Detection Methods: {result.get('detection_methods', [])}")
                
                # Log rule details
                for rule_detail in result.get('rule_details', []):
                    logger.warning(f"     📝 Rule: {rule_detail.get('rule_name')} (Severity: {rule_detail.get('severity')})")
            
            return result
            
        except Exception as e:
            logger.error(f"💥 Detection on raw data failed: {str(e)}")
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
            
            alert_service = get_alert_service()
            alert = await alert_service.create_alert_from_detection(
                session=session,
                event_id=event.EventID,
                detection_result=detection_result,
                agent_id=str(event.AgentID)
            )
            
            if alert:
                logger.warning(f"🚨 ALERT CREATED:")
                logger.warning(f"   📋 Alert ID: {alert.AlertID}")
                logger.warning(f"   📝 Title: {alert.Title}")
                logger.warning(f"   ⚡ Severity: {alert.Severity}")
                logger.warning(f"   📊 Risk Score: {alert.RiskScore}")
            
            return alert
            
        except Exception as e:
            logger.error(f"💥 Alert creation failed: {str(e)}")
            return None
    
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

def get_event_service() -> EventService:
    """Get the global event service instance"""
    return event_service

# Create global service instance
event_service = EventService()