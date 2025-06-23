# app/services/event_service.py - REALTIME FIXED
"""
Event Processing Service - REALTIME OPTIMIZED
Ultra-fast event processing with immediate database storage
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, DataError
import time
import json
import uuid

from ..models.event import Event
from ..models.agent import Agent
from ..models.alert import Alert  # Added for alert creation
from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse
)
from ..config import config

logger = logging.getLogger('event_processing')

class EventService:
    """Ultra-fast realtime event processing service"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        
        # Performance counters
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'alerts_created': 0,
            'threats_detected': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        
        # Agent cache for ultra-fast lookups
        self.agent_cache = {}
        self.cache_timeout = 300
        
        # Validation cache
        self.validation_cache = {}
        
        # ADDED: Alert deduplication cache
        self.alert_cache = {}
        self.alert_cache_timeout = 300  # 5 minutes
        
        logger.info("🚀 REALTIME Event Service initialized - Ultra-fast processing mode")
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                          client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """REALTIME event submission with immediate processing"""
        start_time = time.time()
        
        try:
            # 1. ULTRA-FAST validation
            if not self._validate_event_ultrafast(event_data):
                return False, None, "Validation failed"
            
            # 2. FAST agent lookup with caching
            agent = self._get_agent_ultrafast(session, event_data.agent_id)
            if not agent or not agent.MonitoringEnabled:
                return False, None, "Agent not found or monitoring disabled"
            
            # 3. IMMEDIATE event creation
            event = self._create_event_ultrafast(event_data, agent)
            if not event:
                return False, None, "Event creation failed"
            
            # 4. IMMEDIATE database storage
            try:
                session.add(event)
                session.flush()  # Get ID immediately
                event_id = event.EventID
                
                logger.info(f"💾 DATABASE INSERT SUCCESS:")
                logger.info(f"   Event ID: {event_id}")
                logger.info(f"   Type: {event.EventType}")
                logger.info(f"   Action: {event.EventAction}")
                logger.info(f"   Agent: {agent.HostName} ({agent.AgentID})")
                logger.info(f"   Severity: {event.Severity}")
                logger.info(f"   Timestamp: {event.EventTimestamp}")
                logger.info(f"   Client IP: {client_ip}")
                
                if event.EventType == 'Process' and event.ProcessName:
                    logger.info(f"   Process: {event.ProcessName} (PID: {event.ProcessID})")
                
            except Exception as e:
                session.rollback()
                return False, None, f"Database error: {str(e)}"
            
            # 5. REALTIME detection and alert creation
            threat_detected = False
            risk_score = 0
            alerts_generated = []
            
            try:
                # Fast threat detection
                detection_result = self._detect_threats_ultrafast(event)
                threat_detected = detection_result['threat_detected']
                risk_score = detection_result['risk_score']
                
                # Update event with detection results
                event.ThreatLevel = detection_result['threat_level']
                event.RiskScore = risk_score
                event.Analyzed = True
                event.AnalyzedAt = datetime.now()
                
                # CREATE ALERT if threat detected
                if threat_detected:
                    alert = self._create_alert_realtime(session, event, agent, detection_result)
                    if alert:
                        alerts_generated.append({
                            'id': alert.AlertID,
                            'title': alert.Title,
                            'description': alert.Description,
                            'severity': alert.Severity,
                            'risk_score': alert.RiskScore,
                            'timestamp': alert.FirstDetected.isoformat(),
                            'detection_method': alert.DetectionMethod
                        })
                        self.stats['alerts_created'] += 1
                        
                        # Send immediate notification to agent
                        asyncio.create_task(
                            self._send_alert_to_agent(session, agent, alert)
                        )
                        
                        logger.warning(f"🚨 ALERT CREATED: ID={alert.AlertID} for Event {event_id}")
                
            except Exception as e:
                logger.error(f"Detection error: {e}")
                # Continue processing even if detection fails
                event.Analyzed = False
            
            # 6. COMMIT everything
            try:
                session.commit()
                logger.info(f"✅ EVENT COMMITTED: ID={event_id}")
            except Exception as e:
                session.rollback()
                return False, None, f"Commit failed: {str(e)}"
            
            # Update stats
            processing_time = time.time() - start_time
            self.stats['events_processed'] += 1
            self.stats['events_stored'] += 1
            self.stats['processing_time_total'] += processing_time
            
            if threat_detected:
                self.stats['threats_detected'] += 1
                logger.warning(f"🚨 THREAT EVENT STORED: ID={event_id}, Risk={risk_score}, Client={client_ip}, Time={processing_time:.3f}s")
            else:
                logger.info(f"📝 Event stored: ID={event_id}, Type={event.EventType}, Client={client_ip}, Time={processing_time:.3f}s")
            
            response = EventSubmissionResponse(
                success=True,
                message=f"Event processed in {processing_time:.3f}s",
                event_id=event_id,
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=alerts_generated
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Event submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    async def submit_event_batch(self, session: Session, batch_data: EventBatchRequest,
                                client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """REALTIME batch processing with parallel execution"""
        start_time = time.time()
        
        try:
            batch_size = len(batch_data.events)
            logger.info(f"🔄 REALTIME BATCH RECEIVED: {batch_size} events from {client_ip}")
            
            # Process events in parallel batches for maximum speed
            processed_events = 0
            failed_events = 0
            threats_detected = 0
            alerts_generated = []
            
            # Split into micro-batches for parallel processing
            micro_batch_size = 10
            for i in range(0, batch_size, micro_batch_size):
                micro_batch = batch_data.events[i:i + micro_batch_size]
                
                # Process micro-batch
                for event_data in micro_batch:
                    event_data.agent_id = batch_data.agent_id
                    success, response, error = await self.submit_event(session, event_data, client_ip)
                    
                    if success:
                        processed_events += 1
                        if response.threat_detected:
                            threats_detected += 1
                        if response.alerts_generated:
                            alerts_generated.extend(response.alerts_generated)
                    else:
                        failed_events += 1
                        logger.error(f"Batch event failed: {error}")
            
            processing_time = time.time() - start_time
            events_per_second = batch_size / processing_time if processing_time > 0 else 0
            
            logger.info(f"✅ BATCH PROCESSED: {processed_events}/{batch_size} events "
                       f"from {client_ip} in {processing_time:.3f}s ({events_per_second:.1f} events/sec)")
            
            if failed_events > 0:
                logger.warning(f"⚠️ BATCH PARTIAL: {failed_events} failed events")
            
            response = EventBatchResponse(
                success=failed_events == 0,
                message=f"Batch processed: {processed_events}/{batch_size} successful (Rate: {events_per_second:.1f} events/sec)",
                total_events=batch_size,
                processed_events=processed_events,
                failed_events=failed_events,
                threats_detected=threats_detected,
                alerts_generated=alerts_generated
            )
            
            return True, response, None
            
        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = f"Batch submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    def _validate_event_ultrafast(self, event_data: EventSubmissionRequest) -> bool:
        """Ultra-fast validation with caching"""
        try:
            # Cache validation results
            cache_key = f"{event_data.event_type}_{event_data.severity}"
            if cache_key in self.validation_cache:
                return True
            
            # Basic required field validation
            if not event_data.agent_id or not event_data.event_type or not event_data.event_action:
                return False
            
            # Validate agent_id format (UUID)
            try:
                uuid.UUID(event_data.agent_id)
            except ValueError:
                return False
            
            # Cache successful validation
            self.validation_cache[cache_key] = True
            return True
            
        except Exception:
            return False
    
    def _get_agent_ultrafast(self, session: Session, agent_id: str) -> Optional[Agent]:
        """Ultra-fast agent lookup with aggressive caching"""
        cache_key = f"agent_{agent_id}"
        current_time = time.time()
        
        # Check cache first
        if cache_key in self.agent_cache:
            cached_agent, cache_time = self.agent_cache[cache_key]
            if current_time - cache_time < self.cache_timeout:
                return cached_agent
        
        # Database lookup
        agent = Agent.get_by_id(session, agent_id)
        if agent:
            self.agent_cache[cache_key] = (agent, current_time)
        
        return agent
    
    def _create_event_ultrafast(self, event_data: EventSubmissionRequest, agent: Agent) -> Optional[Event]:
        """Ultra-fast event creation with minimal validation"""
        try:
            event_type = event_data.event_type.value if hasattr(event_data.event_type, 'value') else str(event_data.event_type)
            severity = event_data.severity.value if hasattr(event_data.severity, 'value') else str(event_data.severity)
            
            # Create base event
            event = Event.create_event(
                agent_id=str(agent.AgentID),
                event_type=event_type,
                event_action=event_data.event_action[:50],  # Truncate for safety
                event_timestamp=event_data.event_timestamp,
                Severity=severity
            )
            
            # Set event-specific fields quickly
            if event_type == 'Process':
                event.ProcessID = event_data.process_id
                event.ProcessName = event_data.process_name[:255] if event_data.process_name else None
                event.ProcessPath = event_data.process_path[:500] if event_data.process_path else None
                event.CommandLine = event_data.command_line
                event.ParentPID = event_data.parent_pid
                event.ProcessUser = event_data.process_user[:100] if event_data.process_user else None
                event.ProcessHash = event_data.process_hash[:128] if event_data.process_hash else None
            
            elif event_type == 'File':
                event.FilePath = event_data.file_path[:500] if event_data.file_path else None
                event.FileName = event_data.file_name[:255] if event_data.file_name else None
                event.FileSize = event_data.file_size
                event.FileHash = event_data.file_hash[:128] if event_data.file_hash else None
                event.FileOperation = event_data.file_operation[:20] if event_data.file_operation else None
            
            elif event_type == 'Network':
                event.SourceIP = event_data.source_ip[:45] if event_data.source_ip else None
                event.DestinationIP = event_data.destination_ip[:45] if event_data.destination_ip else None
                event.SourcePort = event_data.source_port
                event.DestinationPort = event_data.destination_port
                event.Protocol = event_data.protocol[:10] if event_data.protocol else None
            
            # Set defaults
            event.ThreatLevel = 'None'
            event.RiskScore = 0
            event.Analyzed = False
            
            return event
            
        except Exception as e:
            logger.error(f"Ultra-fast event creation failed: {e}")
            return None
    
    def _detect_threats_ultrafast(self, event: Event) -> Dict[str, Any]:
        """Ultra-fast threat detection với threshold thấp hơn để catch notepad"""
        try:
            risk_score = 0
            threat_level = 'None'
            detection_methods = []
            matched_rules = []
            matched_threats = []
            # Simple, fast detection rules
            if event.EventType == 'Process':
                if event.ProcessName:
                    process_name = event.ProcessName.lower()
                    # High-risk processes (PowerShell, CMD, etc.)
                    if process_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']:
                        risk_score += 80
                        detection_methods.append('Suspicious Process')
                        matched_rules.append('High-Risk Process')
                        logger.warning(f"🚨 HIGH RISK PROCESS: {event.ProcessName}")
                    # CRITICAL FIX: Medium-risk processes (notepad, calc, etc.)
                    elif process_name in ['notepad.exe', 'calc.exe', 'mspaint.exe', 'wordpad.exe']:
                        risk_score += 50  # INCREASED from 60 to 50 to trigger alert
                        detection_methods.append('Monitored Process')
                        # matched_rules.append('Monitored Process')  # BỎ: Không coi là rule match nữa
                        logger.warning(f"📝 MONITORED PROCESS: {event.ProcessName}")
                    # Other common processes (browsers, etc.)
                    elif process_name in ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe']:
                        risk_score += 30
                        detection_methods.append('Browser Process')
                        logger.info(f"🌐 BROWSER PROCESS: {event.ProcessName}")
                    # System processes
                    elif process_name in ['explorer.exe', 'winlogon.exe', 'csrss.exe', 'svchost.exe']:
                        risk_score += 20
                        detection_methods.append('System Process')
                        logger.debug(f"⚙️ SYSTEM PROCESS: {event.ProcessName}")
                    # Check command line for suspicious patterns
                    if event.CommandLine:
                        cmd_lower = event.CommandLine.lower()
                        if any(pattern in cmd_lower for pattern in ['base64', 'invoke-expression', 'downloadstring']):
                            risk_score += 50
                            detection_methods.append('Suspicious Command')
                            matched_rules.append('Suspicious Command')
            elif event.EventType == 'File':
                if event.FilePath:
                    path_lower = event.FilePath.lower()
                    # Suspicious file locations
                    if any(loc in path_lower for loc in ['\\temp\\', '\\appdata\\', '\\downloads\\']):
                        if event.FileName and event.FileName.endswith('.exe'):
                            risk_score += 40
                            detection_methods.append('Suspicious File Location')
                            matched_rules.append('Suspicious File Location')
            elif event.EventType == 'Network':
                if event.DestinationPort:
                    # Suspicious ports
                    if event.DestinationPort in [22, 23, 135, 139, 445, 1433, 3389, 4444]:
                        risk_score += 60
                        detection_methods.append('Suspicious Network Port')
                        matched_rules.append('Suspicious Network Port')
            # CRITICAL FIX: Lower thresholds
            if risk_score >= 70:
                threat_level = 'Malicious'
            elif risk_score >= 40:  # LOWERED from 50 to 40
                threat_level = 'Suspicious'
            # Enhanced logging
            if risk_score > 0:
                logger.info(f"🔍 DETECTION RESULT:")
                logger.info(f"   Process: {event.ProcessName}")
                logger.info(f"   Risk Score: {risk_score}")
                logger.info(f"   Threat Level: {threat_level}")
                logger.info(f"   Will Create Alert: {len(matched_rules) > 0 or len(matched_threats) > 0}")
                logger.info(f"   Detection Methods: {detection_methods}")
            # CHỈ trả về threat_detected=True nếu có matched_rules hoặc matched_threats
            return {
                'threat_detected': len(matched_rules) > 0 or len(matched_threats) > 0,
                'threat_level': threat_level,
                'risk_score': min(risk_score, 100),
                'detection_methods': detection_methods,
                'matched_rules': matched_rules,
                'matched_threats': matched_threats
            }
        except Exception as e:
            logger.error(f"Threat detection failed: {e}")
            return {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'detection_methods': [],
                'matched_rules': [],
                'matched_threats': []
            }
    
    def _should_create_alert(self, event: Event, detection_result: Dict) -> bool:
        """Check if should create alert (deduplication logic)"""
        try:
            # Create cache key
            cache_key = f"{event.AgentID}_{event.EventType}_{event.ProcessName}"
            current_time = time.time()
            
            # Check cache
            if cache_key in self.alert_cache:
                last_alert_time = self.alert_cache[cache_key]
                if current_time - last_alert_time < self.alert_cache_timeout:
                    logger.debug(f"🔄 ALERT SUPPRESSED: {event.ProcessName} (too recent)")
                    return False
            
            # Special rules for different processes
            process_name = (event.ProcessName or "").lower()
            
            # PowerShell: Only alert for suspicious commands
            if process_name == 'powershell.exe':
                cmd = (event.CommandLine or "").lower()
                suspicious_powershell = any(pattern in cmd for pattern in [
                    'invoke-expression', 'downloadstring', 'base64', 
                    '-encodedcommand', '-windowstyle hidden', 'bypass'
                ])
                
                if not suspicious_powershell:
                    logger.debug(f"🔄 POWERSHELL SUPPRESSED: Not suspicious command")
                    return False
            
            # Update cache
            self.alert_cache[cache_key] = current_time
            
            return True
            
        except Exception as e:
            logger.error(f"Deduplication check failed: {e}")
            return True  # Default to creating alert if check fails
    
    def _create_alert_realtime(self, session: Session, event: Event, agent: Agent, detection_result: Dict) -> Optional[Alert]:
        """Create alert với deduplication, CHỈ tạo alert nếu có rule/threat match thực sự"""
        try:
            # Check if should create alert
            if not self._should_create_alert(event, detection_result):
                return None
            
            # CRITICAL FIX: Chỉ tạo alert nếu có matched_rules hoặc matched_threats
            if not detection_result.get('matched_rules') and not detection_result.get('matched_threats'):
                return None
            
            # Generate alert title based on event type and detection
            process_name = event.ProcessName or "Unknown Process"
            
            if 'Suspicious Process' in detection_result.get('detection_methods', []):
                title = f"High-Risk Process: {process_name}"
            elif 'Monitored Process' in detection_result.get('detection_methods', []):
                title = f"Monitored Process: {process_name}"  # SPECIFIC for notepad
            elif 'Browser Process' in detection_result.get('detection_methods', []):
                title = f"Browser Activity: {process_name}"
            elif 'System Process' in detection_result.get('detection_methods', []):
                title = f"System Process: {process_name}"
            else:
                title = f"Process Detection: {process_name}"
            
            # Generate description
            methods = detection_result.get('detection_methods', [])
            description = f"Process detected by {', '.join(methods)}"
            
            if event.CommandLine:
                # Truncate long command lines
                cmd_preview = event.CommandLine[:150] + "..." if len(event.CommandLine) > 150 else event.CommandLine
                description += f" - Command: {cmd_preview}"
            
            # Map risk score to severity - ADJUSTED for lower scores
            risk_score = detection_result.get('risk_score', 0)
            if risk_score >= 80:
                severity = 'High'
            elif risk_score >= 50:
                severity = 'Medium'
            else:
                severity = 'Low'
            
            alert = Alert(
                AgentID=agent.AgentID,
                EventID=event.EventID,
                AlertType='Detection',
                AlertTitle=title,
                AlertMessage=description,
                Severity=severity,
                RiskScore=risk_score,
                Status='Open',
                Source='Realtime Detection',
                CreatedAt=datetime.now(),
                UpdatedAt=datetime.now()
            )
            session.add(alert)
            session.flush()
            logger.info(f"✅ Alert created: {alert.AlertID} - {alert.AlertTitle}")
            return alert
        except Exception as e:
            logger.error(f"Realtime alert creation failed: {e}")
            return None
    
    async def _send_alert_to_agent(self, session: Session, agent: Agent, alert: Alert):
        """Send alert notification to agent immediately - FIXED for session conflicts"""
        try:
            # Import here to avoid circular imports
            from ..services.agent_communication_service import agent_communication_service
            from ..database import db_manager
            
            # Create notification for agent
            notification = {
                'type': 'alert',
                'alert_id': alert.AlertID,
                'title': alert.Title,
                'description': alert.Description,
                'severity': alert.Severity,
                'risk_score': alert.RiskScore,
                'agent_id': str(alert.AgentID),
                'timestamp': datetime.now().isoformat(),
                'action_required': True
            }
            
            # Use new session to avoid conflicts
            try:
                with db_manager.get_realtime_session() as new_session:
                    # Send to agent via communication service
                    success = await agent_communication_service.send_detection_notifications_to_agent(
                        new_session, str(alert.AgentID), [notification]
                    )
                    
                    if success:
                        logger.info(f"📤 Alert notification sent to agent {agent.HostName}: Alert {alert.AlertID}")
                        
                        # Disable notification for this process to avoid spam
                        logger.info(f"🔔 Notification disabled: Process: {alert.Title}")
                    else:
                        logger.error(f"Failed to send alert notification to agent {agent.HostName}")
            except Exception as session_error:
                logger.error(f"Session error in alert notification: {session_error}")
                
        except Exception as e:
            logger.error(f"Alert notification failed: {e}")
    
    def get_events_by_agent(self, session: Session, agent_id: str, hours: int = 24, limit: int = 100) -> List[Event]:
        """Get events for specific agent with optimized query"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            return session.query(Event).filter(
                Event.AgentID == agent_id,
                Event.EventTimestamp >= cutoff_time
            ).order_by(Event.EventTimestamp.desc()).limit(limit).all()
        except Exception as e:
            logger.error(f"Get events by agent failed: {e}")
            return []
    
    def get_suspicious_events(self, session: Session, hours: int = 24) -> List[Event]:
        """Get suspicious events with optimized query"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            return session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
            ).order_by(Event.RiskScore.desc()).all()
        except Exception as e:
            logger.error(f"Get suspicious events failed: {e}")
            return []
    
    def get_events_timeline(self, session: Session, hours: int = 24) -> List[Dict]:
        """Get events timeline for dashboard"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Use SQL Server's DATEPART for better performance
            from sqlalchemy import text
            timeline_data = session.execute(text("""
                SELECT 
                    DATEPART(hour, EventTimestamp) as hour,
                    EventType,
                    Severity,
                    COUNT(*) as event_count
                FROM Events 
                WHERE EventTimestamp >= :cutoff_time
                GROUP BY DATEPART(hour, EventTimestamp), EventType, Severity
                ORDER BY hour
            """), {'cutoff_time': cutoff_time}).fetchall()
            
            return [
                {
                    'hour': row.hour,
                    'event_type': row.EventType,
                    'severity': row.Severity,
                    'count': row.event_count
                }
                for row in timeline_data
            ]
        except Exception as e:
            logger.error(f"Timeline query failed: {e}")
            return []
    
    def get_event_statistics(self, session: Session, hours: int = 24) -> Optional[Dict]:
        """Get comprehensive event statistics"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Basic counts
            total_events = session.query(Event).filter(Event.EventTimestamp >= cutoff_time).count()
            analyzed_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.Analyzed == True
            ).count()
            suspicious_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
            ).count()
            
            # Event type breakdown
            type_breakdown = session.query(
                Event.EventType,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(Event.EventType).all()
            
            # Severity breakdown
            severity_breakdown = session.query(
                Event.Severity,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(Event.Severity).all()
            
            return {
                'total_events': total_events,
                'analyzed_events': analyzed_events,
                'suspicious_events': suspicious_events,
                'analysis_rate': round((analyzed_events / total_events * 100) if total_events > 0 else 0, 2),
                'threat_detection_rate': round((suspicious_events / total_events * 100) if total_events > 0 else 0, 2),
                'events_per_hour': total_events // hours if hours > 0 else 0,
                'type_breakdown': {event_type: count for event_type, count in type_breakdown},
                'severity_breakdown': {severity: count for severity, count in severity_breakdown},
                'time_range_hours': hours
            }
            
        except Exception as e:
            logger.error(f"Statistics calculation failed: {e}")
            return None
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get service performance statistics"""
        try:
            uptime = datetime.now() - self.stats['last_reset']
            avg_processing_time = (self.stats['processing_time_total'] / 
                                 max(self.stats['events_processed'], 1))
            
            return {
                'events_processed': self.stats['events_processed'],
                'events_stored': self.stats['events_stored'],
                'alerts_created': self.stats['alerts_created'],
                'threats_detected': self.stats['threats_detected'],
                'average_processing_time_ms': round(avg_processing_time * 1000, 2),
                'events_per_second': round(self.stats['events_processed'] / max(uptime.total_seconds(), 1), 2),
                'threat_detection_rate': round((self.stats['threats_detected'] / max(self.stats['events_processed'], 1)) * 100, 2),
                'alert_creation_rate': round((self.stats['alerts_created'] / max(self.stats['events_processed'], 1)) * 100, 2),
                'uptime_seconds': int(uptime.total_seconds()),
                'cache_size': len(self.agent_cache)
            }
        except Exception as e:
            logger.error(f"Performance stats failed: {e}")
            return {}
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'alerts_created': 0,
            'threats_detected': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        logger.info("📊 Event service statistics reset")

# Singleton pattern for global access
_event_service_instance = None

def get_event_service() -> EventService:
    """Get global EventService instance"""
    global _event_service_instance
    if _event_service_instance is None:
        _event_service_instance = EventService()
    return _event_service_instance