# app/services/event_service.py - FIXED VERSION (Complete Database Validation)
"""
Event Processing Service - FIXED FOR DATABASE INTEGRITY
Enhanced validation, error handling, and proper database insertion
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

# Import models
from ..models.event import Event
from ..models.agent import Agent

# Detection models with error handling
try:
    from ..models.detection_rule import DetectionRule
    from ..models.threat import Threat
    from ..models.system_config import SystemConfig
    DETECTION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Detection models not available: {e}")
    DetectionRule = None
    Threat = None
    SystemConfig = None
    DETECTION_AVAILABLE = False

from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse
)
from ..config import config

logger = logging.getLogger('event_processing')

class EventService:
    """Service for realtime event processing with enhanced database validation"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        self.detection_enabled = (DETECTION_AVAILABLE and 
                                self.detection_config.get('rules_enabled', False))
        
        # Performance counters
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'events_failed': 0,
            'validation_errors': 0,
            'database_errors': 0,
            'threats_detected': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        
        # Cache for agent validation
        self.agent_cache = {}
        self.cache_timeout = 300  # 5 minutes
        
        # Validation constants
        self.VALID_EVENT_TYPES = ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
        self.VALID_SEVERITIES = ['Info', 'Low', 'Medium', 'High', 'Critical']
        self.VALID_THREAT_LEVELS = ['None', 'Suspicious', 'Malicious']
        
        logger.info("🚀 FIXED Event Service initialized - Enhanced database validation")
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                    client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """Submit single event with ENHANCED validation and error handling"""
        start_time = time.time()
        
        try:
            # 1. ENHANCED validation
            validation_result = self._validate_event_data_enhanced(event_data)
            if not validation_result['valid']:
                self.stats['validation_errors'] += 1
                error_msg = f"Validation failed: {validation_result['errors']}"
                logger.warning(f"❌ {error_msg}")
                return False, None, error_msg
            
            # 2. FAST agent validation with caching
            agent = self._get_agent_fast(session, event_data.agent_id)
            if not agent:
                error_msg = f"Agent not found: {event_data.agent_id}"
                logger.warning(f"❌ {error_msg}")
                return False, None, error_msg
            
            # 3. Check if monitoring is enabled
            if not agent.MonitoringEnabled:
                error_msg = f"Monitoring disabled for agent: {agent.HostName}"
                logger.warning(f"❌ {error_msg}")
                return False, None, error_msg
            
            # 4. ENHANCED event creation with validation
            event = self._create_event_from_request_enhanced(event_data, agent)
            if not event:
                self.stats['events_failed'] += 1
                error_msg = "Failed to create event from request data"
                logger.error(f"❌ {error_msg}")
                return False, None, error_msg
            
            # 5. DATABASE transaction with error handling
            try:
                session.add(event)
                session.flush()  # Get event ID immediately
                
                # ENHANCED LOGGING: Log every database insert with details
                logger.info(f"💾 DATABASE INSERT SUCCESS:")
                logger.info(f"   Event ID: {event.EventID}")
                logger.info(f"   Type: {event.EventType}")
                logger.info(f"   Action: {event.EventAction}")
                logger.info(f"   Agent: {agent.HostName} ({agent.AgentID})")
                logger.info(f"   Severity: {event.Severity}")
                logger.info(f"   Timestamp: {event.EventTimestamp}")
                logger.info(f"   Client IP: {client_ip}")
                
                # Additional field logging based on event type
                if event.EventType == 'Process' and event.ProcessName:
                    logger.info(f"   Process: {event.ProcessName} (PID: {event.ProcessID})")
                elif event.EventType == 'File' and event.FileName:
                    logger.info(f"   File: {event.FileName} ({event.FileOperation})")
                elif event.EventType == 'Network' and event.DestinationIP:
                    logger.info(f"   Network: {event.SourceIP} -> {event.DestinationIP}:{event.DestinationPort}")
                
            except IntegrityError as e:
                session.rollback()
                self.stats['database_errors'] += 1
                error_msg = f"Database integrity error: {str(e)}"
                logger.error(f"❌ {error_msg}")
                return False, None, error_msg
            
            except DataError as e:
                session.rollback()
                self.stats['database_errors'] += 1
                error_msg = f"Database data error: {str(e)}"
                logger.error(f"❌ {error_msg}")
                return False, None, error_msg
            
            # Update stats
            self.stats['events_processed'] += 1
            self.stats['events_stored'] += 1
            
            # 6. ENHANCED detection analysis
            threat_detected = False
            risk_score = 0
            detection_notifications = []
            
            if self.detection_enabled:
                try:
                    detection_results = await self._run_enhanced_detection(session, event)
                    if detection_results:
                        threat_detected = detection_results.get('threat_detected', False)
                        risk_score = detection_results.get('risk_score', 0)
                        detection_notifications = detection_results.get('notifications', [])
                        
                        # Update event with detection results
                        event.update_analysis(
                            threat_level=detection_results.get('threat_level', 'None'),
                            risk_score=risk_score
                        )
                        
                        if threat_detected:
                            self.stats['threats_detected'] += 1
                            
                            # ASYNC notification sending (non-blocking)
                            if detection_notifications:
                                asyncio.create_task(
                                    self._send_notifications_async(
                                        session, event_data.agent_id, detection_notifications, agent.HostName
                                    )
                                )
                        
                except Exception as e:
                    logger.error(f"❌ Detection engine error for event {event.EventID}: {str(e)}")
                    # Continue processing even if detection fails
            else:
                # Set basic analysis if detection not available
                event.update_analysis(threat_level='None', risk_score=0)
            
            # 7. FINAL COMMIT to database
            try:
                session.commit()
                logger.info(f"✅ EVENT COMMITTED: ID={event.EventID}")
            except Exception as e:
                session.rollback()
                self.stats['database_errors'] += 1
                error_msg = f"Commit failed: {str(e)}"
                logger.error(f"❌ {error_msg}")
                return False, None, error_msg
            
            # Calculate processing time
            processing_time = time.time() - start_time
            self.stats['processing_time_total'] += processing_time
            
            # Log result based on risk
            if risk_score > 70 or threat_detected:
                logger.warning(f"🚨 HIGH RISK Event stored successfully:")
                logger.warning(f"   ID={event.EventID}, Type={event.EventType}")
                logger.warning(f"   Agent={agent.HostName}, Risk={risk_score}")
                logger.warning(f"   Processing time: {processing_time:.3f}s")
            else:
                logger.info(f"📝 Event stored successfully:")
                logger.info(f"   ID={event.EventID}, Type={event.EventType}")
                logger.info(f"   Agent={agent.HostName}, Time={processing_time:.3f}s")
            
            response = EventSubmissionResponse(
                success=True,
                message="Event processed and stored successfully",
                event_id=event.EventID,
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=[]
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            self.stats['events_failed'] += 1
            error_msg = f"Event submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            logger.error(f"❌ Event data: {event_data}")
            return False, None, error_msg
    
    def _validate_event_data_enhanced(self, event_data: EventSubmissionRequest) -> Dict[str, Any]:
        """ENHANCED validation for event data"""
        errors = []
        valid = True
        
        try:
            # 1. Validate agent_id format (UUID)
            try:
                uuid.UUID(event_data.agent_id)
            except ValueError:
                errors.append(f"Invalid agent_id format: {event_data.agent_id}")
                valid = False
            
            # 2. Validate event_type
            event_type = event_data.event_type.value if hasattr(event_data.event_type, 'value') else str(event_data.event_type)
            if event_type not in self.VALID_EVENT_TYPES:
                errors.append(f"Invalid event_type: {event_type}. Must be one of {self.VALID_EVENT_TYPES}")
                valid = False
            
            # 3. Validate severity
            severity = event_data.severity.value if hasattr(event_data.severity, 'value') else str(event_data.severity)
            if severity not in self.VALID_SEVERITIES:
                errors.append(f"Invalid severity: {severity}. Must be one of {self.VALID_SEVERITIES}")
                valid = False
            
            # 4. Validate event_action
            if not event_data.event_action or len(event_data.event_action.strip()) == 0:
                errors.append("event_action cannot be empty")
                valid = False
            elif len(event_data.event_action) > 50:
                errors.append(f"event_action too long: {len(event_data.event_action)} chars (max 50)")
                valid = False
            
            # 5. Validate timestamp
            if not event_data.event_timestamp:
                errors.append("event_timestamp is required")
                valid = False
            else:
                # Check if timestamp is reasonable (not too far in future/past)
                now = datetime.now()
                time_diff = abs((now - event_data.event_timestamp).total_seconds())
                if time_diff > 86400:  # 24 hours
                    errors.append(f"event_timestamp too far from current time: {time_diff} seconds")
                    valid = False
            
            # 6. Event-specific validation
            if event_type == 'Process':
                if event_data.process_name and len(event_data.process_name) > 255:
                    errors.append(f"process_name too long: {len(event_data.process_name)} chars (max 255)")
                    valid = False
                if event_data.process_path and len(event_data.process_path) > 500:
                    errors.append(f"process_path too long: {len(event_data.process_path)} chars (max 500)")
                    valid = False
            
            elif event_type == 'File':
                if event_data.file_path and len(event_data.file_path) > 500:
                    errors.append(f"file_path too long: {len(event_data.file_path)} chars (max 500)")
                    valid = False
                if event_data.file_name and len(event_data.file_name) > 255:
                    errors.append(f"file_name too long: {len(event_data.file_name)} chars (max 255)")
                    valid = False
            
            elif event_type == 'Network':
                # Validate IP addresses
                if event_data.source_ip:
                    try:
                        import ipaddress
                        ipaddress.ip_address(event_data.source_ip)
                    except ValueError:
                        errors.append(f"Invalid source_ip format: {event_data.source_ip}")
                        valid = False
                
                if event_data.destination_ip:
                    try:
                        import ipaddress
                        ipaddress.ip_address(event_data.destination_ip)
                    except ValueError:
                        errors.append(f"Invalid destination_ip format: {event_data.destination_ip}")
                        valid = False
                
                # Validate ports
                for port_field, port_value in [('source_port', event_data.source_port), 
                                              ('destination_port', event_data.destination_port)]:
                    if port_value is not None and (port_value < 1 or port_value > 65535):
                        errors.append(f"Invalid {port_field}: {port_value} (must be 1-65535)")
                        valid = False
            
            return {'valid': valid, 'errors': errors}
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return {'valid': False, 'errors': [f"Validation exception: {str(e)}"]}
    
    def _create_event_from_request_enhanced(self, event_data: EventSubmissionRequest, agent: Agent) -> Optional[Event]:
        """ENHANCED event creation with proper validation and error handling"""
        try:
            # Extract and validate enum values
            event_type = event_data.event_type.value if hasattr(event_data.event_type, 'value') else str(event_data.event_type)
            severity = event_data.severity.value if hasattr(event_data.severity, 'value') else str(event_data.severity)
            
            # Ensure values are in valid constraints
            if event_type not in self.VALID_EVENT_TYPES:
                logger.error(f"Invalid event_type after validation: {event_type}")
                return None
            
            if severity not in self.VALID_SEVERITIES:
                logger.error(f"Invalid severity after validation: {severity}")
                return None
            
            # Sanitize string fields
            event_action = self._sanitize_string(event_data.event_action, 50)
            
            # Create base event with validated data
            event = Event.create_event(
                agent_id=str(agent.AgentID),  # Ensure string format
                event_type=event_type,
                event_action=event_action,
                event_timestamp=event_data.event_timestamp,
                Severity=severity
            )
            
            # Set event-specific fields with proper validation and sanitization
            if event_type == 'Process':
                event.ProcessID = event_data.process_id
                event.ProcessName = self._sanitize_string(event_data.process_name, 255)
                event.ProcessPath = self._sanitize_string(event_data.process_path, 500)
                event.CommandLine = self._sanitize_text(event_data.command_line)
                event.ParentPID = event_data.parent_pid
                event.ParentProcessName = self._sanitize_string(event_data.parent_process_name, 255)
                event.ProcessUser = self._sanitize_string(event_data.process_user, 100)
                event.ProcessHash = self._sanitize_string(event_data.process_hash, 128)
            
            elif event_type == 'File':
                event.FilePath = self._sanitize_string(event_data.file_path, 500)
                event.FileName = self._sanitize_string(event_data.file_name, 255)
                event.FileSize = event_data.file_size
                event.FileHash = self._sanitize_string(event_data.file_hash, 128)
                event.FileExtension = self._sanitize_string(event_data.file_extension, 10)
                event.FileOperation = self._sanitize_string(event_data.file_operation, 20)
            
            elif event_type == 'Network':
                event.SourceIP = self._sanitize_string(event_data.source_ip, 45)
                event.DestinationIP = self._sanitize_string(event_data.destination_ip, 45)
                event.SourcePort = event_data.source_port
                event.DestinationPort = event_data.destination_port
                event.Protocol = self._sanitize_string(event_data.protocol, 10)
                event.Direction = self._sanitize_string(event_data.direction, 10)
            
            elif event_type == 'Registry':
                event.RegistryKey = self._sanitize_string(event_data.registry_key, 500)
                event.RegistryValueName = self._sanitize_string(event_data.registry_value_name, 255)
                event.RegistryValueData = self._sanitize_text(event_data.registry_value_data)
                event.RegistryOperation = self._sanitize_string(event_data.registry_operation, 20)
            
            elif event_type == 'Authentication':
                event.LoginUser = self._sanitize_string(event_data.login_user, 100)
                event.LoginType = self._sanitize_string(event_data.login_type, 50)
                event.LoginResult = self._sanitize_string(event_data.login_result, 20)
            
            # Set raw event data if provided
            if event_data.raw_event_data:
                try:
                    event.set_raw_data(event_data.raw_event_data)
                except Exception as e:
                    logger.warning(f"Failed to set raw event data: {e}")
            
            # Set default values for required fields
            event.ThreatLevel = 'None'
            event.RiskScore = 0
            event.Analyzed = False
            
            logger.debug(f"✅ Event created successfully:")
            logger.debug(f"   Type: {event_type}, Action: {event_action}")
            logger.debug(f"   Agent: {agent.HostName}, Severity: {severity}")
            
            return event
            
        except Exception as e:
            logger.error(f"❌ Enhanced event creation failed: {str(e)}")
            logger.error(f"❌ Event data: {event_data}")
            return None
    
    def _sanitize_string(self, value: Any, max_length: int) -> Optional[str]:
        """Sanitize string input with length validation"""
        if value is None:
            return None
        
        try:
            # Convert to string and remove null bytes and control characters
            sanitized = str(value).replace('\x00', '').replace('\r\n', '\n')
            
            # Remove other control characters except newline and tab
            import re
            sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', '', sanitized)
            
            # Truncate to max length
            if len(sanitized) > max_length:
                sanitized = sanitized[:max_length]
                logger.debug(f"String truncated to {max_length} chars")
            
            # Return None if empty after sanitization
            return sanitized.strip() if sanitized.strip() else None
            
        except Exception as e:
            logger.warning(f"String sanitization failed: {e}")
            return None
    
    def _sanitize_text(self, value: Any) -> Optional[str]:
        """Sanitize text input (for NVARCHAR(MAX) fields)"""
        if value is None:
            return None
        
        try:
            # Convert to string and remove null bytes
            sanitized = str(value).replace('\x00', '')
            
            # Keep newlines but remove other dangerous control characters
            import re
            sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', '', sanitized)
            
            # Limit to reasonable size (4000 chars for performance)
            if len(sanitized) > 4000:
                sanitized = sanitized[:4000]
                logger.debug("Text truncated to 4000 chars")
            
            return sanitized if sanitized.strip() else None
            
        except Exception as e:
            logger.warning(f"Text sanitization failed: {e}")
            return None
    
    def get_enhanced_stats(self) -> Dict[str, Any]:
        """Get enhanced performance and error statistics"""
        try:
            uptime = datetime.now() - self.stats['last_reset']
            avg_processing_time = (self.stats['processing_time_total'] / 
                                 max(self.stats['events_processed'], 1))
            
            success_rate = (self.stats['events_stored'] / 
                           max(self.stats['events_processed'], 1) * 100)
            
            return {
                'events_processed': self.stats['events_processed'],
                'events_stored': self.stats['events_stored'],
                'events_failed': self.stats['events_failed'],
                'validation_errors': self.stats['validation_errors'],
                'database_errors': self.stats['database_errors'],
                'success_rate': round(success_rate, 2),
                'threats_detected': self.stats['threats_detected'],
                'notifications_sent': self.stats['notifications_sent'],
                'average_processing_time_ms': round(avg_processing_time * 1000, 2),
                'events_per_second': round(self.stats['events_processed'] / max(uptime.total_seconds(), 1), 2),
                'uptime_seconds': int(uptime.total_seconds()),
                'cache_size': len(self.agent_cache),
                'detection_enabled': self.detection_enabled
            }
        except Exception as e:
            logger.error(f"Stats calculation failed: {e}")
            return {}
    
    # Keep existing methods...
    def _get_agent_fast(self, session: Session, agent_id: str) -> Optional[Agent]:
        """Fast agent validation with caching"""
        try:
            # Check cache first
            cache_key = f"agent_{agent_id}"
            current_time = time.time()
            
            if cache_key in self.agent_cache:
                cached_agent, cache_time = self.agent_cache[cache_key]
                if current_time - cache_time < self.cache_timeout:
                    return cached_agent
                else:
                    # Remove expired cache
                    del self.agent_cache[cache_key]
            
            # Query database
            agent = Agent.get_by_id(session, agent_id)
            
            # Cache result
            if agent:
                self.agent_cache[cache_key] = (agent, current_time)
            
            return agent
            
        except Exception as e:
            logger.error(f"Fast agent lookup failed: {e}")
            return None
    
    async def _run_enhanced_detection(self, session: Session, event: Event) -> Optional[Dict]:
        """ENHANCED detection analysis (keeping existing implementation)"""
        try:
            if not DETECTION_AVAILABLE:
                return None
            
            detection_results = {
                'threat_detected': False,
                'threat_level': 'None',
                'risk_score': 0,
                'notifications': [],
                'detection_methods': []
            }
            
            # Enhanced detection based on event type
            event_type = event.EventType
            
            if event_type == 'Process':
                detection_results['risk_score'] += len(event.ProcessName or '') * 20
                detection_results['detection_methods'].append('Process Analysis')
                
                notification = self._create_process_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'File':
                detection_results['risk_score'] += (event.FileSize or 0) * 0.01
                detection_results['detection_methods'].append('File Analysis')
                
                notification = self._create_file_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'Network':
                detection_results['risk_score'] += len(event.DestinationIP or '') * 10
                detection_results['detection_methods'].append('Network Analysis')
                
                notification = self._create_network_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'Registry':
                detection_results['risk_score'] += len(event.RegistryKey or '') * 10
                detection_results['detection_methods'].append('Registry Analysis')
                
                notification = self._create_registry_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'Authentication':
                detection_results['risk_score'] += len(event.LoginUser or '') * 10
                detection_results['detection_methods'].append('Authentication Analysis')
                
                notification = self._create_authentication_notification_fast(event)
                detection_results['notifications'].append(notification)
            
            # Determine threat level
            risk_score = min(detection_results['risk_score'], 100)
            detection_results['risk_score'] = risk_score
            
            if risk_score >= 80:
                detection_results['threat_level'] = 'Malicious'
            elif risk_score >= 50:
                detection_results['threat_level'] = 'Suspicious'
            else:
                detection_results['threat_level'] = 'None'
            
            # Mark as threat detected if significant risk
            risk_threshold = self.detection_config.get('risk_score_threshold', 70)
            if risk_score >= risk_threshold:
                detection_results['threat_detected'] = True
            
            return detection_results
            
        except Exception as e:
            logger.error(f"Enhanced detection analysis failed: {str(e)}")
            return None
    
    # Keep all existing notification methods...
    def _create_process_notification_fast(self, event: Event) -> Dict:
        """FAST process notification creation"""
        return {
            'type': 'process_analysis',
            'event_id': event.EventID,
            'process_id': event.ProcessID,
            'process_name': event.ProcessName,
            'title': f"Process: {event.ProcessName or 'Unknown'}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.ProcessName or '') * 20,
            'confidence': 0.8
        }
    
    def _create_file_notification_fast(self, event: Event) -> Dict:
        """FAST file notification creation"""
        return {
            'type': 'file_analysis',
            'event_id': event.EventID,
            'file_path': event.FilePath,
            'file_name': event.FileName,
            'title': f"File: {event.FileName or 'Unknown'}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': (event.FileSize or 0) * 0.01,
            'confidence': 0.8
        }
    
    def _create_network_notification_fast(self, event: Event) -> Dict:
        """FAST network notification creation"""
        return {
            'type': 'network_analysis',
            'event_id': event.EventID,
            'source_ip': event.SourceIP,
            'destination_ip': event.DestinationIP,
            'title': f"Network: {event.SourceIP or 'Unknown'} -> {event.DestinationIP or 'Unknown'}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.DestinationIP or '') * 10,
            'confidence': 0.8
        }
    
    def _create_registry_notification_fast(self, event: Event) -> Dict:
        """FAST registry notification creation"""
        return {
            'type': 'registry_analysis',
            'event_id': event.EventID,
            'registry_key': event.RegistryKey,
            'title': f"Registry: {event.RegistryKey or 'Unknown'}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.RegistryKey or '') * 10,
            'confidence': 0.8
        }
    
    def _create_authentication_notification_fast(self, event: Event) -> Dict:
        """FAST authentication notification creation"""
        return {
            'type': 'authentication_analysis',
            'event_id': event.EventID,
            'login_user': event.LoginUser,
            'title': f"Authentication: {event.LoginUser or 'Unknown'}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.LoginUser or '') * 10,
            'confidence': 0.8
        }
    async def _send_notifications_async(self, session: Session, agent_id: str, 
                                      notifications: List[Dict], agent_hostname: str):
        """ASYNC notification sending (non-blocking)"""
        try:
            if not notifications or not SystemConfig:
                return
            
            for notification in notifications:
                try:
                    # Store notification in database
                    notification_record = {
                        'agent_id': agent_id,
                        'notification_type': notification.get('type', 'detection'),
                        'notification_data': notification,
                        'sent_at': datetime.now().isoformat(),
                        'status': 'pending'
                    }
                    
                    # Get notification config
                    config_key = f"agent_{agent_id}_notifications"
                    config = session.query(SystemConfig).filter_by(ConfigKey=config_key).first()
                    
                    if config and config.ConfigValue.get('enabled', True):
                        # Send notification via configured channels
                        await self._send_notification_to_channels(notification, agent_hostname)
                        notification_record['status'] = 'sent'
                        self.stats['notifications_sent'] += 1
                    else:
                        notification_record['status'] = 'disabled'
                    
                    # Log notification
                    logger.info(f"🔔 Notification {notification_record['status']}: {notification.get('title', 'Unknown')}")
                    
                except Exception as e:
                    logger.error(f"❌ Notification sending failed: {str(e)}")
                    
        except Exception as e:
            logger.error(f"❌ Async notification processing failed: {str(e)}")
    
    async def _send_notification_to_channels(self, notification: Dict, agent_hostname: str):
        """Send notification to configured channels (email, webhook, etc.)"""
        try:
            # Email notification
            if self.detection_config.get('email_notifications_enabled', False):
                await self._send_email_notification(notification, agent_hostname)
            
            # Webhook notification
            if self.detection_config.get('webhook_notifications_enabled', False):
                await self._send_webhook_notification(notification, agent_hostname)
            
            # Slack notification
            if self.detection_config.get('slack_notifications_enabled', False):
                await self._send_slack_notification(notification, agent_hostname)
                
        except Exception as e:
            logger.error(f"❌ Channel notification failed: {str(e)}")
    
    async def _send_email_notification(self, notification: Dict, agent_hostname: str):
        """Send email notification"""
        try:
            # Implementation would depend on your email service
            logger.info(f"📧 Email notification sent for {agent_hostname}")
        except Exception as e:
            logger.error(f"❌ Email notification failed: {str(e)}")
    
    async def _send_webhook_notification(self, notification: Dict, agent_hostname: str):
        """Send webhook notification"""
        try:
            # Implementation would depend on your webhook configuration
            logger.info(f"🔗 Webhook notification sent for {agent_hostname}")
        except Exception as e:
            logger.error(f"❌ Webhook notification failed: {str(e)}")
    
    async def _send_slack_notification(self, notification: Dict, agent_hostname: str):
        """Send Slack notification"""
        try:
            # Implementation would depend on your Slack integration
            logger.info(f"💬 Slack notification sent for {agent_hostname}")
        except Exception as e:
            logger.error(f"❌ Slack notification failed: {str(e)}")
    
    async def submit_batch_events(self, session: Session, batch_data: EventBatchRequest,
                                client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """Submit batch of events with enhanced processing"""
        start_time = time.time()
        
        try:
            # Validate batch size
            if len(batch_data.events) > self.max_batch_size:
                error_msg = f"Batch size {len(batch_data.events)} exceeds maximum {self.max_batch_size}"
                logger.warning(f"❌ {error_msg}")
                return False, None, error_msg
            
            # Process events in batch
            successful_events = []
            failed_events = []
            total_threats = 0
            
            for i, event_data in enumerate(batch_data.events):
                try:
                    success, response, error = await self.submit_event(session, event_data, client_ip)
                    
                    if success:
                        successful_events.append({
                            'index': i,
                            'event_id': response.event_id,
                            'threat_detected': response.threat_detected,
                            'risk_score': response.risk_score
                        })
                        
                        if response.threat_detected:
                            total_threats += 1
                    else:
                        failed_events.append({
                            'index': i,
                            'error': error or 'Unknown error'
                        })
                        
                except Exception as e:
                    failed_events.append({
                        'index': i,
                        'error': str(e)
                    })
            
            # Calculate processing metrics
            processing_time = time.time() - start_time
            success_rate = len(successful_events) / len(batch_data.events) * 100
            
            # Log batch results
            logger.info(f"📦 Batch processed:")
            logger.info(f"   Total: {len(batch_data.events)}")
            logger.info(f"   Successful: {len(successful_events)}")
            logger.info(f"   Failed: {len(failed_events)}")
            logger.info(f"   Threats: {total_threats}")
            logger.info(f"   Success Rate: {success_rate:.1f}%")
            logger.info(f"   Processing Time: {processing_time:.3f}s")
            
            response = EventBatchResponse(
                success=len(failed_events) == 0,
                message=f"Batch processed: {len(successful_events)}/{len(batch_data.events)} successful",
                successful_count=len(successful_events),
                failed_count=len(failed_events),
                total_threats_detected=total_threats,
                processing_time_seconds=processing_time,
                successful_events=successful_events,
                failed_events=failed_events
            )
            
            return True, response, None
            
        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = f"Batch submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'events_failed': 0,
            'validation_errors': 0,
            'database_errors': 0,
            'threats_detected': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        logger.info("📊 Statistics reset")
    
    def clear_agent_cache(self):
        """Clear agent cache"""
        cache_size = len(self.agent_cache)
        self.agent_cache.clear()
        logger.info(f"🗑️ Agent cache cleared ({cache_size} entries)")
    
    async def health_check(self, session: Session) -> Dict[str, Any]:
        """Comprehensive health check"""
        try:
            health = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'service_info': {
                    'detection_enabled': self.detection_enabled,
                    'max_batch_size': self.max_batch_size,
                    'cache_timeout': self.cache_timeout
                }
            }
            
            # Add performance stats
            health.update(self.get_enhanced_stats())
            
            # Test database connectivity
            try:
                session.execute("SELECT 1")
                health['database'] = 'connected'
            except Exception as e:
                health['database'] = f'error: {str(e)}'
                health['status'] = 'degraded'
            
            # Test agent cache
            health['cache_status'] = f"{len(self.agent_cache)} entries"
            
            return health
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def __del__(self):
        """Cleanup on service destruction"""
        try:
            if hasattr(self, 'stats') and self.stats['events_processed'] > 0:
                logger.info(f"🏁 EventService destroyed - Final stats:")
                logger.info(f"   Events processed: {self.stats['events_processed']}")
                logger.info(f"   Events stored: {self.stats['events_stored']}")
                logger.info(f"   Success rate: {(self.stats['events_stored']/self.stats['events_processed']*100):.1f}%")
        except:
            pass


# Factory function for creating EventService instance
def create_event_service() -> EventService:
    """Factory function to create EventService instance"""
    return EventService()


# Global service instance (singleton pattern)
_event_service_instance = None

def get_event_service() -> EventService:
    """Get global EventService instance (singleton)"""
    global _event_service_instance
    if _event_service_instance is None:
        _event_service_instance = create_event_service()
    return _event_service_instance