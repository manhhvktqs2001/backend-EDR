# app/services/event_service.py - FIXED VERSION (Import Error)
"""
Event Processing Service - OPTIMIZED FOR REALTIME
Tối ưu hóa cho việc nhận và xử lý events realtime từ agents
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any  # FIXED: Explicit Dict import
from sqlalchemy.orm import Session
from sqlalchemy import func
import time
import json

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
    """Service for realtime event processing and database storage"""
    
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
            'threats_detected': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        
        # Cache for agent validation
        self.agent_cache = {}
        self.cache_timeout = 300  # 5 minutes
        
        logger.info("🚀 REALTIME Event Service initialized - Zero delay processing enabled")
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                    client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """Submit single event for REALTIME processing and database storage"""
        start_time = time.time()
        
        try:
            # 1. FAST agent validation with caching
            agent = self._get_agent_fast(session, event_data.agent_id)
            if not agent:
                error_msg = f"Agent not found: {event_data.agent_id}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # 2. Check if monitoring is enabled
            if not agent.MonitoringEnabled:
                error_msg = f"Monitoring disabled for agent: {agent.HostName}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # 3. FAST event creation with enhanced event type processing
            event = self._create_event_from_request_fast(event_data)
            if not event:
                error_msg = "Failed to create event from request data"
                logger.error(error_msg)
                return False, None, error_msg
            
            # 4. IMMEDIATE database storage
            session.add(event)
            session.flush()  # Get event ID immediately
            
            # ENHANCED LOGGING: Log every database insert
            logger.info(f"💾 DATABASE INSERT: Event ID={event.EventID}, Type={event.EventType}, "
                       f"Agent={agent.HostName}, Action={event.EventAction}, "
                       f"Severity={event.Severity}, Timestamp={event.EventTimestamp}")
            
            # Update stats
            self.stats['events_processed'] += 1
            self.stats['events_stored'] += 1
            
            # 5. ENHANCED detection analysis for different event types
            threat_detected = False
            risk_score = 0
            detection_notifications = []
            
            if self.detection_enabled:
                try:
                    # Enhanced detection based on event type
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
                    logger.error(f"Detection engine error for event {event.EventID}: {str(e)}")
                    # Continue processing even if detection fails
            else:
                # Set basic analysis if detection not available
                event.update_analysis(threat_level='None', risk_score=0)
            
            # 6. COMMIT to database - REALTIME STORAGE
            session.commit()
            
            # Calculate processing time
            processing_time = time.time() - start_time
            self.stats['processing_time_total'] += processing_time
            
            # Log high-priority events
            if risk_score > 70 or threat_detected:
                logger.warning(f"🚨 HIGH RISK Event stored: ID={event.EventID}, Type={event.EventType}, "
                             f"Agent={agent.HostName}, Risk={risk_score}, Time={processing_time:.3f}s")
            else:
                logger.debug(f"📝 Event stored: ID={event.EventID}, Type={event.EventType}, "
                           f"Agent={agent.HostName}, Time={processing_time:.3f}s")
            
            response = EventSubmissionResponse(
                success=True,
                message="Event processed and stored successfully",
                event_id=event.EventID,
                threat_detected=threat_detected,
                risk_score=risk_score,
                alerts_generated=[]  # No auto alerts in this mode
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Event submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    async def submit_event_batch(self, session: Session, batch_data: EventBatchRequest,
                          client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """Submit batch of events for REALTIME processing - OPTIMIZED"""
        start_time = time.time()
        
        try:
            # Validate batch size
            if len(batch_data.events) > self.max_batch_size:
                error_msg = f"Batch size {len(batch_data.events)} exceeds maximum {self.max_batch_size}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # FAST agent validation with caching
            agent = self._get_agent_fast(session, batch_data.agent_id)
            if not agent:
                error_msg = f"Agent not found: {batch_data.agent_id}"
                logger.warning(error_msg)
                return False, None, error_msg
            
            logger.info(f"🔄 Processing REALTIME batch: {len(batch_data.events)} events from {agent.HostName}")
            
            # Process events in batch - OPTIMIZED
            processed_events = 0
            failed_events = 0
            detection_notifications = []
            errors = []
            total_risk_score = 0
            threats_detected = 0
            
            # Batch processing for performance
            events_to_add = []
            
            for i, event_data in enumerate(batch_data.events):
                try:
                    # Ensure agent_id matches batch agent_id
                    event_data.agent_id = batch_data.agent_id
                    
                    # FAST event creation
                    event = self._create_event_from_request_fast(event_data)
                    if not event:
                        failed_events += 1
                        errors.append(f"Failed to create event {i+1}")
                        continue
                    
                    # Add to batch list
                    events_to_add.append(event)
                    processed_events += 1
                    
                except Exception as e:
                    failed_events += 1
                    errors.append(f"Event {i+1} processing error: {str(e)}")
                    logger.error(f"Failed to process event {i+1} in batch: {str(e)}")
            
            # BULK INSERT for performance
            if events_to_add:
                session.add_all(events_to_add)
                session.flush()  # Get all event IDs
                
                # ENHANCED LOGGING: Log batch database insert
                event_ids = [event.EventID for event in events_to_add]
                event_types = [event.EventType for event in events_to_add]
                logger.info(f"💾 BATCH DATABASE INSERT: {len(events_to_add)} events, IDs={event_ids[:5]}{'...' if len(event_ids) > 5 else ''}, "
                           f"Types={list(set(event_types))}, Agent={agent.HostName}")
                
                # Update stats
                self.stats['events_processed'] += len(events_to_add)
                self.stats['events_stored'] += len(events_to_add)
                
                # FAST detection for batch (if enabled)
                if self.detection_enabled:
                    try:
                        batch_notifications = await self._run_batch_detection(session, events_to_add)
                        if batch_notifications:
                            detection_notifications.extend(batch_notifications)
                            threats_detected = len([n for n in batch_notifications if n.get('severity') in ['High', 'Critical']])
                            total_risk_score = sum(n.get('risk_score', 0) for n in batch_notifications)
                            
                            if threats_detected > 0:
                                self.stats['threats_detected'] += threats_detected
                    except Exception as e:
                        logger.error(f"Batch detection failed: {str(e)}")
                
                # COMMIT all events to database
                session.commit()
            
            processing_time = time.time() - start_time
            self.stats['processing_time_total'] += processing_time
            
            # Enhanced logging
            avg_risk = total_risk_score / processed_events if processed_events > 0 else 0
            logger.info(f"✅ BATCH STORED: {processed_events} events, {failed_events} failed, "
                       f"from {agent.HostName} in {processing_time:.3f}s")
            
            if threats_detected > 0:
                logger.warning(f"🚨 BATCH THREATS: {threats_detected}/{processed_events} events, "
                             f"Avg risk: {avg_risk:.1f}, Notifications: {len(detection_notifications)}")
            
            # ASYNC notification sending for batch
            if detection_notifications:
                asyncio.create_task(
                    self._send_notifications_async(
                        session, batch_data.agent_id, detection_notifications, agent.HostName
                    )
                )

            response = EventBatchResponse(
                success=True,
                message=f"Batch processed and stored: {processed_events} events in {processing_time:.3f}s",
                total_events=len(batch_data.events),
                processed_events=processed_events,
                failed_events=failed_events,
                alerts_generated=[],  # No auto alerts
                errors=errors
            )
            
            return True, response, None
            
        except Exception as e:
            session.rollback()
            processing_time = time.time() - start_time
            error_msg = f"Event batch submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
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
    
    def _create_event_from_request_fast(self, event_data: EventSubmissionRequest) -> Optional[Event]:
        """FAST event creation optimized for performance - FIXED for complete data insertion"""
        try:
            # Create base event with proper data types
            event = Event.create_event(
                agent_id=event_data.agent_id,
                event_type=event_data.event_type.value,
                event_action=event_data.event_action,
                event_timestamp=event_data.event_timestamp,
                Severity=event_data.severity.value
            )
            
            # Set event-specific fields based on type - COMPLETE MAPPING
            event_type = event_data.event_type.value
            
            if event_type == 'Process':
                # Process Events - Complete mapping
                event.ProcessID = event_data.process_id
                event.ProcessName = event_data.process_name
                event.ProcessPath = event_data.process_path
                event.CommandLine = event_data.command_line
                event.ParentPID = event_data.parent_pid
                event.ParentProcessName = event_data.parent_process_name
                event.ProcessUser = event_data.process_user
                event.ProcessHash = event_data.process_hash
            
            elif event_type == 'File':
                # File Events - Complete mapping
                event.FilePath = event_data.file_path
                event.FileName = event_data.file_name
                event.FileSize = event_data.file_size
                event.FileHash = event_data.file_hash
                event.FileExtension = event_data.file_extension
                event.FileOperation = event_data.file_operation
            
            elif event_type == 'Network':
                # Network Events - Complete mapping
                event.SourceIP = event_data.source_ip
                event.DestinationIP = event_data.destination_ip
                event.SourcePort = event_data.source_port
                event.DestinationPort = event_data.destination_port
                event.Protocol = event_data.protocol
                event.Direction = event_data.direction
            
            elif event_type == 'Registry':
                # Registry Events - Complete mapping
                event.RegistryKey = event_data.registry_key
                event.RegistryValueName = event_data.registry_value_name
                event.RegistryValueData = event_data.registry_value_data
                event.RegistryOperation = event_data.registry_operation
            
            elif event_type == 'Authentication':
                # Authentication Events - Complete mapping
                event.LoginUser = event_data.login_user
                event.LoginType = event_data.login_type
                event.LoginResult = event_data.login_result
            
            elif event_type == 'System':
                # System Events - Store in raw data
                pass
            
            # Set raw event data if provided - ENHANCED
            if event_data.raw_event_data:
                event.set_raw_data(event_data.raw_event_data)
            
            # Set description if provided
            if hasattr(event_data, 'description') and event_data.description:
                # Store description in raw data if not a standard field
                if not hasattr(event, 'Description'):
                    raw_data = event.get_raw_data() or {}
                    raw_data['description'] = event_data.description
                    event.set_raw_data(raw_data)
            
            # Log successful event creation for debugging
            logger.debug(f"✅ Event created: Type={event_type}, Action={event_data.event_action}, "
                        f"Agent={event_data.agent_id}, Severity={event_data.severity.value}")
            
            return event
            
        except Exception as e:
            logger.error(f"❌ Fast event creation failed: {str(e)}")
            logger.error(f"Event data: {event_data}")
            return None
    
    async def _run_enhanced_detection(self, session: Session, event: Event) -> Optional[Dict]:
        """ENHANCED detection analysis for different event types"""
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
                detection_results['risk_score'] += len(event.ProcessName) * 20 if event.ProcessName else 0
                detection_results['detection_methods'].append('Process Analysis')
                
                # Create process notifications
                notification = self._create_process_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'File':
                detection_results['risk_score'] += event.FileSize * 0.01 if event.FileSize else 0
                detection_results['detection_methods'].append('File Analysis')
                
                # Create file notifications
                notification = self._create_file_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'Network':
                detection_results['risk_score'] += len(event.DestinationIP) * 10 if event.DestinationIP else 0
                detection_results['detection_methods'].append('Network Analysis')
                
                # Create network notifications
                notification = self._create_network_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'Registry':
                detection_results['risk_score'] += len(event.RegistryKey) * 10 if event.RegistryKey else 0
                detection_results['detection_methods'].append('Registry Analysis')
                
                # Create registry notifications
                notification = self._create_registry_notification_fast(event)
                detection_results['notifications'].append(notification)
                
            elif event_type == 'Authentication':
                detection_results['risk_score'] += len(event.LoginUser) * 10 if event.LoginUser else 0
                detection_results['detection_methods'].append('Authentication Analysis')
                
                # Create authentication notifications
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
    
    def _create_process_notification_fast(self, event: Event) -> Dict:
        """FAST process notification creation"""
        return {
            'type': 'process_analysis',
            'event_id': event.EventID,
            'process_id': event.ProcessID,
            'process_name': event.ProcessName,
            'title': f"Process: {event.ProcessName}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': event.ProcessName and len(event.ProcessName) * 20 or 0,
            'confidence': 0.8
        }
    
    def _create_file_notification_fast(self, event: Event) -> Dict:
        """FAST file notification creation"""
        return {
            'type': 'file_analysis',
            'event_id': event.EventID,
            'file_path': event.FilePath,
            'file_name': event.FileName,
            'title': f"File: {event.FileName}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': event.FileSize * 0.01 if event.FileSize else 0,
            'confidence': 0.8
        }
    
    def _create_network_notification_fast(self, event: Event) -> Dict:
        """FAST network notification creation"""
        return {
            'type': 'network_analysis',
            'event_id': event.EventID,
            'source_ip': event.SourceIP,
            'destination_ip': event.DestinationIP,
            'title': f"Network: {event.SourceIP} -> {event.DestinationIP}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.DestinationIP) * 10 if event.DestinationIP else 0,
            'confidence': 0.8
        }
    
    def _create_registry_notification_fast(self, event: Event) -> Dict:
        """FAST registry notification creation"""
        return {
            'type': 'registry_analysis',
            'event_id': event.EventID,
            'registry_key': event.RegistryKey,
            'title': f"Registry: {event.RegistryKey}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.RegistryKey) * 10 if event.RegistryKey else 0,
            'confidence': 0.8
        }
    
    def _create_authentication_notification_fast(self, event: Event) -> Dict:
        """FAST authentication notification creation"""
        return {
            'type': 'authentication_analysis',
            'event_id': event.EventID,
            'login_user': event.LoginUser,
            'title': f"Authentication: {event.LoginUser}",
            'severity': 'Medium',
            'detected_at': datetime.now().isoformat(),
            'risk_score': len(event.LoginUser) * 10 if event.LoginUser else 0,
            'confidence': 0.8
        }
    
    async def _run_batch_detection(self, session: Session, events: List[Event]) -> List[Dict]:
        """FAST batch detection for multiple events"""
        try:
            notifications = []
            
            for event in events:
                detection_result = await self._run_enhanced_detection(session, event)
                if detection_result and detection_result.get('notifications'):
                    notifications.extend(detection_result['notifications'])
            
            return notifications
            
        except Exception as e:
            logger.error(f"Batch detection failed: {e}")
            return []
    
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
                    
                    config_key = f"agent_notification_{agent_id}_{notification.get('type', 'det')}_{int(time.time())}"
                    config_value = json.dumps(notification_record)
                    
                    new_config = SystemConfig(
                        ConfigKey=config_key,
                        ConfigValue=config_value,
                        ConfigType='JSON',
                        Category='AgentNotifications',
                        Description=f'Detection notification for agent {agent_hostname}'
                    )
                    session.add(new_config)
                    
                except Exception as e:
                    logger.error(f"Failed to store notification: {e}")
                    continue
            
            session.commit()
            self.stats['notifications_sent'] += len(notifications)
            
            logger.info(f"📤 Sent {len(notifications)} notifications to {agent_hostname}")
            
        except Exception as e:
            logger.error(f"ASYNC notification sending failed: {str(e)}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get realtime performance statistics"""
        try:
            uptime = datetime.now() - self.stats['last_reset']
            avg_processing_time = (self.stats['processing_time_total'] / 
                                 max(self.stats['events_processed'], 1))
            
            return {
                'events_processed': self.stats['events_processed'],
                'events_stored': self.stats['events_stored'],
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
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'threats_detected': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        logger.info("📊 Performance stats reset")
    
    def clear_cache(self):
        """Clear agent cache"""
        self.agent_cache.clear()
        logger.info("🧹 Agent cache cleared")
    
    # Keep existing helper methods for backward compatibility
    def get_events_by_agent(self, session: Session, agent_id: str, 
                           hours: int = 24, limit: int = 100) -> List[Event]:
        """Get events for specific agent"""
        try:
            return Event.get_by_agent(session, agent_id, limit)
        except Exception as e:
            logger.error(f"Failed to get events for agent {agent_id}: {str(e)}")
            return []
    
    def get_recent_events(self, session: Session, hours: int = 24, 
                         limit: int = 1000) -> List[Event]:
        """Get recent events across all agents"""
        try:
            return Event.get_recent_events(session, hours, limit)
        except Exception as e:
            logger.error(f"Failed to get recent events: {str(e)}")
            return []
    
    def get_suspicious_events(self, session: Session, hours: int = 24) -> List[Event]:
        """Get events marked as suspicious or malicious"""
        try:
            return Event.get_suspicious_events(session, hours)
        except Exception as e:
            logger.error(f"Failed to get suspicious events: {str(e)}")
            return []
    
    def get_event_statistics(self, session: Session, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive event statistics"""
        try:
            stats = Event.get_events_summary(session, hours)
            
            # Add performance stats
            perf_stats = self.get_performance_stats()
            stats.update({
                'performance': perf_stats,
                'realtime_mode': True,
                'zero_delay_processing': True
            })
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get event statistics: {str(e)}")
            return {}
    
    def cleanup_old_events(self, session: Session, retention_days: int = 365) -> Tuple[int, str]:
        """Clean up old events based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # Count events to be deleted
            old_events_count = session.query(Event).filter(
                Event.EventTimestamp < cutoff_date
            ).count()
            
            if old_events_count == 0:
                return 0, "No old events to clean up"
            
            # Delete old events in batches for performance
            batch_size = 1000
            total_deleted = 0
            
            while True:
                deleted_count = session.query(Event).filter(
                    Event.EventTimestamp < cutoff_date
                ).limit(batch_size).delete()
                
                if deleted_count == 0:
                    break
                
                total_deleted += deleted_count
                session.commit()
                
                logger.info(f"Deleted batch: {deleted_count} events ({total_deleted}/{old_events_count})")
            
            message = f"Cleaned up {total_deleted:,} events older than {retention_days} days"
            logger.info(message)
            
            return total_deleted, message
            
        except Exception as e:
            session.rollback()
            error_msg = f"Event cleanup failed: {str(e)}"
            logger.error(error_msg)
            return 0, error_msg
    
    def get_events_timeline(self, session: Session, hours: int = 24) -> List[Dict[str, Any]]:
        """Get events timeline for dashboard"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Get hourly event counts
            timeline = session.query(
                func.datepart('hour', Event.EventTimestamp).label('hour'),
                Event.EventType,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(
                func.datepart('hour', Event.EventTimestamp),
                Event.EventType
            ).order_by('hour').all()
            
            return [
                {
                    'hour': row.hour,
                    'event_type': row.EventType,
                    'count': row.count
                }
                for row in timeline
            ]
            
        except Exception as e:
            logger.error(f"Timeline generation failed: {e}")
            return []

# Global service instance
event_service = EventService()