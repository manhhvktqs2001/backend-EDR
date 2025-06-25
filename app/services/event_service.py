# app/services/event_service.py - FIXED VERSION
"""
Event Service - Handles event submission and processing
Fixed for proper error handling and database constraints
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, DataError, SQLAlchemyError
import time
import json
import uuid

from ..models.event import Event
from ..models.agent import Agent
from ..schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse
)
from ..config import config
from ..services.detection_engine import get_detection_service
from ..services.alert_service import get_alert_service

logger = logging.getLogger(__name__)

class EventService:
    """FIXED Event processing service with proper rule detection"""
    
    def __init__(self):
        self.agent_config = config['agent']
        self.detection_config = config['detection']
        self.max_batch_size = self.agent_config['event_batch_size']
        
        # Performance counters
        self.stats = {
            'events_processed': 0,
            'events_stored': 0,
            'rules_matched': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        
        # Agent cache for fast lookups
        self.agent_cache = {}
        self.cache_timeout = 300
        
        logger.info("📥 FIXED Event Service - Ready for rule detection")
    
    async def submit_event(self, session: Session, event_data: EventSubmissionRequest,
                          client_ip: str) -> Tuple[bool, EventSubmissionResponse, Optional[str]]:
        """FIXED: Submit single event with proper error handling"""
        start_time = time.time()
        
        try:
            # Fast validation
            if not self._validate_event_fast(event_data):
                return False, None, "Invalid event data"
            
            # Get agent with proper session handling
            agent = self._get_agent_fast(session, event_data.agent_id)
            if not agent:
                return False, None, f"Agent {event_data.agent_id} not found"
            
            # Create event with proper ThreatLevel handling
            event = self._create_event_fast(event_data, agent)
            if not event:
                return False, None, "Event creation failed"
            
            # FIXED: Ensure ThreatLevel is never NULL
            if not event.ThreatLevel:
                event.ThreatLevel = 'None'
            
            # Add to session and commit
            session.add(event)
            session.flush()  # Get the event ID
            
            # Run detection engine with proper error handling
            try:
                detection_service = get_detection_service()
                detection_result = await detection_service.analyze_event_and_create_alerts(
                    session=session,
                    event=event
                )
                
                # FIXED: Update event with detection results, ensuring ThreatLevel is never NULL
                if detection_result:
                    event.Analyzed = True
                    event.AnalyzedAt = datetime.now()
                    event.RiskScore = detection_result.get('risk_score', 0)
                    
                    # FIXED: Ensure ThreatLevel is never NULL
                    threat_level = detection_result.get('threat_level', 'None')
                    if threat_level and threat_level != 'NULL':
                        event.ThreatLevel = threat_level
                    else:
                        event.ThreatLevel = 'None'
                    
                    # Generate alerts if threats detected
                    alerts_generated = []
                    if detection_result.get('threat_detected', False):
                        alert_service = get_alert_service()
                        alert = await alert_service.create_alert_from_detection(
                            session=session,
                            event_id=event.EventID,
                            detection_result=detection_result,
                            agent_id=event_data.agent_id
                        )
                        if alert:
                            alerts_generated.append(alert)
                
                session.commit()
                
            except Exception as detection_error:
                # FIXED: Handle detection errors gracefully
                logger.warning(f"Detection engine error for event {event.EventID}: {detection_error}")
                
                # Still commit the event even if detection fails
                event.Analyzed = False
                event.ThreatLevel = 'None'  # Ensure it's never NULL
                event.RiskScore = 0
                session.commit()
                
                # Return success but with no alerts
                processing_time = time.time() - start_time
                response = EventSubmissionResponse(
                    success=True,
                    event_id=event.EventID,
                    message=f"Event stored successfully (detection failed)",
                    threat_detected=False,
                    risk_score=0,
                    alerts_generated=[]
                )
                
                logger.info(f"✅ EVENT STORED: ID={event.EventID}, Type={event.EventType}, Process={event.ProcessName}")
                return True, response, None
            
            # Success case
            processing_time = time.time() - start_time
            risk_score = event.RiskScore or 0
            threat_detected = event.ThreatLevel in ['Suspicious', 'Malicious'] or risk_score >= 70
            
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
            error_msg = f"Event submission failed after {processing_time:.3f}s: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return False, None, error_msg
    
    async def submit_event_batch(self, session: Session, batch_data: EventBatchRequest,
                                client_ip: str) -> Tuple[bool, EventBatchResponse, Optional[str]]:
        """FIXED: Batch event submission with proper detection"""
        start_time = time.time()
        batch_size = len(batch_data.events)
        
        if batch_size > self.max_batch_size:
            return False, None, f"Batch size {batch_size} exceeds maximum {self.max_batch_size}"
        
        logger.info(f"🚀 PROCESSING BATCH: {batch_size} events from {client_ip}")
        
        processed_events = 0
        failed_events = 0
        alerts_generated = []
        errors = []
        
        try:
            for i, event_data in enumerate(batch_data.events):
                try:
                    success, response, error = await self.submit_event(session, event_data, client_ip)
                    
                    if success:
                        processed_events += 1
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
            logger.info(f"   Alerts Generated: {len(alerts_generated)}")
            logger.info(f"   Time: {processing_time:.3f}s")
            
            batch_response = EventBatchResponse(
                success=failed_events == 0,
                message=f"Batch processed: {processed_events}/{batch_size} successful",
                total_events=batch_size,
                processed_events=processed_events,
                failed_events=failed_events,
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
        cache_key = f"agent_{agent_id}"
        current_time = time.time()
        
        if cache_key in self.agent_cache:
            cached_agent, cache_time = self.agent_cache[cache_key]
            if current_time - cache_time < self.cache_timeout:
                return cached_agent
        
        agent = Agent.get_by_id(session, agent_id)
        if agent:
            self.agent_cache[cache_key] = (agent, current_time)
        
        return agent
    
    def _create_event_fast(self, event_data: EventSubmissionRequest, agent: Agent) -> Optional[Event]:
        """Fast event creation"""
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
    
    # Backward compatibility methods
    def get_events_by_agent(self, session: Session, agent_id: str, hours: int = 24, limit: int = 100) -> List[Event]:
        """Get events for specific agent"""
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
        """Get suspicious events"""
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
            
            total_events = session.query(Event).filter(Event.EventTimestamp >= cutoff_time).count()
            analyzed_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.Analyzed == True
            ).count()
            suspicious_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
            ).count()
            
            type_breakdown = session.query(
                Event.EventType,
                func.count(Event.EventID).label('count')
            ).filter(
                Event.EventTimestamp >= cutoff_time
            ).group_by(Event.EventType).all()
            
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
                'rules_matched': self.stats['rules_matched'],
                'alerts_created': self.stats['alerts_created'],
                'notifications_sent': self.stats['notifications_sent'],
                'average_processing_time_ms': round(avg_processing_time * 1000, 2),
                'events_per_second': round(self.stats['events_processed'] / max(uptime.total_seconds(), 1), 2),
                'rule_match_rate': round((self.stats['rules_matched'] / max(self.stats['events_processed'], 1)) * 100, 2),
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
            'rules_matched': 0,
            'alerts_created': 0,
            'notifications_sent': 0,
            'processing_time_total': 0.0,
            'last_reset': datetime.now()
        }
        logger.info("📊 Statistics reset")
    
    def clear_caches(self):
        """Clear all caches"""
        self.agent_cache.clear()
        logger.info("🧹 Caches cleared")

def get_event_service() -> EventService:
    """Get the global event service instance"""
    return event_service

# Create global service instance
event_service = EventService()