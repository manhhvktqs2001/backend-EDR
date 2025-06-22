"""
Events API Endpoints - OPTIMIZED FOR REALTIME
Event submission, processing, and management with zero-delay processing
"""

import logging
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime
import time
import asyncio

from ...database import get_db
from ...models.event import Event
from ...models.agent import Agent
from ...schemas.event import (
    EventSubmissionRequest, EventSubmissionResponse,
    EventBatchRequest, EventBatchResponse,
    EventResponse, EventListResponse, EventSummary,
    EventSearchRequest, EventStats
)
from ...services.event_service import event_service

logger = logging.getLogger('event_processing')
router = APIRouter()

# Performance tracking
request_stats = {
    'total_requests': 0,
    'total_events': 0,
    'total_processing_time': 0.0,
    'last_reset': datetime.now()
}

# Authentication helper
def verify_agent_token(x_agent_token: Optional[str] = Header(None)):
    """Verify agent authentication token"""
    if not x_agent_token or x_agent_token != "edr_agent_auth_2024":
        raise HTTPException(status_code=401, detail="Invalid or missing agent token")
    return True

@router.post("/submit", response_model=EventSubmissionResponse)
async def submit_event(
    request: Request,
    event_data: EventSubmissionRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Submit single event for REALTIME processing and immediate database storage"""
    start_time = time.time()
    client_ip = request.client.host
    
    try:
        # ENHANCED LOGGING: Log event received
        logger.info(f"📥 EVENT RECEIVED: Type={event_data.event_type}, Action={event_data.event_action}, "
                   f"Agent={event_data.agent_id}, Client={client_ip}")
        
        # Update request stats
        request_stats['total_requests'] += 1
        request_stats['total_events'] += 1
        
        # REALTIME processing
        success, response, error = await event_service.submit_event(session, event_data, client_ip)
        
        if not success:
            logger.warning(f"❌ Event submission failed from {client_ip}: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        request_stats['total_processing_time'] += processing_time
        
        # Log high-priority events immediately
        if response.threat_detected:
            logger.warning(f"🚨 THREAT EVENT STORED: ID={response.event_id}, "
                         f"Risk={response.risk_score}, Client={client_ip}, Time={processing_time:.3f}s")
        else:
            logger.debug(f"📝 Event stored: ID={response.event_id}, Type={event_data.event_type}, "
                        f"Client={client_ip}, Time={processing_time:.3f}s")
        
        # Add performance metrics to response
        response.message += f" (Processed in {processing_time:.3f}s)"
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        processing_time = time.time() - start_time
        error_msg = f"Event submission error after {processing_time:.3f}s: {str(e)}"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail="Event submission failed")

@router.post("/batch", response_model=EventBatchResponse)
async def submit_event_batch(
    request: Request,
    batch_data: EventBatchRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Submit batch of events for REALTIME processing - OPTIMIZED FOR HIGH THROUGHPUT"""
    start_time = time.time()
    client_ip = request.client.host
    batch_size = len(batch_data.events)
    
    try:
        # ENHANCED LOGGING: Log batch received
        event_types = [event.event_type for event in batch_data.events]
        logger.info(f"📥 BATCH RECEIVED: {batch_size} events, Types={list(set(event_types))}, "
                   f"Agent={batch_data.agent_id}, Client={client_ip}")
        
        # Update request stats
        request_stats['total_requests'] += 1
        request_stats['total_events'] += batch_size
        
        logger.info(f"🔄 REALTIME BATCH RECEIVED: {batch_size} events from {client_ip}")
        
        # REALTIME batch processing
        success, response, error = await event_service.submit_event_batch(session, batch_data, client_ip)
        
        if not success:
            logger.warning(f"❌ Batch submission failed from {client_ip}: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        # Calculate processing metrics
        processing_time = time.time() - start_time
        request_stats['total_processing_time'] += processing_time
        events_per_second = batch_size / processing_time if processing_time > 0 else 0
        
        # Enhanced logging with performance metrics
        logger.info(f"✅ BATCH PROCESSED: {response.processed_events}/{batch_size} events "
                   f"from {client_ip} in {processing_time:.3f}s ({events_per_second:.1f} events/sec)")
        
        if response.failed_events > 0:
            logger.warning(f"⚠️ BATCH PARTIAL: {response.failed_events} failed events")
        
        # Add performance metrics to response
        response.message += f" (Rate: {events_per_second:.1f} events/sec)"
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        processing_time = time.time() - start_time
        error_msg = f"Batch submission error after {processing_time:.3f}s: {str(e)}"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail="Event batch submission failed")

@router.get("/list", response_model=EventListResponse)
async def list_events(
    request: Request,
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level"),
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, le=1000, description="Maximum events to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    session: Session = Depends(get_db)
):
    """List events with filtering and pagination - OPTIMIZED QUERIES"""
    try:
        # Build optimized query
        query = session.query(Event)
        
        # Apply filters
        filters_applied = {}
        
        if agent_id:
            query = query.filter(Event.AgentID == agent_id)
            filters_applied['agent_id'] = agent_id
        
        if event_type:
            query = query.filter(Event.EventType == event_type)
            filters_applied['event_type'] = event_type
        
        if severity:
            query = query.filter(Event.Severity == severity)
            filters_applied['severity'] = severity
        
        if threat_level:
            query = query.filter(Event.ThreatLevel == threat_level)
            filters_applied['threat_level'] = threat_level
        
        # Time range filter - OPTIMIZED
        if hours:
            from datetime import datetime, timedelta
            cutoff_time = datetime.now() - timedelta(hours=hours)
            query = query.filter(Event.EventTimestamp >= cutoff_time)
            filters_applied['hours'] = hours
        
        # Get total count efficiently
        total_count = query.count()
        
        # Apply pagination and get results with optimized ordering
        events = query.order_by(Event.EventTimestamp.desc()).offset(offset).limit(limit).all()
        
        # Convert to summary format efficiently
        event_summaries = [event.to_summary() for event in events]
        
        # Calculate page info
        page = (offset // limit) + 1 if limit > 0 else 1
        
        logger.debug(f"📋 Listed {len(event_summaries)} events (total: {total_count})")
        
        return EventListResponse(
            events=event_summaries,
            total_count=total_count,
            page=page,
            page_size=limit,
            filters_applied=filters_applied
        )
        
    except Exception as e:
        logger.error(f"List events failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list events")

@router.get("/{event_id}", response_model=EventResponse)
async def get_event_details(
    request: Request,
    event_id: int,
    include_raw_data: bool = Query(False, description="Include raw event data"),
    session: Session = Depends(get_db)
):
    """Get specific event details - OPTIMIZED SINGLE QUERY"""
    try:
        event = session.query(Event).filter(Event.EventID == event_id).first()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        
        event_data = event.to_dict(include_raw_data=include_raw_data)
        return EventResponse(**event_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get event details failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get event details")

@router.get("/agent/{agent_id}/recent")
async def get_agent_recent_events(
    request: Request,
    agent_id: str,
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, le=1000, description="Maximum events to return"),
    session: Session = Depends(get_db)
):
    """Get recent events for specific agent - OPTIMIZED"""
    try:
        # Verify agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get events efficiently
        events = event_service.get_events_by_agent(session, agent_id, hours, limit)
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        return {
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "events": event_summaries,
            "total_count": len(event_summaries),
            "time_range_hours": hours,
            "realtime_mode": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get agent events failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get agent events")

@router.get("/stats/summary", response_model=EventStats)
async def get_event_statistics(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get event statistics summary - INCLUDES REALTIME PERFORMANCE METRICS"""
    try:
        # Get standard statistics
        stats = event_service.get_event_statistics(session, hours)
        
        if not stats:
            raise HTTPException(status_code=500, detail="Failed to generate statistics")
        
        # Add realtime performance metrics
        perf_stats = event_service.get_performance_stats()
        api_stats = get_api_performance_stats()
        
        stats.update({
            'realtime_performance': perf_stats,
            'api_performance': api_stats,
            'database_mode': 'realtime_optimized'
        })
        
        # Get top agents by event count with optimized query
        from sqlalchemy import func
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        top_agents_query = session.query(
            Event.AgentID,
            Agent.HostName,
            func.count(Event.EventID).label('event_count')
        ).join(
            Agent, Event.AgentID == Agent.AgentID
        ).filter(
            Event.EventTimestamp >= cutoff_time
        ).group_by(
            Event.AgentID, Agent.HostName
        ).order_by(
            func.count(Event.EventID).desc()
        ).limit(10).all()
        
        top_agents = [
            {
                "agent_id": str(row.AgentID),
                "hostname": row.HostName,
                "event_count": row.event_count
            }
            for row in top_agents_query
        ]
        
        stats['top_agents'] = top_agents
        
        return EventStats(**stats)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get event statistics failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get event statistics")

@router.get("/timeline/hourly")
async def get_events_timeline(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Get events timeline for dashboard - OPTIMIZED AGGREGATION"""
    try:
        timeline = event_service.get_events_timeline(session, hours)
        
        return {
            "timeline": timeline,
            "time_range_hours": hours,
            "total_points": len(timeline),
            "realtime_mode": True,
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Get events timeline failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get events timeline")

@router.get("/suspicious/recent")
async def get_suspicious_events(
    request: Request,
    hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, le=1000, description="Maximum events to return"),
    session: Session = Depends(get_db)
):
    """Get recent suspicious or malicious events - HIGH PRIORITY EVENTS"""
    try:
        events = event_service.get_suspicious_events(session, hours)
        
        # Apply limit
        if limit and len(events) > limit:
            events = events[:limit]
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        # Calculate threat statistics
        threat_stats = {
            "suspicious": len([e for e in events if e.ThreatLevel == 'Suspicious']),
            "malicious": len([e for e in events if e.ThreatLevel == 'Malicious']),
            "high_risk": len([e for e in events if e.RiskScore >= 80]),
            "critical_risk": len([e for e in events if e.RiskScore >= 90])
        }
        
        logger.info(f"🚨 Suspicious events query: {len(event_summaries)} events, "
                   f"Threats: {threat_stats}")
        
        return {
            "suspicious_events": event_summaries,
            "total_count": len(event_summaries),
            "time_range_hours": hours,
            "threat_statistics": threat_stats,
            "realtime_analysis": True
        }
        
    except Exception as e:
        logger.error(f"Get suspicious events failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get suspicious events")

@router.post("/search")
async def search_events(
    request: Request,
    search_request: EventSearchRequest,
    session: Session = Depends(get_db)
):
    """Advanced event search with multiple criteria - OPTIMIZED SEARCH"""
    try:
        query = session.query(Event)
        
        # Apply search filters efficiently
        if search_request.agent_id:
            query = query.filter(Event.AgentID == search_request.agent_id)
        
        if search_request.event_type:
            query = query.filter(Event.EventType == search_request.event_type.value)
        
        if search_request.severity:
            query = query.filter(Event.Severity == search_request.severity.value)
        
        if search_request.threat_level:
            query = query.filter(Event.ThreatLevel == search_request.threat_level.value)
        
        if search_request.start_time:
            query = query.filter(Event.EventTimestamp >= search_request.start_time)
        
        if search_request.end_time:
            query = query.filter(Event.EventTimestamp <= search_request.end_time)
        
        if search_request.search_text:
            # Optimized text search
            search_term = f"%{search_request.search_text}%"
            query = query.filter(
                Event.ProcessName.ilike(search_term) |
                Event.ProcessPath.ilike(search_term) |
                Event.CommandLine.ilike(search_term) |
                Event.FilePath.ilike(search_term) |
                Event.FileName.ilike(search_term)
            )
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination with optimized ordering
        events = query.order_by(Event.EventTimestamp.desc()).offset(search_request.offset).limit(search_request.limit).all()
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        logger.info(f"🔍 Search completed: {len(event_summaries)}/{total_count} events")
        
        return {
            "events": event_summaries,
            "total_count": total_count,
            "page": (search_request.offset // search_request.limit) + 1,
            "page_size": search_request.limit,
            "search_criteria": search_request.dict(exclude_none=True),
            "search_optimized": True
        }
        
    except Exception as e:
        logger.error(f"Event search failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Event search failed")

@router.get("/performance/stats")
async def get_performance_statistics(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get REALTIME performance statistics"""
    try:
        # Get service performance stats
        service_stats = event_service.get_performance_stats()
        
        # Get API performance stats
        api_stats = get_api_performance_stats()
        
        # Get database performance
        db_stats = get_database_performance_stats(session)
        
        return {
            "service_performance": service_stats,
            "api_performance": api_stats,
            "database_performance": db_stats,
            "realtime_mode": True,
            "zero_delay_processing": True,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Performance stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get performance statistics")

@router.post("/performance/reset")
async def reset_performance_stats(
    request: Request,
    session: Session = Depends(get_db)
):
    """Reset performance statistics"""
    try:
        # Reset service stats
        event_service.reset_stats()
        
        # Reset API stats
        reset_api_stats()
        
        logger.info("📊 Performance statistics reset")
        
        return {
            "success": True,
            "message": "Performance statistics reset",
            "reset_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Stats reset failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to reset statistics")

@router.get("/health/realtime")
async def get_realtime_health_status(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get REALTIME event processing health status"""
    try:
        from datetime import datetime, timedelta
        
        # Get recent event statistics
        recent_stats = event_service.get_event_statistics(session, 1)  # Last hour
        
        # Get unanalyzed events count
        unanalyzed_count = session.query(Event).filter(Event.Analyzed == False).count()
        
        # Get service performance
        perf_stats = event_service.get_performance_stats()
        
        # Calculate health metrics
        events_per_minute = perf_stats.get('events_per_second', 0) * 60
        avg_processing_time = perf_stats.get('average_processing_time_ms', 0)
        
        # Determine health status
        health_status = "healthy"
        issues = []
        
        if unanalyzed_count > 5000:
            health_status = "critical"
            issues.append(f"Very high processing backlog: {unanalyzed_count:,}")
        elif unanalyzed_count > 1000:
            health_status = "warning" if health_status == "healthy" else health_status
            issues.append(f"Processing backlog: {unanalyzed_count:,}")
        
        if avg_processing_time > 1000:  # 1 second
            health_status = "warning" if health_status == "healthy" else health_status
            issues.append(f"Slow processing: {avg_processing_time:.1f}ms average")
        
        if events_per_minute > 10000:  # Very high load
            issues.append(f"High event load: {events_per_minute:.0f} events/minute")
        
        return {
            "status": health_status,
            "realtime_processing": {
                "events_per_minute": events_per_minute,
                "average_processing_time_ms": avg_processing_time,
                "unanalyzed_backlog": unanalyzed_count,
                "cache_size": perf_stats.get('cache_size', 0)
            },
            "performance_metrics": perf_stats,
            "issues": issues,
            "recommendations": [
                "Monitor processing backlog" if unanalyzed_count > 500 else None,
                "Check database performance" if avg_processing_time > 500 else None,
                "Consider scaling" if events_per_minute > 5000 else None
            ],
            "last_checked": datetime.now().isoformat(),
            "mode": "realtime_optimized"
        }
        
    except Exception as e:
        logger.error(f"Realtime health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Realtime health check failed")

# Helper functions
def get_api_performance_stats() -> Dict:
    """Get API performance statistics"""
    try:
        uptime = datetime.now() - request_stats['last_reset']
        avg_processing_time = (request_stats['total_processing_time'] / 
                             max(request_stats['total_requests'], 1))
        
        return {
            'total_requests': request_stats['total_requests'],
            'total_events_processed': request_stats['total_events'],
            'average_request_time_ms': round(avg_processing_time * 1000, 2),
            'requests_per_second': round(request_stats['total_requests'] / max(uptime.total_seconds(), 1), 2),
            'events_per_second': round(request_stats['total_events'] / max(uptime.total_seconds(), 1), 2),
            'uptime_seconds': int(uptime.total_seconds())
        }
    except Exception:
        return {}

def reset_api_stats():
    """Reset API performance statistics"""
    global request_stats
    request_stats = {
        'total_requests': 0,
        'total_events': 0,
        'total_processing_time': 0.0,
        'last_reset': datetime.now()
    }

def get_database_performance_stats(session: Session) -> Dict:
    """Get database performance statistics"""
    try:
        from sqlalchemy import text
        
        # Simple database performance check
        start_time = time.time()
        result = session.execute(text("SELECT COUNT(*) FROM Events")).scalar()
        query_time = (time.time() - start_time) * 1000
        
        return {
            'total_events_in_db': result,
            'query_response_time_ms': round(query_time, 2),
            'connection_status': 'healthy'
        }
    except Exception as e:
        return {
            'total_events_in_db': 0,
            'query_response_time_ms': 0,
            'connection_status': 'error',
            'error': str(e)
        }