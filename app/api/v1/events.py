"""
Events API Endpoints
Event submission, processing, and management
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query
from sqlalchemy.orm import Session
from datetime import datetime
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
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Submit single event for processing"""
    try:
        client_ip = request.client.host
        success, response, error = await event_service.submit_event(session, event_data, client_ip)
        
        if not success:
            logger.warning(f"Event submission failed: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        logger.debug(f"Event submitted: Type={event_data.event_type}, Agent={event_data.agent_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Event submission error: {str(e)}")
        raise HTTPException(status_code=500, detail="Event submission failed")

@router.post("/batch", response_model=EventBatchResponse)
async def submit_event_batch(
    request: Request,
    batch_data: EventBatchRequest,
    session: Session = Depends(get_db),
    _: bool = Depends(verify_agent_token)
):
    """Submit batch of events for processing"""
    try:
        client_ip = request.client.host
        success, response, error = await event_service.submit_event_batch(session, batch_data, client_ip)
        
        if not success:
            logger.warning(f"Event batch submission failed: {error}")
            raise HTTPException(status_code=400, detail=error)
        
        logger.info(f"Event batch submitted: {len(batch_data.events)} events from agent {batch_data.agent_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Event batch submission error: {str(e)}")
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
    """List events with filtering and pagination"""
    try:
        # Build query
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
        
        # Time range filter
        if hours:
            from datetime import datetime, timedelta
            cutoff_time = datetime.now() - timedelta(hours=hours)
            query = query.filter(Event.EventTimestamp >= cutoff_time)
            filters_applied['hours'] = hours
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination and get results
        events = query.order_by(Event.EventTimestamp.desc()).offset(offset).limit(limit).all()
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        # Calculate page info
        page = (offset // limit) + 1 if limit > 0 else 1
        
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
    """Get specific event details"""
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
    """Get recent events for specific agent"""
    try:
        # Verify agent exists
        agent = Agent.get_by_id(session, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get events
        events = event_service.get_events_by_agent(session, agent_id, hours, limit)
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        return {
            "agent_id": agent_id,
            "hostname": agent.HostName,
            "events": event_summaries,
            "total_count": len(event_summaries),
            "time_range_hours": hours
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
    """Get event statistics summary"""
    try:
        stats = event_service.get_event_statistics(session, hours)
        
        if not stats:
            raise HTTPException(status_code=500, detail="Failed to generate statistics")
        
        # Get top agents by event count
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
    """Get events timeline for dashboard"""
    try:
        timeline = event_service.get_events_timeline(session, hours)
        
        return {
            "timeline": timeline,
            "time_range_hours": hours,
            "total_points": len(timeline)
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
    """Get recent suspicious or malicious events"""
    try:
        events = event_service.get_suspicious_events(session, hours)
        
        # Apply limit
        if limit and len(events) > limit:
            events = events[:limit]
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        return {
            "suspicious_events": event_summaries,
            "total_count": len(event_summaries),
            "time_range_hours": hours,
            "threat_levels": {
                "suspicious": len([e for e in events if e.ThreatLevel == 'Suspicious']),
                "malicious": len([e for e in events if e.ThreatLevel == 'Malicious'])
            }
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
    """Advanced event search with multiple criteria"""
    try:
        query = session.query(Event)
        
        # Apply search filters
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
            # Search in multiple text fields
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
        
        # Apply pagination
        events = query.order_by(Event.EventTimestamp.desc()).offset(search_request.offset).limit(search_request.limit).all()
        
        # Convert to summary format
        event_summaries = [event.to_summary() for event in events]
        
        return {
            "events": event_summaries,
            "total_count": total_count,
            "page": (search_request.offset // search_request.limit) + 1,
            "page_size": search_request.limit,
            "search_criteria": search_request.dict(exclude_none=True)
        }
        
    except Exception as e:
        logger.error(f"Event search failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Event search failed")

@router.get("/patterns/analysis")
async def analyze_event_patterns(
    request: Request,
    agent_id: Optional[str] = Query(None, description="Analyze patterns for specific agent"),
    hours: int = Query(24, description="Time range in hours"),
    session: Session = Depends(get_db)
):
    """Analyze event patterns for anomaly detection"""
    try:
        patterns = event_service.analyze_event_patterns(session, agent_id, hours)
        
        return {
            "patterns": patterns,
            "agent_id": agent_id,
            "time_range_hours": hours,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Event pattern analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Pattern analysis failed")

@router.delete("/cleanup")
async def cleanup_old_events(
    request: Request,
    retention_days: int = Query(30, description="Delete events older than this many days"),
    session: Session = Depends(get_db)
):
    """Clean up old events based on retention policy"""
    try:
        deleted_count, message = event_service.cleanup_old_events(session, retention_days)
        
        return {
            "success": True,
            "message": message,
            "deleted_count": deleted_count,
            "retention_days": retention_days
        }
        
    except Exception as e:
        logger.error(f"Event cleanup failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Event cleanup failed")

@router.get("/health/status")
async def get_event_processing_health(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get event processing health status"""
    try:
        from datetime import datetime, timedelta
        
        # Get recent event statistics
        recent_stats = event_service.get_event_statistics(session, 1)  # Last hour
        
        # Get unanalyzed events count
        unanalyzed_count = session.query(Event).filter(Event.Analyzed == False).count()
        
        # Get processing health metrics
        health_status = {
            "status": "healthy",
            "event_processing": {
                "events_last_hour": recent_stats.get('total_events', 0),
                "unanalyzed_events": unanalyzed_count,
                "processing_lag": "normal" if unanalyzed_count < 1000 else "high"
            },
            "detection_engine": {
                "enabled": True,  # From config
                "threat_detections_last_hour": recent_stats.get('threat_breakdown', {}).get('Suspicious', 0) + recent_stats.get('threat_breakdown', {}).get('Malicious', 0)
            },
            "performance": {
                "avg_events_per_minute": recent_stats.get('total_events', 0) / 60 if recent_stats.get('total_events', 0) > 0 else 0,
                "backlog_size": unanalyzed_count
            },
            "last_checked": datetime.now().isoformat()
        }
        
        # Determine overall health
        if unanalyzed_count > 5000:
            health_status["status"] = "critical"
        elif unanalyzed_count > 1000:
            health_status["status"] = "warning"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Event health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Event health check failed")