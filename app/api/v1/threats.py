"""
Threats API Endpoints
Threat intelligence management and lookup
"""

import logging
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session

from ...database import get_db
from ...models.threat import Threat
from ...schemas.threat import (
    ThreatResponse, ThreatSummary, ThreatListResponse,
    ThreatLookupRequest, ThreatLookupResponse,
    ThreatStatsResponse, ThreatCreateRequest
)
from datetime import datetime
logger = logging.getLogger('threat_intelligence')
router = APIRouter()

@router.get("/list", response_model=ThreatListResponse)
async def list_threats(
    request: Request,
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    limit: int = Query(100, le=1000, description="Maximum threats to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    session: Session = Depends(get_db)
):
    """List threats with filtering and pagination"""
    try:
        # Build query
        query = session.query(Threat)
        
        # Apply filters
        filters_applied = {}
        
        if threat_type:
            query = query.filter(Threat.ThreatType == threat_type)
            filters_applied['threat_type'] = threat_type
        
        if category:
            query = query.filter(Threat.ThreatCategory == category)
            filters_applied['category'] = category
        
        if severity:
            query = query.filter(Threat.Severity == severity)
            filters_applied['severity'] = severity
        
        if is_active is not None:
            query = query.filter(Threat.IsActive == is_active)
            filters_applied['is_active'] = is_active
        
        if platform:
            query = query.filter(
                (Threat.Platform == platform) | (Threat.Platform == 'All')
            )
            filters_applied['platform'] = platform
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination and get results
        threats = query.order_by(Threat.UpdatedAt.desc()).offset(offset).limit(limit).all()
        
        # Convert to summary format
        threat_summaries = [ThreatSummary(**threat.to_summary()) for threat in threats]
        
        # Calculate page info
        page = (offset // limit) + 1 if limit > 0 else 1
        
        # Get summary statistics
        active_count = session.query(Threat).filter(Threat.IsActive == True).count()
        high_confidence_count = session.query(Threat).filter(
            Threat.IsActive == True,
            Threat.Confidence >= 0.8
        ).count()
        
        return ThreatListResponse(
            threats=threat_summaries,
            total_count=total_count,
            active_count=active_count,
            high_confidence_count=high_confidence_count,
            page=page,
            page_size=limit,
            filters_applied=filters_applied
        )
        
    except Exception as e:
        logger.error(f"List threats failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list threats")

@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat_details(
    request: Request,
    threat_id: int,
    session: Session = Depends(get_db)
):
    """Get specific threat details"""
    try:
        threat = session.query(Threat).filter(Threat.ThreatID == threat_id).first()
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # Get threat data
        threat_data = threat.to_dict()
        
        # Get related alerts count
        from ...models.alert import Alert
        related_alerts = session.query(Alert).filter(Alert.ThreatID == threat_id).count()
        threat_data['related_alerts_count'] = related_alerts
        
        # Get recent detections
        recent_alerts = session.query(Alert).filter(
            Alert.ThreatID == threat_id
        ).order_by(Alert.FirstDetected.desc()).limit(10).all()
        
        threat_data['recent_detections'] = [
            {
                "alert_id": alert.AlertID,
                "agent_id": str(alert.AgentID),
                "title": alert.Title,
                "severity": alert.Severity,
                "first_detected": alert.FirstDetected.isoformat() if alert.FirstDetected else None
            }
            for alert in recent_alerts
        ]
        
        return ThreatResponse(**threat_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get threat details failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get threat details")

@router.post("/lookup", response_model=ThreatLookupResponse)
async def lookup_threat(
    request: Request,
    lookup_request: ThreatLookupRequest,
    session: Session = Depends(get_db)
):
    """Lookup threat intelligence for indicators"""
    try:
        results = {
            "indicators_checked": len(lookup_request.indicators),
            "threats_found": [],
            "clean_indicators": [],
            "lookup_timestamp": datetime.now().isoformat()
        }
        
        for indicator in lookup_request.indicators:
            threat_found = False
            
            # Check hash indicators
            if lookup_request.indicator_type in ['hash', 'all']:
                threat = Threat.check_hash(session, indicator)
                if threat:
                    results["threats_found"].append({
                        "indicator": indicator,
                        "threat_id": threat.ThreatID,
                        "threat_name": threat.ThreatName,
                        "threat_type": threat.ThreatType,
                        "category": threat.ThreatCategory,
                        "severity": threat.Severity,
                        "confidence": float(threat.Confidence) if threat.Confidence else 0.5,
                        "description": threat.Description
                    })
                    threat_found = True
            
            # Check IP indicators
            if lookup_request.indicator_type in ['ip', 'all'] and not threat_found:
                threat = Threat.check_ip(session, indicator)
                if threat:
                    results["threats_found"].append({
                        "indicator": indicator,
                        "threat_id": threat.ThreatID,
                        "threat_name": threat.ThreatName,
                        "threat_type": threat.ThreatType,
                        "category": threat.ThreatCategory,
                        "severity": threat.Severity,
                        "confidence": float(threat.Confidence) if threat.Confidence else 0.5,
                        "description": threat.Description
                    })
                    threat_found = True
            
            # Check domain indicators
            if lookup_request.indicator_type in ['domain', 'all'] and not threat_found:
                threat = Threat.check_domain(session, indicator)
                if threat:
                    results["threats_found"].append({
                        "indicator": indicator,
                        "threat_id": threat.ThreatID,
                        "threat_name": threat.ThreatName,
                        "threat_type": threat.ThreatType,
                        "category": threat.ThreatCategory,
                        "severity": threat.Severity,
                        "confidence": float(threat.Confidence) if threat.Confidence else 0.5,
                        "description": threat.Description
                    })
                    threat_found = True
            
            # If no threat found, add to clean indicators
            if not threat_found:
                results["clean_indicators"].append(indicator)
        
        results["threats_count"] = len(results["threats_found"])
        results["clean_count"] = len(results["clean_indicators"])
        
        logger.info(f"Threat lookup completed: {results['threats_count']} threats found out of {results['indicators_checked']} indicators")
        
        return ThreatLookupResponse(**results)
        
    except Exception as e:
        logger.error(f"Threat lookup failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Threat lookup failed")

@router.post("/check-hash")
async def check_hash(
    request: Request,
    file_hash: str = Query(..., description="File hash to check"),
    session: Session = Depends(get_db)
):
    """Quick hash check against threat database"""
    try:
        threat = Threat.check_hash(session, file_hash)
        
        if threat:
            return {
                "hash": file_hash,
                "threat_found": True,
                "threat_id": threat.ThreatID,
                "threat_name": threat.ThreatName,
                "category": threat.ThreatCategory,
                "severity": threat.Severity,
                "confidence": float(threat.Confidence) if threat.Confidence else 0.5,
                "description": threat.Description,
                "mitre_tactic": threat.MitreTactic,
                "mitre_technique": threat.MitreTechnique
            }
        else:
            return {
                "hash": file_hash,
                "threat_found": False,
                "status": "clean"
            }
            
    except Exception as e:
        logger.error(f"Hash check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Hash check failed")

@router.post("/check-ip")
async def check_ip(
    request: Request,
    ip_address: str,
    session: Session = Depends(get_db)
):
    """Quick IP check against threat database"""
    try:
        threat = Threat.check_ip(session, ip_address)
        
        if threat:
            return {
                "ip": ip_address,
                "threat_found": True,
                "threat_id": threat.ThreatID,
                "threat_name": threat.ThreatName,
                "category": threat.ThreatCategory,
                "severity": threat.Severity,
                "confidence": float(threat.Confidence) if threat.Confidence else 0.5,
                "description": threat.Description,
                "mitre_tactic": threat.MitreTactic,
                "mitre_technique": threat.MitreTechnique
            }
        else:
            return {
                "ip": ip_address,
                "threat_found": False,
                "status": "clean"
            }
            
    except Exception as e:
        logger.error(f"IP check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="IP check failed")

@router.post("/check-domain")
async def check_domain(
    request: Request,
    domain: str,
    session: Session = Depends(get_db)
):
    """Quick domain check against threat database"""
    try:
        threat = Threat.check_domain(session, domain)
        
        if threat:
            return {
                "domain": domain,
                "threat_found": True,
                "threat_id": threat.ThreatID,
                "threat_name": threat.ThreatName,
                "category": threat.ThreatCategory,
                "severity": threat.Severity,
                "confidence": float(threat.Confidence) if threat.Confidence else 0.5,
                "description": threat.Description,
                "mitre_tactic": threat.MitreTactic,
                "mitre_technique": threat.MitreTechnique
            }
        else:
            return {
                "domain": domain,
                "threat_found": False,
                "status": "clean"
            }
            
    except Exception as e:
        logger.error(f"Domain check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Domain check failed")

@router.get("/stats/summary", response_model=ThreatStatsResponse)
async def get_threat_statistics(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get threat intelligence statistics"""
    try:
        stats = Threat.get_threats_summary(session)
        
        # Get additional statistics
        from sqlalchemy import func
        from datetime import datetime, timedelta
        
        # Recent additions
        last_30_days = datetime.now() - timedelta(days=30)
        recent_additions = session.query(Threat).filter(
            Threat.CreatedAt >= last_30_days
        ).count()
        
        # High confidence threats
        high_confidence = session.query(Threat).filter(
            Threat.IsActive == True,
            Threat.Confidence >= 0.8
        ).count()
        
        # Platform distribution
        platform_distribution = session.query(
            Threat.Platform,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True
        ).group_by(Threat.Platform).all()
        
        # Source distribution
        source_distribution = session.query(
            Threat.ThreatSource,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True,
            Threat.ThreatSource.isnot(None)
        ).group_by(Threat.ThreatSource).all()
        
        # MITRE techniques
        mitre_techniques = session.query(
            Threat.MitreTechnique,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True,
            Threat.MitreTechnique.isnot(None)
        ).group_by(Threat.MitreTechnique).order_by(
            func.count(Threat.ThreatID).desc()
        ).limit(10).all()
        
        return ThreatStatsResponse(
            total_threats=stats['total_threats'],
            active_threats=stats['active_threats'],
            type_breakdown=stats['type_breakdown'],
            severity_breakdown=stats['severity_breakdown'],
            recent_additions=recent_additions,
            high_confidence_threats=high_confidence,
            platform_distribution={platform: count for platform, count in platform_distribution},
            source_distribution={source: count for source, count in source_distribution if source},
            top_mitre_techniques=[
                {"technique": technique, "count": count}
                for technique, count in mitre_techniques if technique
            ]
        )
        
    except Exception as e:
        logger.error(f"Get threat statistics failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get threat statistics")

@router.get("/categories/list")
async def get_threat_categories(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get list of threat categories"""
    try:
        from sqlalchemy import func, distinct
        
        categories = session.query(
            distinct(Threat.ThreatCategory).label('category')
        ).filter(
            Threat.IsActive == True,
            Threat.ThreatCategory.isnot(None)
        ).all()
        
        category_list = [cat.category for cat in categories if cat.category]
        
        return {
            "categories": sorted(category_list),
            "total_categories": len(category_list)
        }
        
    except Exception as e:
        logger.error(f"Get threat categories failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get threat categories")

@router.get("/types/list")
async def get_threat_types(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get list of threat types"""
    try:
        from sqlalchemy import func, distinct
        
        types = session.query(
            distinct(Threat.ThreatType).label('type')
        ).filter(
            Threat.IsActive == True
        ).all()
        
        type_list = [t.type for t in types if t.type]
        
        return {
            "types": sorted(type_list),
            "total_types": len(type_list)
        }
        
    except Exception as e:
        logger.error(f"Get threat types failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get threat types")

@router.get("/mitre/tactics")
async def get_mitre_tactics(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get MITRE ATT&CK tactics from threats"""
    try:
        from sqlalchemy import func
        
        tactics = session.query(
            Threat.MitreTactic,
            func.count(Threat.ThreatID).label('count')
        ).filter(
            Threat.IsActive == True,
            Threat.MitreTactic.isnot(None)
        ).group_by(Threat.MitreTactic).order_by(
            func.count(Threat.ThreatID).desc()
        ).all()
        
        return {
            "tactics": [
                {
                    "tactic": tactic,
                    "threat_count": count
                }
                for tactic, count in tactics if tactic
            ],
            "total_tactics": len(tactics)
        }
        
    except Exception as e:
        logger.error(f"Get MITRE tactics failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get MITRE tactics")

@router.get("/search")
async def search_threats(
    request: Request,
    query: str = Query(..., description="Search query"),
    search_fields: List[str] = Query(default=["threat_name", "description"], description="Fields to search"),
    limit: int = Query(50, le=200, description="Maximum results"),
    session: Session = Depends(get_db)
):
    """Search threats by name, description, or other fields"""
    try:
        # Build search query
        search_query = session.query(Threat).filter(Threat.IsActive == True)
        
        search_term = f"%{query}%"
        
        # Apply search to specified fields
        conditions = []
        if "threat_name" in search_fields:
            conditions.append(Threat.ThreatName.ilike(search_term))
        if "description" in search_fields:
            conditions.append(Threat.Description.ilike(search_term))
        if "category" in search_fields:
            conditions.append(Threat.ThreatCategory.ilike(search_term))
        if "value" in search_fields:
            conditions.append(Threat.ThreatValue.ilike(search_term))
        
        if conditions:
            from sqlalchemy import or_
            search_query = search_query.filter(or_(*conditions))
        
        # Get results
        threats = search_query.order_by(Threat.UpdatedAt.desc()).limit(limit).all()
        
        # Convert to summary format
        threat_summaries = [threat.to_summary() for threat in threats]
        
        return {
            "query": query,
            "search_fields": search_fields,
            "results": threat_summaries,
            "total_results": len(threat_summaries),
            "limited_results": len(threats) == limit
        }
        
    except Exception as e:
        logger.error(f"Threat search failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Threat search failed")

@router.post("/create")
async def create_threat(
    request: Request,
    threat_data: ThreatCreateRequest,
    session: Session = Depends(get_db)
):
    """Create new threat indicator"""
    try:
        # Check if threat already exists
        existing = Threat.get_by_value(session, threat_data.threat_value)
        if existing:
            raise HTTPException(status_code=400, detail="Threat indicator already exists")
        
        # Create new threat
        new_threat = Threat(
            ThreatName=threat_data.threat_name,
            ThreatType=threat_data.threat_type,
            ThreatValue=threat_data.threat_value,
            ThreatCategory=threat_data.threat_category,
            Severity=threat_data.severity,
            Description=threat_data.description,
            Platform=threat_data.platform,
            ThreatSource=threat_data.source,
            Confidence=threat_data.confidence,
            MitreTactic=threat_data.mitre_tactic,
            MitreTechnique=threat_data.mitre_technique,
            IsActive=True
        )
        
        session.add(new_threat)
        session.commit()
        session.refresh(new_threat)
        
        logger.info(f"New threat created: {threat_data.threat_name} ({threat_data.threat_type})")
        
        return {
            "success": True,
            "message": "Threat indicator created successfully",
            "threat_id": new_threat.ThreatID,
            "threat_data": new_threat.to_dict()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Create threat failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create threat")

@router.put("/{threat_id}/status")
async def update_threat_status(
    request: Request,
    threat_id: int,
    is_active: bool,
    session: Session = Depends(get_db)
):
    """Update threat active status"""
    try:
        threat = session.query(Threat).filter(Threat.ThreatID == threat_id).first()
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        threat.IsActive = is_active
        session.commit()
        
        status_text = "activated" if is_active else "deactivated"
        logger.info(f"Threat {threat_id} {status_text}")
        
        return {
            "success": True,
            "message": f"Threat {status_text} successfully",
            "threat_id": threat_id,
            "is_active": is_active
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Update threat status failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update threat status")