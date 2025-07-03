# app/api/v1/detection.py
"""
Detection Rules API Endpoints
Detection rules management and configuration
"""

import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from ...database import get_db
from ...models.detection_rule import DetectionRule
from ...api.dependencies import require_detection_engine

logger = logging.getLogger('detection_rules')
router = APIRouter()

@router.get("/rules")
async def list_detection_rules(
    request: Request,
    rule_type: Optional[str] = Query(None, description="Filter by rule type"),
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    limit: int = Query(100, le=1000, description="Maximum rules to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """List detection rules with filtering and pagination"""
    try:
        # Build query
        query = session.query(DetectionRule)
        
        # Apply filters
        filters_applied = {}
        
        if rule_type:
            query = query.filter(DetectionRule.RuleType == rule_type)
            filters_applied['rule_type'] = rule_type
        
        if category:
            query = query.filter(DetectionRule.RuleCategory == category)
            filters_applied['category'] = category
        
        if platform:
            query = query.filter(
                (DetectionRule.Platform == platform) | (DetectionRule.Platform == 'All')
            )
            filters_applied['platform'] = platform
        
        if is_active is not None:
            query = query.filter(DetectionRule.IsActive == is_active)
            filters_applied['is_active'] = is_active
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination and get results
        rules = query.order_by(DetectionRule.Priority.desc(), DetectionRule.UpdatedAt.desc()).offset(offset).limit(limit).all()
        
        # Convert to summary format
        rule_summaries = [rule.to_summary() for rule in rules]
        
        # Calculate page info
        page = (offset // limit) + 1 if limit > 0 else 1
        
        # Get summary statistics
        active_count = session.query(DetectionRule).filter(DetectionRule.IsActive == True).count()
        
        return {
            "rules": rule_summaries,
            "total_count": total_count,
            "active_count": active_count,
            "page": page,
            "page_size": limit,
            "filters_applied": filters_applied
        }
        
    except Exception as e:
        logger.error(f"List detection rules failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list detection rules")

@router.get("/rules/{rule_id}")
async def get_detection_rule(
    request: Request,
    rule_id: int,
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Get specific detection rule details"""
    try:
        rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        # Get rule data with additional info
        rule_data = rule.to_dict()
        
        # Get rule performance stats (alerts generated)
        from ...models.alert import Alert
        
        alerts_generated = session.query(func.count(Alert.AlertID)).filter(
            Alert.RuleID == rule_id
        ).scalar() or 0
        
        alerts_last_24h = session.query(func.count(Alert.AlertID)).filter(
            Alert.RuleID == rule_id,
            Alert.FirstDetected >= func.dateadd('hour', -24, func.getdate())
        ).scalar() or 0
        
        rule_data['performance'] = {
            'total_alerts_generated': alerts_generated,
            'alerts_last_24h': alerts_last_24h,
            'effectiveness_score': min(100, alerts_generated * 2) if alerts_generated > 0 else 0
        }
        
        return rule_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get detection rule failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get detection rule")

@router.post("/rules")
async def create_detection_rule(
    request: Request,
    rule_data: Dict[str, Any],
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Create new detection rule"""
    try:
        # Validate required fields
        required_fields = ['rule_name', 'rule_type', 'rule_condition', 'alert_title', 'alert_severity', 'alert_type']
        for field in required_fields:
            if field not in rule_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Check for duplicate rule name
        existing = session.query(DetectionRule).filter(DetectionRule.RuleName == rule_data['rule_name']).first()
        if existing:
            raise HTTPException(status_code=400, detail="Rule name already exists")
        
        # Create rule
        new_rule = DetectionRule.create_rule(
            rule_name=rule_data['rule_name'],
            rule_type=rule_data['rule_type'],
            rule_condition=rule_data['rule_condition'],
            alert_title=rule_data['alert_title'],
            alert_severity=rule_data['alert_severity'],
            alert_type=rule_data['alert_type'],
            RuleCategory=rule_data.get('rule_category'),
            AlertDescription=rule_data.get('alert_description'),
            MitreTactic=rule_data.get('mitre_tactic'),
            MitreTechnique=rule_data.get('mitre_technique'),
            Platform=rule_data.get('platform', 'All'),
            Priority=rule_data.get('priority', 50),
            TestMode=rule_data.get('test_mode', False)
        )
        
        session.add(new_rule)
        session.commit()
        session.refresh(new_rule)
        
        logger.info(f"Detection rule created: {new_rule.RuleName} (ID: {new_rule.RuleID})")
        
        return {
            "success": True,
            "message": "Detection rule created successfully",
            "rule_id": new_rule.RuleID,
            "rule_data": new_rule.to_dict()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Create detection rule failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create detection rule")

@router.put("/rules/{rule_id}")
async def update_detection_rule(
    request: Request,
    rule_id: int,
    rule_updates: Dict[str, Any],
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Update detection rule"""
    try:
        rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        # Update allowed fields
        updateable_fields = [
            'rule_category', 'rule_condition', 'alert_title', 'alert_description',
            'alert_severity', 'alert_type', 'mitre_tactic', 'mitre_technique',
            'platform', 'priority', 'is_active', 'test_mode'
        ]
        
        updated_fields = []
        for field, value in rule_updates.items():
            if field in updateable_fields:
                if field == 'rule_condition':
                    rule.set_rule_condition(value)
                elif field == 'is_active':
                    if value:
                        rule.enable()
                    else:
                        rule.disable()
                elif field == 'test_mode':
                    rule.set_test_mode(value)
                else:
                    # Map field names to model attributes
                    attr_map = {
                        'rule_category': 'RuleCategory',
                        'alert_title': 'AlertTitle',
                        'alert_description': 'AlertDescription',
                        'alert_severity': 'AlertSeverity',
                        'alert_type': 'AlertType',
                        'mitre_tactic': 'MitreTactic',
                        'mitre_technique': 'MitreTechnique',
                        'platform': 'Platform',
                        'priority': 'Priority'
                    }
                    
                    attr_name = attr_map.get(field, field)
                    if hasattr(rule, attr_name):
                        setattr(rule, attr_name, value)
                        updated_fields.append(field)
        
        if updated_fields:
            rule.UpdatedAt = func.getdate()
            session.commit()
            
            logger.info(f"Detection rule {rule_id} updated: {updated_fields}")
            
            return {
                "success": True,
                "message": "Detection rule updated successfully",
                "rule_id": rule_id,
                "updated_fields": updated_fields,
                "rule_data": rule.to_dict()
            }
        else:
            return {
                "success": True,
                "message": "No fields updated",
                "rule_id": rule_id
            }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Update detection rule failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update detection rule")

@router.delete("/rules/{rule_id}")
async def delete_detection_rule(
    request: Request,
    rule_id: int,
    force: bool = Query(False),
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Delete detection rule"""
    try:
        rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        rule_name = rule.RuleName
        
        # Check if rule has generated alerts
        from ...models.alert import Alert
        alerts_count = session.query(Alert).filter(Alert.RuleID == rule_id).count()
        
        if alerts_count > 0 and not force:
            # Disable instead of delete if alerts exist and not force
            rule.disable()
            session.commit()
            logger.info(f"Detection rule {rule_id} disabled (has {alerts_count} alerts)")
            return {
                "success": True,
                "message": f"Detection rule disabled (has {alerts_count} existing alerts)",
                "rule_id": rule_id,
                "rule_name": rule_name,
                "action": "disabled"
            }
        else:
            # Safe to delete (force or no alerts)
            session.delete(rule)
            session.commit()
            logger.info(f"Detection rule {rule_id} deleted: {rule_name}")
            return {
                "success": True,
                "message": "Detection rule deleted successfully",
                "rule_id": rule_id,
                "rule_name": rule_name,
                "action": "deleted"
            }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Delete detection rule failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete detection rule")

@router.post("/rules/{rule_id}/enable")
async def enable_detection_rule(
    request: Request,
    rule_id: int,
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Enable detection rule"""
    try:
        rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        rule.enable()
        session.commit()
        
        logger.info(f"Detection rule {rule_id} enabled: {rule.RuleName}")
        
        return {
            "success": True,
            "message": "Detection rule enabled successfully",
            "rule_id": rule_id,
            "rule_name": rule.RuleName,
            "is_active": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Enable detection rule failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to enable detection rule")

@router.post("/rules/{rule_id}/disable")
async def disable_detection_rule(
    request: Request,
    rule_id: int,
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Disable detection rule"""
    try:
        rule = session.query(DetectionRule).filter(DetectionRule.RuleID == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="Detection rule not found")
        
        rule.disable()
        session.commit()
        
        logger.info(f"Detection rule {rule_id} disabled: {rule.RuleName}")
        
        return {
            "success": True,
            "message": "Detection rule disabled successfully",
            "rule_id": rule_id,
            "rule_name": rule.RuleName,
            "is_active": False
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Disable detection rule failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disable detection rule")

@router.get("/rules/stats/summary")
async def get_detection_rules_stats(
    request: Request,
    session: Session = Depends(get_db),
    _: bool = Depends(require_detection_engine)
):
    """Get detection rules statistics summary"""
    try:
        stats = DetectionRule.get_rules_summary(session)
        
        # Get additional statistics
        # Rules by severity
        severity_breakdown = session.query(
            DetectionRule.AlertSeverity,
            func.count(DetectionRule.RuleID).label('count')
        ).filter(
            DetectionRule.IsActive == True
        ).group_by(DetectionRule.AlertSeverity).all()
        
        # Recent rule performance (last 7 days)
        from ...models.alert import Alert
        
        rule_performance = session.query(
            DetectionRule.RuleName,
            func.count(Alert.AlertID).label('alerts_generated')
        ).join(
            Alert, DetectionRule.RuleID == Alert.RuleID
        ).filter(
            Alert.FirstDetected >= func.dateadd('day', -7, func.getdate())
        ).group_by(
            DetectionRule.RuleName
        ).order_by(
            func.count(Alert.AlertID).desc()
        ).limit(10).all()
        
        # Platform coverage
        platform_coverage = session.query(
            DetectionRule.Platform,
            func.count(DetectionRule.RuleID).label('count')
        ).filter(
            DetectionRule.IsActive == True
        ).group_by(DetectionRule.Platform).all()
        
        # MITRE coverage
        mitre_coverage = session.query(
            DetectionRule.MitreTactic,
            func.count(DetectionRule.RuleID).label('count')
        ).filter(
            DetectionRule.IsActive == True,
            DetectionRule.MitreTactic.isnot(None)
        ).group_by(DetectionRule.MitreTactic).all()
        
        stats.update({
            'severity_breakdown': {severity: count for severity, count in severity_breakdown},
            'top_performing_rules': [
                {'rule_name': name, 'alerts_generated': count}
                for name, count in rule_performance
            ],
            'platform_coverage': {platform: count for platform, count in platform_coverage},
            'mitre_coverage': {tactic: count for tactic, count in mitre_coverage if tactic}
        })
        
        return stats
        
    except Exception as e:
        logger.error(f"Get detection rules stats failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get detection rules statistics")

@router.get("/rules/types")
async def get_rule_types(
    request: Request,
    session: Session = Depends(get_db)
):
    """Get available rule types"""
    return {
        "rule_types": [
            {
                "type": "Signature",
                "description": "Static signature-based detection",
                "examples": ["File hash matching", "Registry key patterns"]
            },
            {
                "type": "Behavioral", 
                "description": "Behavior-based detection",
                "examples": ["Process execution patterns", "Network communication behavior"]
            },
            {
                "type": "Threshold",
                "description": "Threshold-based detection", 
                "examples": ["Event frequency limits", "Resource usage thresholds"]
            },
            {
                "type": "Correlation",
                "description": "Event correlation detection",
                "examples": ["Multi-stage attack patterns", "Related event sequences"]
            }
        ],
        "supported_operators": [
            "equals", "iequals", "contains", "contains_any", "not_equals",
            "in", "not_in", "regex", "greater_than", "less_than"
        ],
        "supported_platforms": ["All", "Windows", "Linux", "macOS"]
    }