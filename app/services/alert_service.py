# app/services/alert_service.py
"""
Alert Management Service
Business logic for alert management, correlation, and workflow
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from ..models.alert import Alert
from ..models.agent import Agent
from ..models.event import Event
from ..models.threat import Threat
from ..models.detection_rule import DetectionRule
from ..config import config

logger = logging.getLogger('alert_management')

class AlertService:
    """Service for managing EDR alerts"""
    
    def __init__(self):
        self.alert_config = config['alert']
        self.detection_config = config['detection']
    
    def create_alert(self, session: Session, agent_id: str, alert_type: str, 
                    title: str, severity: str, detection_method: str, **kwargs) -> Alert:
        """Create new alert with validation"""
        try:
            # Validate agent exists
            agent = session.query(Agent).filter(Agent.AgentID == agent_id).first()
            if not agent:
                raise ValueError(f"Agent not found: {agent_id}")
            
            # Check for recent duplicate alerts
            if self._check_duplicate_alert(session, agent_id, alert_type, title):
                logger.debug(f"Duplicate alert suppressed: {title}")
                return None
            
            # Create alert
            alert = Alert.create_alert(
                agent_id=agent_id,
                alert_type=alert_type,
                title=title,
                severity=severity,
                detection_method=detection_method,
                **kwargs
            )
            
            session.add(alert)
            session.flush()  # Get alert ID
            
            logger.info(f"Alert created: ID={alert.AlertID}, Type={alert_type}, Severity={severity}")
            
            # Auto-correlation if enabled
            self._correlate_alert(session, alert)
            
            return alert
            
        except Exception as e:
            logger.error(f"Failed to create alert: {str(e)}")
            raise
    
    def update_alert_status(self, session: Session, alert_id: int, status: str,
                           assigned_to: Optional[str] = None, notes: Optional[str] = None) -> bool:
        """Update alert status with validation"""
        try:
            alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
            if not alert:
                logger.warning(f"Alert not found: {alert_id}")
                return False
            
            old_status = alert.Status
            alert.update_status(status=status, assigned_to=assigned_to)
            
            # Add resolution timestamp if resolved
            if status == 'Resolved' and assigned_to:
                alert.ResolvedBy = assigned_to
            
            session.commit()
            
            logger.info(f"Alert {alert_id} status updated: {old_status} -> {status}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update alert status: {str(e)}")
            return False
    
    def bulk_update_alerts(self, session: Session, alert_ids: List[int], 
                          status: str, assigned_to: Optional[str] = None) -> Tuple[int, List[str]]:
        """Bulk update multiple alerts"""
        try:
            updated_count = 0
            errors = []
            
            for alert_id in alert_ids:
                try:
                    if self.update_alert_status(session, alert_id, status, assigned_to):
                        updated_count += 1
                    else:
                        errors.append(f"Alert {alert_id} not found")
                except Exception as e:
                    errors.append(f"Failed to update alert {alert_id}: {str(e)}")
            
            logger.info(f"Bulk update completed: {updated_count} alerts updated")
            return updated_count, errors
            
        except Exception as e:
            logger.error(f"Bulk update failed: {str(e)}")
            return 0, [str(e)]
    
    def auto_resolve_old_alerts(self, session: Session, days: int = None) -> int:
        """Auto-resolve old alerts based on retention policy"""
        try:
            resolve_days = days or self.alert_config.get('auto_resolve_days', 30)
            cutoff_date = datetime.now() - timedelta(days=resolve_days)
            
            # Find old open alerts
            old_alerts = session.query(Alert).filter(
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.FirstDetected < cutoff_date
            ).all()
            
            resolved_count = 0
            for alert in old_alerts:
                alert.update_status(status='Resolved', resolved_by='System Auto-Resolve')
                resolved_count += 1
            
            session.commit()
            
            if resolved_count > 0:
                logger.info(f"Auto-resolved {resolved_count} old alerts")
            
            return resolved_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"Auto-resolve failed: {str(e)}")
            return 0
    
    def correlate_alerts(self, session: Session, alert: Alert) -> List[int]:
        """Correlate alert with related alerts"""
        try:
            return self._correlate_alert(session, alert)
        except Exception as e:
            logger.error(f"Alert correlation failed: {str(e)}")
            return []
    
    def _correlate_alert(self, session: Session, alert: Alert) -> List[int]:
        """Internal correlation logic"""
        correlated_alerts = []
        correlation_window = timedelta(hours=1)  # 1 hour window
        
        try:
            # Find related alerts within time window
            time_start = alert.FirstDetected - correlation_window
            time_end = alert.FirstDetected + correlation_window
            
            # Correlation criteria
            related_query = session.query(Alert).filter(
                Alert.AlertID != alert.AlertID,
                Alert.FirstDetected.between(time_start, time_end),
                Alert.Status.in_(['Open', 'Investigating'])
            )
            
            # Same agent correlation
            same_agent_alerts = related_query.filter(Alert.AgentID == alert.AgentID).all()
            
            # Same MITRE tactic correlation
            if alert.MitreTactic:
                same_tactic_alerts = related_query.filter(
                    Alert.MitreTactic == alert.MitreTactic
                ).all()
                correlated_alerts.extend([a.AlertID for a in same_tactic_alerts])
            
            # Same threat correlation
            if alert.ThreatID:
                same_threat_alerts = related_query.filter(
                    Alert.ThreatID == alert.ThreatID
                ).all()
                correlated_alerts.extend([a.AlertID for a in same_threat_alerts])
            
            correlated_alerts.extend([a.AlertID for a in same_agent_alerts])
            
            # Remove duplicates
            correlated_alerts = list(set(correlated_alerts))
            
            if correlated_alerts:
                logger.debug(f"Alert {alert.AlertID} correlated with {len(correlated_alerts)} alerts")
            
            return correlated_alerts
            
        except Exception as e:
            logger.error(f"Correlation logic failed: {str(e)}")
            return []
    
    def _check_duplicate_alert(self, session: Session, agent_id: str, 
                              alert_type: str, title: str) -> bool:
        """Check for recent duplicate alerts"""
        try:
            dedup_window = self.detection_config.get('alert_deduplication_window', 300)  # 5 minutes
            cutoff_time = datetime.now() - timedelta(seconds=dedup_window)
            
            existing = session.query(Alert).filter(
                Alert.AgentID == agent_id,
                Alert.AlertType == alert_type,
                Alert.Title == title,
                Alert.FirstDetected >= cutoff_time,
                Alert.Status.in_(['Open', 'Investigating'])
            ).first()
            
            return existing is not None
            
        except Exception as e:
            logger.error(f"Duplicate check failed: {str(e)}")
            return False
    
    def get_alert_metrics(self, session: Session, hours: int = 24) -> Dict:
        """Get alert metrics for dashboard"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Basic counts
            total_alerts = session.query(Alert).filter(Alert.FirstDetected >= cutoff_time).count()
            open_alerts = session.query(Alert).filter(
                Alert.Status.in_(['Open', 'Investigating'])
            ).count()
            critical_alerts = session.query(Alert).filter(
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.Severity.in_(['High', 'Critical'])
            ).count()
            
            # Resolution metrics
            resolved_alerts = session.query(Alert).filter(
                Alert.FirstDetected >= cutoff_time,
                Alert.Status == 'Resolved'
            ).count()
            
            # Top alert types
            top_types = session.query(
                Alert.AlertType,
                func.count(Alert.AlertID).label('count')
            ).filter(
                Alert.FirstDetected >= cutoff_time
            ).group_by(Alert.AlertType).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(10).all()
            
            # Agent breakdown
            agent_breakdown = session.query(
                Agent.HostName,
                func.count(Alert.AlertID).label('alert_count')
            ).join(
                Alert, Agent.AgentID == Alert.AgentID
            ).filter(
                Alert.FirstDetected >= cutoff_time
            ).group_by(Agent.HostName).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(10).all()
            
            # MITRE tactics
            mitre_tactics = session.query(
                Alert.MitreTactic,
                func.count(Alert.AlertID).label('count')
            ).filter(
                Alert.FirstDetected >= cutoff_time,
                Alert.MitreTactic.isnot(None)
            ).group_by(Alert.MitreTactic).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(10).all()
            
            return {
                'time_range_hours': hours,
                'total_alerts': total_alerts,
                'open_alerts': open_alerts,
                'critical_alerts': critical_alerts,
                'resolved_alerts': resolved_alerts,
                'resolution_rate': round((resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0, 2),
                'top_alert_types': [{'type': t, 'count': c} for t, c in top_types],
                'agent_breakdown': [{'hostname': h, 'count': c} for h, c in agent_breakdown],
                'mitre_tactics': [{'tactic': t, 'count': c} for t, c in mitre_tactics if t]
            }
            
        except Exception as e:
            logger.error(f"Failed to get alert metrics: {str(e)}")
            return {}
    
    def get_alert_trends(self, session: Session, days: int = 7) -> Dict:
        """Get alert trends over time"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days)
            
            # Daily alert counts
            daily_counts = session.query(
                func.cast(Alert.FirstDetected, func.date()).label('alert_date'),
                func.count(Alert.AlertID).label('count')
            ).filter(
                Alert.FirstDetected >= cutoff_time
            ).group_by(
                func.cast(Alert.FirstDetected, func.date())
            ).order_by('alert_date').all()
            
            # Severity trends
            severity_trends = session.query(
                func.cast(Alert.FirstDetected, func.date()).label('alert_date'),
                Alert.Severity,
                func.count(Alert.AlertID).label('count')
            ).filter(
                Alert.FirstDetected >= cutoff_time
            ).group_by(
                func.cast(Alert.FirstDetected, func.date()),
                Alert.Severity
            ).order_by('alert_date', Alert.Severity).all()
            
            return {
                'time_range_days': days,
                'daily_counts': [
                    {'date': str(date), 'count': count} 
                    for date, count in daily_counts
                ],
                'severity_trends': [
                    {'date': str(date), 'severity': severity, 'count': count}
                    for date, severity, count in severity_trends
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to get alert trends: {str(e)}")
            return {}
    
    def escalate_alert(self, session: Session, alert_id: int, escalated_to: str,
                      escalation_reason: str) -> bool:
        """Escalate alert to higher priority"""
        try:
            alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
            if not alert:
                return False
            
            # Update priority and assignment
            priority_map = {'Low': 'Medium', 'Medium': 'High', 'High': 'Critical'}
            new_priority = priority_map.get(alert.Priority, 'Critical')
            
            alert.Priority = new_priority
            alert.AssignedTo = escalated_to
            alert.update_status('Investigating', escalated_to)
            
            # Log escalation
            logger.info(f"Alert {alert_id} escalated to {escalated_to}: {escalation_reason}")
            
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Alert escalation failed: {str(e)}")
            return False
    
    def suppress_similar_alerts(self, session: Session, alert_id: int, 
                               suppression_hours: int = 24) -> int:
        """Suppress similar alerts for specified time"""
        try:
            source_alert = session.query(Alert).filter(Alert.AlertID == alert_id).first()
            if not source_alert:
                return 0
            
            # Find similar alerts
            similar_alerts = session.query(Alert).filter(
                Alert.AlertID != alert_id,
                Alert.AgentID == source_alert.AgentID,
                Alert.AlertType == source_alert.AlertType,
                Alert.Status.in_(['Open', 'Investigating'])
            ).all()
            
            suppressed_count = 0
            for alert in similar_alerts:
                alert.update_status('Suppressed', 'System Auto-Suppress')
                suppressed_count += 1
            
            session.commit()
            
            logger.info(f"Suppressed {suppressed_count} similar alerts to {alert_id}")
            return suppressed_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"Alert suppression failed: {str(e)}")
            return 0
    
    def cleanup_old_alerts(self, session: Session, retention_days: int = None) -> int:
        """Clean up old alerts based on retention policy"""
        try:
            retention_days = retention_days or self.alert_config.get('retention_days', 90)
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # Find old alerts to delete
            old_alerts = session.query(Alert).filter(
                Alert.FirstDetected < cutoff_date
            ).all()
            
            deleted_count = 0
            for alert in old_alerts:
                session.delete(alert)
                deleted_count += 1
            
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old alerts")
            
            return deleted_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"Alert cleanup failed: {str(e)}")
            return 0
    
    async def create_alert_from_detection(self, session: Session, event_id: int, 
                                        detection_result: Dict, agent_id: str) -> Optional[Alert]:
        """Create alert from detection engine results"""
        try:
            # Extract detection information
            threat_detected = detection_result.get('threat_detected', False)
            risk_score = detection_result.get('risk_score', 0)
            detection_methods = detection_result.get('detection_methods', [])
            matched_rules = detection_result.get('matched_rules', [])
            
            if not threat_detected:
                return None
            
            # Determine alert type and severity
            alert_type = "Threat Detection"
            severity = self._determine_severity(risk_score)
            
            # Create alert title
            if matched_rules:
                rule_names = [rule.get('name', 'Unknown Rule') for rule in matched_rules]
                title = f"Rule Violation: {', '.join(rule_names)}"
            else:
                title = f"Threat Detected (Risk Score: {risk_score})"
            
            # Create alert description
            description = f"Threat detected with risk score {risk_score}. "
            if detection_methods:
                description += f"Detection methods: {', '.join(detection_methods)}"
            
            # Create the alert
            alert = self.create_alert(
                session=session,
                agent_id=agent_id,
                alert_type=alert_type,
                title=title,
                severity=severity,
                detection_method="Detection Engine",
                description=description,
                risk_score=risk_score,
                event_id=event_id,
                raw_detection_data=detection_result
            )
            
            if alert:
                logger.warning(f"🚨 ALERT CREATED from detection: ID={alert.AlertID}, Title={title}")
            
            return alert
            
        except Exception as e:
            logger.error(f"Failed to create alert from detection: {e}")
            return None
    
    def _determine_severity(self, risk_score: int) -> str:
        """Determine alert severity from risk score"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

# Global instance
_alert_service_instance = None

def get_alert_service() -> AlertService:
    """Get singleton alert service instance"""
    global _alert_service_instance
    if _alert_service_instance is None:
        _alert_service_instance = AlertService()
        logger.info("🚨 Alert Service singleton created")
    return _alert_service_instance