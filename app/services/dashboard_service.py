# app/services/dashboard_service.py
"""
Dashboard Data Service
Business logic for dashboard data aggregation and statistics
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from ..models.agent import Agent
from ..models.event import Event
from ..models.alert import Alert
from ..models.threat import Threat
from ..models.detection_rule import DetectionRule
from ..database import get_database_status

logger = logging.getLogger('dashboard_service')

class DashboardService:
    """Service for dashboard data aggregation"""
    
    def __init__(self):
        pass
    
    def get_system_overview(self, session: Session) -> Dict:
        """Get complete system overview for main dashboard"""
        try:
            now = datetime.now()
            last_24h = now - timedelta(hours=24)
            last_hour = now - timedelta(hours=1)
            
            overview = {
                'timestamp': now.isoformat(),
                'agents': self._get_agent_overview(session),
                'events': self._get_event_overview(session, last_24h),
                'alerts': self._get_alert_overview(session),
                'threats': self._get_threat_overview(session),
                'detection': self._get_detection_overview(session),
                'system_health': self._get_system_health(session)
            }
            
            return overview
            
        except Exception as e:
            logger.error(f"Failed to get system overview: {str(e)}")
            return {'error': str(e)}
    
    def _get_agent_overview(self, session: Session) -> Dict:
        """Get agent overview statistics"""
        try:
            total_agents = session.query(Agent).count()
            active_agents = session.query(Agent).filter(Agent.Status == 'Active').count()
            
            # Online agents (heartbeat within 5 minutes)
            online_cutoff = datetime.now() - timedelta(minutes=5)
            online_agents = session.query(Agent).filter(
                Agent.Status == 'Active',
                Agent.LastHeartbeat >= online_cutoff
            ).count()
            
            # OS breakdown
            os_breakdown = session.query(
                Agent.OperatingSystem,
                func.count(Agent.AgentID).label('count')
            ).group_by(Agent.OperatingSystem).all()
            
            # Performance issues
            performance_issues = session.query(Agent).filter(
                Agent.Status == 'Active',
                or_(
                    Agent.CPUUsage > 90,
                    Agent.MemoryUsage > 95,
                    Agent.DiskUsage > 90
                )
            ).count()
            
            return {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'online_agents': online_agents,
                'offline_agents': total_agents - online_agents,
                'health_percentage': round((online_agents / total_agents * 100) if total_agents > 0 else 0, 1),
                'os_breakdown': {os: count for os, count in os_breakdown},
                'performance_issues': performance_issues
            }
            
        except Exception as e:
            logger.error(f"Agent overview failed: {str(e)}")
            return {}
    
    def _get_event_overview(self, session: Session, cutoff_time: datetime) -> Dict:
        """Get event overview statistics"""
        try:
            total_events = session.query(Event).filter(Event.EventTimestamp >= cutoff_time).count()
            
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
            
            # Threat events
            suspicious_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel == 'Suspicious'
            ).count()
            
            malicious_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.ThreatLevel == 'Malicious'
            ).count()
            
            # Processing rate
            analyzed_events = session.query(Event).filter(
                Event.EventTimestamp >= cutoff_time,
                Event.Analyzed == True
            ).count()
            
            analysis_rate = (analyzed_events / total_events * 100) if total_events > 0 else 0
            
            return {
                'total_events_24h': total_events,
                'events_per_hour': total_events // 24 if total_events > 0 else 0,
                'type_breakdown': {event_type: count for event_type, count in type_breakdown},
                'severity_breakdown': {severity: count for severity, count in severity_breakdown},
                'suspicious_events': suspicious_events,
                'malicious_events': malicious_events,
                'threat_detection_rate': round(((suspicious_events + malicious_events) / total_events * 100) if total_events > 0 else 0, 2),
                'analysis_rate': round(analysis_rate, 2),
                'unanalyzed_events': total_events - analyzed_events
            }
            
        except Exception as e:
            logger.error(f"Event overview failed: {str(e)}")
            return {}
    
    def _get_alert_overview(self, session: Session) -> Dict:
        """Get alert overview statistics"""
        try:
            # Current alert status
            open_alerts = session.query(Alert).filter(
                Alert.Status.in_(['Open', 'Investigating'])
            ).count()
            
            critical_alerts = session.query(Alert).filter(
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.Severity.in_(['High', 'Critical'])
            ).count()
            
            # Last 24 hours
            last_24h = datetime.now() - timedelta(hours=24)
            alerts_24h = session.query(Alert).filter(Alert.FirstDetected >= last_24h).count()
            resolved_24h = session.query(Alert).filter(
                Alert.FirstDetected >= last_24h,
                Alert.Status == 'Resolved'
            ).count()
            
            # Alert types
            top_alert_types = session.query(
                Alert.AlertType,
                func.count(Alert.AlertID).label('count')
            ).filter(
                Alert.FirstDetected >= last_24h
            ).group_by(Alert.AlertType).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(5).all()
            
            # MITRE tactics
            mitre_tactics = session.query(
                Alert.MitreTactic,
                func.count(Alert.AlertID).label('count')
            ).filter(
                Alert.FirstDetected >= last_24h,
                Alert.MitreTactic.isnot(None)
            ).group_by(Alert.MitreTactic).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(5).all()
            
            # Recent critical alerts
            recent_critical = session.query(Alert).filter(
                Alert.Severity.in_(['High', 'Critical']),
                Alert.Status.in_(['Open', 'Investigating'])
            ).order_by(Alert.FirstDetected.desc()).limit(10).all()
            
            return {
                'open_alerts': open_alerts,
                'critical_alerts': critical_alerts,
                'alerts_24h': alerts_24h,
                'resolved_24h': resolved_24h,
                'resolution_rate': round((resolved_24h / alerts_24h * 100) if alerts_24h > 0 else 0, 1),
                'top_alert_types': [{'type': t, 'count': c} for t, c in top_alert_types],
                'mitre_tactics': [{'tactic': t, 'count': c} for t, c in mitre_tactics if t],
                'recent_critical': [
                    {
                        'alert_id': alert.AlertID,
                        'title': alert.Title,
                        'severity': alert.Severity,
                        'age_minutes': alert.get_age_minutes()
                    }
                    for alert in recent_critical
                ]
            }
            
        except Exception as e:
            logger.error(f"Alert overview failed: {str(e)}")
            return {}
    
    def _get_threat_overview(self, session: Session) -> Dict:
        """Get threat intelligence overview"""
        try:
            # Active threats
            active_threats = session.query(Threat).filter(Threat.IsActive == True).count()
            
            # Threat type breakdown
            type_breakdown = session.query(
                Threat.ThreatType,
                func.count(Threat.ThreatID).label('count')
            ).filter(
                Threat.IsActive == True
            ).group_by(Threat.ThreatType).all()
            
            # Recent detections (alerts linked to threats)
            last_24h = datetime.now() - timedelta(hours=24)
            recent_detections = session.query(
                Threat.ThreatName,
                Threat.ThreatCategory,
                func.count(Alert.AlertID).label('detection_count')
            ).join(
                Alert, Threat.ThreatID == Alert.ThreatID
            ).filter(
                Alert.FirstDetected >= last_24h
            ).group_by(
                Threat.ThreatName, Threat.ThreatCategory
            ).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(10).all()
            
            # High confidence threats
            high_confidence = session.query(Threat).filter(
                Threat.IsActive == True,
                Threat.Confidence >= 0.8
            ).count()
            
            return {
                'active_threats': active_threats,
                'high_confidence_threats': high_confidence,
                'type_breakdown': {threat_type: count for threat_type, count in type_breakdown},
                'recent_detections': [
                    {
                        'threat_name': name,
                        'category': category,
                        'detection_count': count
                    }
                    for name, category, count in recent_detections
                ]
            }
            
        except Exception as e:
            logger.error(f"Threat overview failed: {str(e)}")
            return {}
    
    def _get_detection_overview(self, session: Session) -> Dict:
        """Get detection engine overview"""
        try:
            # Active rules
            active_rules = session.query(DetectionRule).filter(DetectionRule.IsActive == True).count()
            
            # Rules by type
            rule_types = session.query(
                DetectionRule.RuleType,
                func.count(DetectionRule.RuleID).label('count')
            ).filter(
                DetectionRule.IsActive == True
            ).group_by(DetectionRule.RuleType).all()
            
            # Recent rule hits (alerts from rules)
            last_24h = datetime.now() - timedelta(hours=24)
            rule_hits = session.query(
                DetectionRule.RuleName,
                func.count(Alert.AlertID).label('hit_count')
            ).join(
                Alert, DetectionRule.RuleID == Alert.RuleID
            ).filter(
                Alert.FirstDetected >= last_24h
            ).group_by(
                DetectionRule.RuleName
            ).order_by(
                func.count(Alert.AlertID).desc()
            ).limit(10).all()
            
            # Coverage by platform
            platform_coverage = session.query(
                DetectionRule.Platform,
                func.count(DetectionRule.RuleID).label('count')
            ).filter(
                DetectionRule.IsActive == True
            ).group_by(DetectionRule.Platform).all()
            
            return {
                'active_rules': active_rules,
                'rule_types': {rule_type: count for rule_type, count in rule_types},
                'top_rule_hits': [
                    {'rule_name': name, 'hit_count': count}
                    for name, count in rule_hits
                ],
                'platform_coverage': {platform: count for platform, count in platform_coverage}
            }
            
        except Exception as e:
            logger.error(f"Detection overview failed: {str(e)}")
            return {}
    
    def _get_system_health(self, session: Session) -> Dict:
        """Get system health metrics"""
        try:
            # Database health
            db_status = get_database_status()
            
            # Processing health
            unanalyzed_events = session.query(Event).filter(Event.Analyzed == False).count()
            
            # Agent health
            total_agents = session.query(Agent).count()
            healthy_agents = session.query(Agent).filter(
                Agent.Status == 'Active',
                Agent.LastHeartbeat >= datetime.now() - timedelta(minutes=5)
            ).count()
            
            # Alert processing health
            old_alerts = session.query(Alert).filter(
                Alert.Status.in_(['Open', 'Investigating']),
                Alert.FirstDetected < datetime.now() - timedelta(hours=24)
            ).count()
            
            # Overall health score
            health_factors = [
                (healthy_agents / total_agents if total_agents > 0 else 0) * 40,  # Agent health (40%)
                (1 if db_status.get('healthy') else 0) * 30,  # Database health (30%)
                (1 if unanalyzed_events < 1000 else 0.5 if unanalyzed_events < 5000 else 0) * 20,  # Processing (20%)
                (1 if old_alerts < 10 else 0.5 if old_alerts < 50 else 0) * 10  # Alert management (10%)
            ]
            
            overall_score = sum(health_factors)
            
            return {
                'overall_score': round(overall_score, 1),
                'status': self._get_health_status(overall_score),
                'database_healthy': db_status.get('healthy', False),
                'database_response_ms': db_status.get('response_time_ms', 0),
                'agent_health_percent': round((healthy_agents / total_agents * 100) if total_agents > 0 else 0, 1),
                'processing_backlog': unanalyzed_events,
                'old_unresolved_alerts': old_alerts,
                'issues': self._get_health_issues(db_status, unanalyzed_events, old_alerts, healthy_agents, total_agents)
            }
            
        except Exception as e:
            logger.error(f"System health check failed: {str(e)}")
            return {'overall_score': 0, 'status': 'Error', 'error': str(e)}
    
    def _get_health_status(self, score: float) -> str:
        """Get health status text from score"""
        if score >= 90:
            return "Excellent"
        elif score >= 75:
            return "Good" 
        elif score >= 60:
            return "Fair"
        elif score >= 40:
            return "Poor"
        else:
            return "Critical"
    
    def _get_health_issues(self, db_status: Dict, unanalyzed: int, old_alerts: int, 
                          healthy_agents: int, total_agents: int) -> List[str]:
        """Get list of health issues"""
        issues = []
        
        if not db_status.get('healthy'):
            issues.append("Database connection issues")
        
        if unanalyzed > 5000:
            issues.append(f"High processing backlog: {unanalyzed:,} unanalyzed events")
        elif unanalyzed > 1000:
            issues.append(f"Processing backlog: {unanalyzed:,} unanalyzed events")
        
        if old_alerts > 50:
            issues.append(f"Many old unresolved alerts: {old_alerts}")
        elif old_alerts > 10:
            issues.append(f"Some old unresolved alerts: {old_alerts}")
        
        agent_health_percent = (healthy_agents / total_agents * 100) if total_agents > 0 else 0
        if agent_health_percent < 80:
            issues.append(f"Low agent health: {agent_health_percent:.1f}% healthy")
        
        return issues
    
    def get_real_time_stats(self, session: Session) -> Dict:
        """Get real-time statistics for live updates"""
        try:
            now = datetime.now()
            last_5min = now - timedelta(minutes=5)
            last_hour = now - timedelta(hours=1)
            
            return {
                'timestamp': now.isoformat(),
                'recent_activity': {
                    'events_last_5min': session.query(Event).filter(Event.CreatedAt >= last_5min).count(),
                    'alerts_last_5min': session.query(Alert).filter(Alert.FirstDetected >= last_5min).count(),
                    'agent_heartbeats_last_5min': session.query(Agent).filter(Agent.LastHeartbeat >= last_5min).count()
                },
                'current_status': {
                    'online_agents': session.query(Agent).filter(
                        Agent.Status == 'Active',
                        Agent.LastHeartbeat >= last_5min
                    ).count(),
                    'open_alerts': session.query(Alert).filter(Alert.Status.in_(['Open', 'Investigating'])).count(),
                    'critical_alerts': session.query(Alert).filter(
                        Alert.Status.in_(['Open', 'Investigating']),
                        Alert.Severity.in_(['High', 'Critical'])
                    ).count(),
                    'unanalyzed_events': session.query(Event).filter(Event.Analyzed == False).count()
                },
                'hourly_rates': {
                    'events_per_hour': session.query(Event).filter(Event.CreatedAt >= last_hour).count(),
                    'alerts_per_hour': session.query(Alert).filter(Alert.FirstDetected >= last_hour).count(),
                    'threats_detected_per_hour': session.query(Event).filter(
                        Event.CreatedAt >= last_hour,
                        Event.ThreatLevel.in_(['Suspicious', 'Malicious'])
                    ).count()
                }
            }
            
        except Exception as e:
            logger.error(f"Real-time stats failed: {str(e)}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}

# Global service instance
dashboard_service = DashboardService()