"""
Business Logic Services Package
"""

from .agent_service import AgentService
from .event_service import EventService
from .detection_engine import DetectionEngine
from .alert_service import AlertService
from .dashboard_service import DashboardService
from .agent_communication_service import AgentCommunicationService
from .threat_intel import ThreatIntelService, threat_intel_service

# Create service instances
agent_service = AgentService()
event_service = EventService()
detection_engine = DetectionEngine()
alert_service = AlertService()
dashboard_service = DashboardService()
agent_communication_service = AgentCommunicationService()

__all__ = [
    'AgentService', 'agent_service',
    'EventService', 'event_service', 
    'DetectionEngine', 'detection_engine',
    'AlertService', 'alert_service',
    'DashboardService', 'dashboard_service',
    'AgentCommunicationService', 'agent_communication_service',
    'ThreatIntelService', 'threat_intel_service'
]