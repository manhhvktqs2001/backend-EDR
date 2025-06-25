"""
Business Logic Services Package - FIXED
"""

from .agent_service import AgentService
from .event_service import EventService, get_event_service
from .detection_engine import DetectionEngine, get_detection_service, detection_engine
from .alert_service import AlertService
from .dashboard_service import DashboardService
from .agent_communication_service import AgentCommunicationService
from .threat_intel import ThreatIntelService, threat_intel_service

# Create service instances
agent_service = AgentService()
event_service = get_event_service()  # Use singleton pattern
alert_service = AlertService()
dashboard_service = DashboardService()
agent_communication_service = AgentCommunicationService()

__all__ = [
    'AgentService', 'agent_service',
    'EventService', 'event_service', 
    'DetectionEngine', 'detection_engine', 'get_detection_service',
    'AlertService', 'alert_service',
    'DashboardService', 'dashboard_service',
    'AgentCommunicationService', 'agent_communication_service',
    'ThreatIntelService', 'threat_intel_service'
]