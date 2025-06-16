"""
EDR System Models Package
SQLAlchemy models for all database tables
"""

from .agent import Agent
from .event import Event
from .alert import Alert
from .threat import Threat
from .detection_rule import DetectionRule

# Export all models
__all__ = [
    'Agent',
    'Event', 
    'Alert',
    'Threat',
    'DetectionRule'
]

# Model registry for dynamic access
MODEL_REGISTRY = {
    'Agent': Agent,
    'Event': Event,
    'Alert': Alert,
    'Threat': Threat,
    'DetectionRule': DetectionRule
}

def get_model(model_name: str):
    """Get model class by name"""
    return MODEL_REGISTRY.get(model_name)