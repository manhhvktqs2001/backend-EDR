# Quick fix for import errors
# File: app/models/__init__.py - Updated with proper imports

"""
Database Models Package - FIXED IMPORTS
"""

# Import all models to ensure they are available
try:
    from .agent import Agent
    from .event import Event  
    from .alert import Alert
    from .threat import Threat
    from .detection_rule import DetectionRule
    from .system_config import SystemConfig
    from .agent_config import AgentConfig

    __all__ = [
        'Agent', 
        'Event', 
        'Alert', 
        'Threat', 
        'DetectionRule',
        'SystemConfig',
        'AgentConfig'
    ]
    
    print("✅ All models imported successfully")
    
except ImportError as e:
    print(f"❌ Model import error: {e}")
    # Fallback imports
    try:
        from .agent import Agent
        from .event import Event
        from .alert import Alert
        __all__ = ['Agent', 'Event', 'Alert']
        print("⚠️ Using minimal model imports")
    except ImportError as e2:
        print(f"❌ Critical model import error: {e2}")
        raise