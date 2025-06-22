# app/models/__init__.py - FIXED VERSION
"""
Database Models Package - FIXED IMPORTS
All models properly imported with error handling
"""

import logging
logger = logging.getLogger(__name__)

# Import models with error handling
models_imported = {}

try:
    from .agent import Agent
    models_imported['Agent'] = True
    logger.debug("✅ Agent model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import Agent model: {e}")
    models_imported['Agent'] = False

try:
    from .event import Event
    models_imported['Event'] = True
    logger.debug("✅ Event model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import Event model: {e}")
    models_imported['Event'] = False

try:
    from .alert import Alert
    models_imported['Alert'] = True
    logger.debug("✅ Alert model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import Alert model: {e}")
    models_imported['Alert'] = False

try:
    from .threat import Threat
    models_imported['Threat'] = True
    logger.debug("✅ Threat model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import Threat model: {e}")
    models_imported['Threat'] = False

try:
    from .detection_rule import DetectionRule
    models_imported['DetectionRule'] = True
    logger.debug("✅ DetectionRule model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import DetectionRule model: {e}")
    models_imported['DetectionRule'] = False

try:
    from .system_config import SystemConfig
    models_imported['SystemConfig'] = True
    logger.debug("✅ SystemConfig model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import SystemConfig model: {e}")
    models_imported['SystemConfig'] = False

try:
    from .agent_config import AgentConfig
    models_imported['AgentConfig'] = True
    logger.debug("✅ AgentConfig model imported")
except ImportError as e:
    logger.error(f"❌ Failed to import AgentConfig model: {e}")
    models_imported['AgentConfig'] = False

# Only export successfully imported models
__all__ = []
if models_imported.get('Agent'):
    __all__.append('Agent')
if models_imported.get('Event'):
    __all__.append('Event')
if models_imported.get('Alert'):
    __all__.append('Alert')
if models_imported.get('Threat'):
    __all__.append('Threat')
if models_imported.get('DetectionRule'):
    __all__.append('DetectionRule')
if models_imported.get('SystemConfig'):
    __all__.append('SystemConfig')
if models_imported.get('AgentConfig'):
    __all__.append('AgentConfig')

# Log import summary
successful_imports = sum(models_imported.values())
total_models = len(models_imported)

if successful_imports == total_models:
    logger.info(f"✅ All {total_models} models imported successfully")
elif successful_imports > 0:
    logger.warning(f"⚠️ {successful_imports}/{total_models} models imported successfully")
    logger.warning(f"Failed models: {[k for k, v in models_imported.items() if not v]}")
else:
    logger.error(f"❌ No models imported successfully")

# Helper function to check if all models are available
def all_models_available() -> bool:
    """Check if all models are available"""
    return all(models_imported.values())

def get_available_models() -> list:
    """Get list of available models"""
    return [k for k, v in models_imported.items() if v]

def get_unavailable_models() -> list:
    """Get list of unavailable models"""
    return [k for k, v in models_imported.items() if not v]