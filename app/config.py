# config_ultra_fast.py - ULTRA SPEED (No Validation, Direct Values)
"""
EDR Server Configuration - ULTRA FAST VERSION  
No validation, no auto-detection, direct hardcoded optimal values
"""

import os
import sys
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Direct Database Configuration - NO VALIDATION
DATABASE_CONFIG = {
    'server': 'localhost',  # Direct - no fallback
    'database': 'EDR_System',
    'driver': 'ODBC Driver 17 for SQL Server',
    'timeout': 15,  # Faster timeout
    'trusted_connection': True,
    'autocommit': True,
    'login_timeout': 10,
    'connection_timeout': 10,
    'encrypt': False,
    'trust_server_certificate': True,
    'packet_size': 4096,
    'application_name': 'EDR_Agent_Server'
}

# Direct Server Configuration - NO ENV CHECKS
SERVER_CONFIG = {
    'bind_host': '192.168.20.85',
    'bind_port': 5000,
    'debug': False,
    'reload': False,
    'workers': 4,
    'title': 'EDR Agent Communication Server',
    'description': 'Agent Registration & Event Collection (Ultra Fast)',
    'version': '2.0.0'
}

# Direct Network Configuration  
NETWORK_CONFIG = {
    'allowed_agent_network': '192.168.20.0/24',
    'server_endpoint': '192.168.20.85:5000',
    'max_agents': 1000,
    'connection_timeout': 15,
    'heartbeat_timeout': 120
}

# Direct Security Configuration
SECURITY_CONFIG = {
    'agent_auth_required': True,
    'agent_auth_token': 'edr_agent_auth_2024',
    'api_key_header': 'X-Agent-Token',
    'cors_origins': ['http://localhost:3000', 'http://192.168.20.85:3000'],
    'rate_limiting_enabled': False  # Disabled for speed
}

# Direct Agent Configuration
AGENT_CONFIG = {
    'registration_timeout': 30,
    'heartbeat_interval': 30,
    'heartbeat_grace_period': 60,
    'event_batch_size': 100,
    'event_queue_size': 5000,
    'config_version': '2.0',
    'auto_approve_registration': True,
    'max_events_per_minute': 1000,
    'max_batch_size': 1000
}

# Direct Detection Configuration
DETECTION_CONFIG = {
    'rules_enabled': True,
    'threat_intel_enabled': True,
    'ml_detection_enabled': False,
    'rules_check_interval': 1.0,
    'threat_intel_cache_ttl': 1800,  # Shorter cache
    'alert_deduplication_window': 300,
    'risk_score_threshold': 70,
    'auto_quarantine_threshold': 90,
    'real_time_processing': True
}

# Direct Alert Configuration
ALERT_CONFIG = {
    'default_severity': 'Medium',
    'auto_escalation_enabled': False,
    'escalation_threshold_minutes': 60,
    'alert_retention_days': 90,
    'max_alerts_per_hour': 100,
    'auto_resolve_enabled': True,
    'auto_resolve_days': 30
}

# Direct Performance Configuration - OPTIMIZED
PERFORMANCE_CONFIG = {
    'database_pool_size': 8,  # Smaller for speed
    'database_max_overflow': 12,
    'database_pool_timeout': 15,
    'database_pool_recycle': 1800,
    'database_pool_pre_ping': True,
    'cache_enabled': True,
    'cache_ttl': 300,
    'batch_processing_enabled': True,
    'batch_processing_interval': 5,
    'memory_limit_mb': 2048,
    'max_concurrent_requests': 100,
    'connection_retry_attempts': 1,  # Single retry only
    'connection_retry_delay': 3,
    'query_timeout': 15
}

# Direct Paths Configuration
PATHS = {
    'logs': BASE_DIR / 'logs',
    'temp': BASE_DIR / 'temp',
    'cache': BASE_DIR / 'cache',
    'data': BASE_DIR / 'data'
}

# Create directories immediately - no error handling
for path in PATHS.values():
    path.mkdir(parents=True, exist_ok=True)

# Direct Logging Configuration - MINIMAL
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(asctime)s [%(levelname)s] %(message)s',
            'datefmt': '%H:%M:%S'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'simple',
            'stream': 'ext://sys.stdout'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        }
    }
}

# Direct Feature Flags - OPTIMIZED
FEATURES = {
    'agent_registration': True,
    'event_collection': True,
    'real_time_detection': True,
    'threat_intelligence': True,
    'automated_response': False,
    'ml_detection': False,
    'user_authentication': False,
    'audit_logging': False,
    'notifications': False
}

# Direct EDR Configuration
EDR_CONFIG = {
    'system_name': 'EDR Security Platform (Ultra Fast)',
    'system_version': '2.0.0',
    'deployment_type': 'production',
    'max_agents_per_network': 1000,
    'event_retention_days': 365,
    'alert_retention_days': 90,
    'supported_platforms': ['Windows', 'Linux'],
    'supported_event_types': ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
}

# Direct configuration export - NO VALIDATION
def get_config():
    """Get complete configuration - no validation"""
    return {
        'database': DATABASE_CONFIG,
        'server': SERVER_CONFIG,
        'network': NETWORK_CONFIG,
        'security': SECURITY_CONFIG,
        'agent': AGENT_CONFIG,
        'detection': DETECTION_CONFIG,
        'alert': ALERT_CONFIG,
        'performance': PERFORMANCE_CONFIG,
        'logging': LOGGING_CONFIG,
        'paths': PATHS,
        'features': FEATURES,
        'edr': EDR_CONFIG,
        'environment': 'production'
    }

# Direct database URL function - NO VALIDATION
def get_database_url():
    """Get database URL directly"""
    db_config = DATABASE_CONFIG
    
    connection_params = [
        "driver=ODBC+Driver+17+for+SQL+Server", 
        "trusted_connection=yes",
        "autocommit=true",
        "timeout=15",
        "login_timeout=10",
        "encrypt=no",
        "trustservercertificate=yes",
        "packet_size=4096",
        "app_name=EDR_Agent_Server"
    ]
    
    connection_string = "&".join(connection_params)
    return f"mssql+pyodbc://@{db_config['server']}/{db_config['database']}?{connection_string}"

# Direct helper functions - NO VALIDATION
def get_server_url():
    return f"http://{SERVER_CONFIG['bind_host']}:{SERVER_CONFIG['bind_port']}"

def get_feature_flag(feature_name: str) -> bool:
    return FEATURES.get(feature_name, False)

def get_edr_info():
    return {
        'system_name': EDR_CONFIG['system_name'],
        'version': EDR_CONFIG['system_version'],
        'deployment_type': EDR_CONFIG['deployment_type'],
        'server_url': get_server_url(),
        'database_server': DATABASE_CONFIG['server'],
        'supported_platforms': EDR_CONFIG['supported_platforms'],
        'max_agents': NETWORK_CONFIG['max_agents'],
        'features_enabled': {k: v for k, v in FEATURES.items() if v},
        'authentication': False,
        'network_enabled': True,
        'database_type': 'SQL Server (Direct)'
    }

# Global config instance - NO VALIDATION  
config = get_config()