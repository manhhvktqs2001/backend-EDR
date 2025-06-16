"""
EDR Server Configuration
Complete configuration for Agent Communication Server
"""

import os
from pathlib import Path
from typing import List

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database Configuration - EDR_System database
DATABASE_CONFIG = {
    'server': 'MANH',  # SQL Server instance
    'database': 'EDR_System',
    'driver': 'ODBC Driver 17 for SQL Server',
    'timeout': 30,
    'trusted_connection': True,
    'autocommit': True
}

# Server Configuration - Agent Communication Server
SERVER_CONFIG = {
    'bind_host': '192.168.20.85',  # Server binds to this IP
    'bind_port': 5000,             # Server listens on this port
    'debug': True,
    'reload': True,
    'workers': 1,
    'title': 'EDR Agent Communication Server',
    'description': 'Agent Registration, Event Collection & Detection Engine',
    'version': '1.0.0'
}

# Network Security Configuration
NETWORK_CONFIG = {
    'allowed_agent_network': '192.168.20.0/24',  # Accept agents from this network
    'server_endpoint': '192.168.20.85:5000',     # What agents connect to
    'max_agents': 1000,                          # Maximum number of agents
    'connection_timeout': 30,                    # Connection timeout seconds
    'heartbeat_timeout': 300                     # 5 minutes agent timeout
}

# Security Configuration
SECURITY_CONFIG = {
    'agent_auth_required': True,
    'agent_auth_token': 'edr_agent_auth_2024',
    'api_key_header': 'X-API-Key',
    'cors_origins': [
        'http://localhost:3000',      # Dashboard development
        'http://127.0.0.1:3000',      # Dashboard local
        'http://192.168.20.85:3000'   # Dashboard production
    ],
    'trusted_proxies': ['192.168.20.0/24']
}

# Agent Configuration
AGENT_CONFIG = {
    'registration_timeout': 60,      # Agent registration timeout
    'heartbeat_interval': 30,        # Expected heartbeat interval (seconds)
    'heartbeat_grace_period': 90,    # Grace period before marking offline
    'event_batch_size': 100,         # Maximum events per batch
    'event_queue_size': 10000,       # Maximum queued events per agent
    'config_version': '1.0',         # Agent configuration version
    'auto_approve_registration': True, # Auto-approve new agents
    'require_agent_certificate': False # Certificate-based auth (future)
}

# Detection Engine Configuration
DETECTION_CONFIG = {
    'rules_enabled': True,
    'threat_intel_enabled': True,
    'ml_detection_enabled': False,    # Future ML integration
    'rules_check_interval': 1,        # Check rules every N seconds
    'threat_intel_cache_ttl': 3600,   # Cache threat intel for 1 hour
    'alert_deduplication_window': 300, # 5 minutes dedup window
    'max_alerts_per_agent': 1000,     # Max alerts per agent per day
    'risk_score_threshold': 70,       # Alert threshold (0-100)
    'auto_quarantine_threshold': 90   # Auto-quarantine threshold
}

# Alert Configuration
ALERT_CONFIG = {
    'default_severity': 'Medium',
    'auto_escalation_enabled': True,
    'escalation_threshold_minutes': 60,  # Escalate after 1 hour
    'alert_retention_days': 90,
    'max_alerts_per_hour': 100,
    'notification_enabled': False,      # Future email/SMS notifications
    'webhook_enabled': False            # Future webhook integration
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'database_pool_size': 10,
    'database_max_overflow': 20,
    'database_pool_timeout': 30,
    'cache_enabled': True,
    'cache_ttl': 300,                   # 5 minutes cache
    'batch_processing_enabled': True,
    'batch_processing_interval': 5,     # Process batches every 5 seconds
    'background_tasks_enabled': True
}

# Logging Configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        },
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s',
        },
        'json': {
            'format': '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'default',
        },
        'file_main': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': BASE_DIR / 'logs' / 'server.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
        },
        'file_detection': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'detailed',
            'filename': BASE_DIR / 'logs' / 'detection.log',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_agents': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'default',
            'filename': BASE_DIR / 'logs' / 'agents.log',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_errors': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'ERROR',
            'formatter': 'detailed',
            'filename': BASE_DIR / 'logs' / 'errors.log',
            'maxBytes': 10485760,
            'backupCount': 5,
        }
    },
    'loggers': {
        '': {  # Root logger
            'handlers': ['console', 'file_main'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'uvicorn': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'detection_engine': {
            'handlers': ['console', 'file_detection'],
            'level': 'INFO',
            'propagate': False,
        },
        'agent_communication': {
            'handlers': ['console', 'file_agents'],
            'level': 'INFO',
            'propagate': False,
        },
        'error': {
            'handlers': ['file_errors'],
            'level': 'ERROR',
            'propagate': False,
        }
    },
}

# Paths Configuration
PATHS = {
    'logs': BASE_DIR / 'logs',
    'static': BASE_DIR / 'static',
    'temp': BASE_DIR / 'temp',
    'uploads': BASE_DIR / 'uploads',
    'exports': BASE_DIR / 'exports'
}

# Development vs Production Settings
def get_environment_config():
    """Get configuration based on environment"""
    env = os.getenv('EDR_ENV', 'development')
    
    if env == 'production':
        # Production settings
        SERVER_CONFIG.update({
            'debug': False,
            'reload': False,
            'workers': 4
        })
        LOGGING_CONFIG['handlers']['console']['level'] = 'WARNING'
        DETECTION_CONFIG['rules_check_interval'] = 0.5  # Faster detection
        PERFORMANCE_CONFIG['cache_ttl'] = 600  # Longer cache
        
    elif env == 'testing':
        # Testing settings
        DATABASE_CONFIG['database'] = 'EDR_System_Test'
        SERVER_CONFIG['bind_port'] = 5001
        AGENT_CONFIG['heartbeat_interval'] = 10
        DETECTION_CONFIG['alert_deduplication_window'] = 60
        
    return env

# Feature Flags
FEATURES = {
    'agent_registration': True,
    'event_collection': True,
    'real_time_detection': True,
    'threat_intelligence': True,
    'automated_response': False,    # Future feature
    'ml_detection': False,          # Future feature
    'file_quarantine': False,       # Future feature
    'network_isolation': False,     # Future feature
    'forensic_collection': False,   # Future feature
    'threat_hunting': False         # Future feature
}

# API Rate Limiting
RATE_LIMITING = {
    'enabled': True,
    'agent_registration': '10/minute',
    'agent_heartbeat': '2/second',
    'event_submission': '100/minute',
    'dashboard_api': '60/minute',
    'default': '30/minute'
}

# Monitoring & Health Check
MONITORING_CONFIG = {
    'health_check_enabled': True,
    'health_check_interval': 30,    # seconds
    'metrics_enabled': True,
    'metrics_retention_days': 7,
    'performance_monitoring': True,
    'error_tracking': True,
    'uptime_monitoring': True
}

# Export configuration
def get_config():
    """Get complete configuration"""
    env = get_environment_config()
    
    # Ensure directories exist
    for path in PATHS.values():
        path.mkdir(parents=True, exist_ok=True)
    
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
        'rate_limiting': RATE_LIMITING,
        'monitoring': MONITORING_CONFIG,
        'environment': env
    }

# Global config instance
config = get_config()

# Helper functions
def get_database_url():
    """Get database connection URL"""
    db_config = DATABASE_CONFIG
    return (
        f"mssql+pyodbc://@{db_config['server']}/{db_config['database']}?"
        f"driver={db_config['driver'].replace(' ', '+')}&"
        f"trusted_connection=yes&autocommit=true"
    )

def is_development():
    """Check if running in development mode"""
    return config['environment'] == 'development'

def is_production():
    """Check if running in production mode"""
    return config['environment'] == 'production'

def get_server_url():
    """Get full server URL"""
    server_config = config['server']
    return f"http://{server_config['bind_host']}:{server_config['bind_port']}"

def get_feature_flag(feature_name: str) -> bool:
    """Get feature flag status"""
    return FEATURES.get(feature_name, False)