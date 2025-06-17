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
    'server': os.getenv('DB_SERVER', 'MANH'),  # SQL Server instance
    'database': os.getenv('DB_DATABASE', 'EDR_System'),
    'driver': os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server'),
    'timeout': int(os.getenv('DB_TIMEOUT', '30')),
    'trusted_connection': os.getenv('DB_TRUSTED_CONNECTION', 'true').lower() == 'true',
    'autocommit': True
}

# Server Configuration - Agent Communication Server
SERVER_CONFIG = {
    'bind_host': os.getenv('SERVER_HOST', '192.168.20.85'),  # Server binds to this IP
    'bind_port': int(os.getenv('SERVER_PORT', '5000')),      # Server listens on this port
    'debug': os.getenv('SERVER_DEBUG', 'true').lower() == 'true',
    'reload': os.getenv('SERVER_RELOAD', 'true').lower() == 'true',
    'workers': int(os.getenv('SERVER_WORKERS', '1')),
    'title': 'EDR Agent Communication Server',
    'description': 'Agent Registration, Event Collection & Detection Engine',
    'version': '1.0.0'
}

# Network Security Configuration
NETWORK_CONFIG = {
    'allowed_agent_network': os.getenv('ALLOWED_AGENT_NETWORK', '192.168.20.0/24'),  # Accept agents from this network
    'server_endpoint': f"{SERVER_CONFIG['bind_host']}:{SERVER_CONFIG['bind_port']}",  # What agents connect to
    'max_agents': int(os.getenv('MAX_AGENTS', '1000')),                              # Maximum number of agents
    'connection_timeout': int(os.getenv('CONNECTION_TIMEOUT', '30')),                # Connection timeout seconds
    'heartbeat_timeout': int(os.getenv('HEARTBEAT_TIMEOUT', '300'))                  # 5 minutes agent timeout
}

# Security Configuration
SECURITY_CONFIG = {
    'agent_auth_required': True,
    'agent_auth_token': os.getenv('AGENT_AUTH_TOKEN', 'edr_agent_auth_2024'),
    'api_key_header': os.getenv('API_KEY_HEADER', 'X-API-Key'),
    'secret_key': os.getenv('SECRET_KEY', 'edr_server_secret_key_2024_change_in_production'),
    'cors_origins': os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000,http://192.168.20.85:3000').split(','),
    'trusted_proxies': ['192.168.20.0/24']
}

# Agent Configuration
AGENT_CONFIG = {
    'registration_timeout': 60,      # Agent registration timeout
    'heartbeat_interval': int(os.getenv('HEARTBEAT_INTERVAL', '30')),        # Expected heartbeat interval (seconds)
    'heartbeat_grace_period': 90,    # Grace period before marking offline
    'event_batch_size': int(os.getenv('EVENT_BATCH_SIZE', '100')),           # Maximum events per batch
    'event_queue_size': int(os.getenv('EVENT_QUEUE_SIZE', '10000')),         # Maximum queued events per agent
    'config_version': os.getenv('CONFIG_VERSION', '1.0'),                   # Agent configuration version
    'auto_approve_registration': os.getenv('AUTO_APPROVE_REGISTRATION', 'true').lower() == 'true',
    'require_agent_certificate': False # Certificate-based auth (future)
}

# Detection Engine Configuration
DETECTION_CONFIG = {
    'rules_enabled': os.getenv('RULES_ENABLED', 'true').lower() == 'true',
    'threat_intel_enabled': os.getenv('THREAT_INTEL_ENABLED', 'true').lower() == 'true',
    'ml_detection_enabled': os.getenv('ML_DETECTION_ENABLED', 'false').lower() == 'true',
    'rules_check_interval': int(os.getenv('RULES_CHECK_INTERVAL', '1')),        # Check rules every N seconds
    'threat_intel_cache_ttl': int(os.getenv('THREAT_INTEL_CACHE_TTL', '3600')), # Cache threat intel for 1 hour
    'alert_deduplication_window': int(os.getenv('ALERT_DEDUPLICATION_WINDOW', '300')), # 5 minutes dedup window
    'max_alerts_per_agent': 1000,     # Max alerts per agent per day
    'risk_score_threshold': int(os.getenv('RISK_SCORE_THRESHOLD', '70')),       # Alert threshold (0-100)
    'auto_quarantine_threshold': int(os.getenv('AUTO_QUARANTINE_THRESHOLD', '90')) # Auto-quarantine threshold
}

# Alert Configuration
ALERT_CONFIG = {
    'default_severity': os.getenv('DEFAULT_SEVERITY', 'Medium'),
    'auto_escalation_enabled': os.getenv('AUTO_ESCALATION_ENABLED', 'true').lower() == 'true',
    'escalation_threshold_minutes': int(os.getenv('ESCALATION_THRESHOLD_MINUTES', '60')),  # Escalate after 1 hour
    'alert_retention_days': int(os.getenv('ALERT_RETENTION_DAYS', '90')),
    'max_alerts_per_hour': int(os.getenv('MAX_ALERTS_PER_HOUR', '100')),
    'notification_enabled': False,      # Future email/SMS notifications
    'webhook_enabled': False            # Future webhook integration
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'database_pool_size': int(os.getenv('DATABASE_POOL_SIZE', '10')),
    'database_max_overflow': int(os.getenv('DATABASE_MAX_OVERFLOW', '20')),
    'database_pool_timeout': int(os.getenv('DATABASE_POOL_TIMEOUT', '30')),
    'cache_enabled': os.getenv('CACHE_ENABLED', 'true').lower() == 'true',
    'cache_ttl': int(os.getenv('CACHE_TTL', '300')),                   # 5 minutes cache
    'batch_processing_enabled': os.getenv('BATCH_PROCESSING_ENABLED', 'true').lower() == 'true',
    'batch_processing_interval': int(os.getenv('BATCH_PROCESSING_INTERVAL', '5')),     # Process batches every 5 seconds
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
            'level': os.getenv('LOG_LEVEL', 'INFO'),
            'formatter': 'default',
        },
        'file_main': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': BASE_DIR / 'logs' / 'server.log',
            'maxBytes': int(os.getenv('LOG_MAX_SIZE', '10485760')),  # 10MB
            'backupCount': int(os.getenv('LOG_BACKUP_COUNT', '5')),
        },
        'file_detection': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'detailed',
            'filename': BASE_DIR / 'logs' / 'detection.log',
            'maxBytes': int(os.getenv('LOG_MAX_SIZE', '10485760')),
            'backupCount': int(os.getenv('LOG_BACKUP_COUNT', '5')),
        },
        'file_agents': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'default',
            'filename': BASE_DIR / 'logs' / 'agents.log',
            'maxBytes': int(os.getenv('LOG_MAX_SIZE', '10485760')),
            'backupCount': int(os.getenv('LOG_BACKUP_COUNT', '5')),
        },
        'file_errors': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'ERROR',
            'formatter': 'detailed',
            'filename': BASE_DIR / 'logs' / 'errors.log',
            'maxBytes': int(os.getenv('LOG_MAX_SIZE', '10485760')),
            'backupCount': int(os.getenv('LOG_BACKUP_COUNT', '5')),
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
    'exports': BASE_DIR / 'exports',
    'data': BASE_DIR / 'data'
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
    'agent_registration': os.getenv('FEATURE_AGENT_REGISTRATION', 'true').lower() == 'true',
    'event_collection': os.getenv('FEATURE_EVENT_COLLECTION', 'true').lower() == 'true',
    'real_time_detection': os.getenv('FEATURE_REAL_TIME_DETECTION', 'true').lower() == 'true',
    'threat_intelligence': os.getenv('FEATURE_THREAT_INTELLIGENCE', 'true').lower() == 'true',
    'automated_response': os.getenv('FEATURE_AUTOMATED_RESPONSE', 'false').lower() == 'true',
    'ml_detection': os.getenv('FEATURE_ML_DETECTION', 'false').lower() == 'true',
    'file_quarantine': os.getenv('FEATURE_FILE_QUARANTINE', 'false').lower() == 'true',
    'network_isolation': os.getenv('FEATURE_NETWORK_ISOLATION', 'false').lower() == 'true',
    'forensic_collection': os.getenv('FEATURE_FORENSIC_COLLECTION', 'false').lower() == 'true',
    'threat_hunting': os.getenv('FEATURE_THREAT_HUNTING', 'false').lower() == 'true'
}

# API Rate Limiting
RATE_LIMITING = {
    'enabled': os.getenv('RATE_LIMITING_ENABLED', 'true').lower() == 'true',
    'agent_registration': os.getenv('RATE_LIMIT_AGENT_REGISTRATION', '10/minute'),
    'agent_heartbeat': os.getenv('RATE_LIMIT_AGENT_HEARTBEAT', '2/second'),
    'event_submission': os.getenv('RATE_LIMIT_EVENT_SUBMISSION', '100/minute'),
    'dashboard_api': os.getenv('RATE_LIMIT_DASHBOARD_API', '60/minute'),
    'default': os.getenv('RATE_LIMIT_DEFAULT', '30/minute')
}

# Monitoring & Health Check
MONITORING_CONFIG = {
    'health_check_enabled': os.getenv('HEALTH_CHECK_ENABLED', 'true').lower() == 'true',
    'health_check_interval': int(os.getenv('HEALTH_CHECK_INTERVAL', '30')),    # seconds
    'metrics_enabled': os.getenv('METRICS_ENABLED', 'true').lower() == 'true',
    'metrics_retention_days': int(os.getenv('METRICS_RETENTION_DAYS', '7')),
    'performance_monitoring': os.getenv('PERFORMANCE_MONITORING', 'true').lower() == 'true',
    'error_tracking': os.getenv('ERROR_TRACKING', 'true').lower() == 'true',
    'uptime_monitoring': os.getenv('UPTIME_MONITORING', 'true').lower() == 'true'
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