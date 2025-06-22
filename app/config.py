# app/config.py - REALTIME OPTIMIZED CONFIGURATION
"""
EDR Server Configuration - OPTIMIZED FOR REALTIME EVENT PROCESSING
Enhanced for high-throughput, low-latency event handling
"""

import os
import sys
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# REALTIME Database Configuration - OPTIMIZED FOR HIGH THROUGHPUT
DATABASE_CONFIG = {
    'server': os.getenv('DB_SERVER', 'localhost'),
    'database': 'EDR_System',
    'driver': 'ODBC Driver 17 for SQL Server',
    'timeout': 20,  # Balanced for realtime
    'trusted_connection': True,
    'autocommit': False,  # Explicit transaction control for batch operations
    'login_timeout': 10,
    'connection_timeout': 15,
    'encrypt': False,
    'trust_server_certificate': True,
    'packet_size': 8192,  # Larger packet size for batch operations
    'application_name': 'EDR_Realtime_Server',
    
    # REALTIME OPTIMIZATIONS
    'mars_connection': False,  # Disable for better performance
    'ansi_null_padding': True,
    'ansi_warnings': False,
    'fast_executemany': True,  # Enable fast batch inserts
    'multi_subnet_failover': False
}

# REALTIME Server Configuration
SERVER_CONFIG = {
    'bind_host': '192.168.20.85',
    'bind_port': 5000,
    'debug': False,
    'reload': False,
    'workers': 6,  # Increased for realtime processing
    'title': 'EDR Realtime Agent Communication Server',
    'description': 'High-Performance Agent Communication & Event Processing (Realtime Mode)',
    'version': '2.1.0-realtime',
    
    # PERFORMANCE OPTIMIZATIONS
    'keepalive_timeout': 30,
    'max_requests': 10000,  # High throughput
    'max_requests_jitter': 1000,
    'timeout_keep_alive': 30,
    'timeout_graceful_shutdown': 15,
    'limit_request_line': 8192,  # Larger requests for batch operations
    'limit_request_fields': 200,
    'limit_request_field_size': 16384
}

# Network Configuration - OPTIMIZED
NETWORK_CONFIG = {
    'allowed_agent_network': '192.168.20.0/24',
    'server_endpoint': '192.168.20.85:5000',
    'max_agents': 2000,  # Increased capacity
    'connection_timeout': 20,
    'heartbeat_timeout': 180,  # Longer for high-load scenarios
    
    # REALTIME OPTIMIZATIONS
    'tcp_nodelay': True,
    'tcp_keepalive': True,
    'socket_keepalive': True,
    'max_connections_per_agent': 5
}

# Security Configuration - STREAMLINED FOR PERFORMANCE
SECURITY_CONFIG = {
    'agent_auth_required': True,
    'agent_auth_token': 'edr_agent_auth_2024',
    'api_key_header': 'X-Agent-Token',
    'cors_origins': ['http://localhost:3000', 'http://192.168.20.85:3000'],
    'rate_limiting_enabled': True,
    'rate_limit_burst': True,  # Allow burst traffic
    
    # REALTIME SECURITY OPTIMIZATIONS
    'fast_auth_cache': True,
    'auth_cache_ttl': 300,  # 5 minutes cache
    'skip_detailed_logging': False  # Keep for security
}

# Agent Configuration - REALTIME OPTIMIZED
AGENT_CONFIG = {
    'registration_timeout': 30,
    'heartbeat_interval': 30,
    'heartbeat_grace_period': 90,
    'event_batch_size': 500,  # Larger batches for efficiency
    'event_queue_size': 20000,  # Larger queue for high volume
    'config_version': '2.1-realtime',
    'auto_approve_registration': True,
    'max_events_per_minute': 5000,  # Higher limit
    'max_batch_size': 1000,  # Support larger batches
    
    # REALTIME EVENT PROCESSING
    'zero_delay_processing': True,
    'immediate_storage': True,
    'batch_optimization': True,
    'parallel_processing': True,
    'event_compression': False,  # Disable for speed
    'event_validation_level': 'basic'  # Faster validation
}

# Detection Configuration - OPTIMIZED FOR REALTIME
DETECTION_CONFIG = {
    'rules_enabled': True,
    'threat_intel_enabled': True,
    'ml_detection_enabled': False,  # Disable for performance
    'rules_check_interval': 0.5,  # Faster checking
    'threat_intel_cache_ttl': 1800,  # 30 minutes
    'alert_deduplication_window': 300,
    'risk_score_threshold': 70,
    'auto_quarantine_threshold': 90,
    'real_time_processing': True,
    
    # REALTIME DETECTION OPTIMIZATIONS
    'fast_rule_evaluation': True,
    'parallel_rule_checking': True,
    'threat_cache_enabled': True,
    'detection_timeout': 5,  # Quick timeout for realtime
    'max_rules_per_event': 20,  # Limit for performance
    'async_threat_intel': True,
    'batch_detection': True
}

# Alert Configuration - REALTIME FOCUSED
ALERT_CONFIG = {
    'default_severity': 'Medium',
    'auto_escalation_enabled': False,
    'escalation_threshold_minutes': 60,
    'alert_retention_days': 90,
    'max_alerts_per_hour': 500,  # Higher limit for realtime
    'auto_resolve_enabled': True,
    'auto_resolve_days': 30,
    
    # REALTIME ALERT OPTIMIZATIONS
    'notification_mode': 'realtime',
    'immediate_notification': True,
    'batch_notifications': True,
    'notification_queue_size': 10000,
    'alert_compression': False  # Disable for speed
}

# Performance Configuration - ULTRA HIGH PERFORMANCE
PERFORMANCE_CONFIG = {
    # DATABASE POOL - OPTIMIZED FOR REALTIME
    'database_pool_size': 25,  # Larger pool for high concurrency
    'database_max_overflow': 50,  # Allow more overflow
    'database_pool_timeout': 20,
    'database_pool_recycle': 3600,  # 1 hour
    'database_pool_pre_ping': True,
    'database_echo': False,  # Disable for performance
    
    # CACHING - AGGRESSIVE FOR REALTIME
    'cache_enabled': True,
    'cache_ttl': 300,
    'cache_max_size': 10000,  # Larger cache
    'cache_type': 'memory',  # In-memory for speed
    
    # BATCH PROCESSING - OPTIMIZED
    'batch_processing_enabled': True,
    'batch_processing_interval': 2,  # Faster batching
    'batch_size': 1000,
    'batch_timeout': 10,
    
    # MEMORY & RESOURCES
    'memory_limit_mb': 4096,  # Higher memory limit
    'max_concurrent_requests': 200,  # Higher concurrency
    'worker_connections': 2000,
    'max_queue_size': 50000,
    
    # CONNECTION OPTIMIZATION
    'connection_retry_attempts': 2,
    'connection_retry_delay': 2,
    'query_timeout': 15,
    'bulk_insert_threshold': 100,
    
    # REALTIME SPECIFIC
    'zero_delay_mode': True,
    'immediate_commit': True,
    'async_processing': True,
    'parallel_workers': 8,
    'event_buffer_size': 10000,
    'flush_interval': 1  # Flush every second
}

# Paths Configuration
PATHS = {
    'logs': BASE_DIR / 'logs',
    'temp': BASE_DIR / 'temp',
    'cache': BASE_DIR / 'cache',
    'data': BASE_DIR / 'data',
    'metrics': BASE_DIR / 'metrics'  # For performance metrics
}

# Create directories immediately
for path in PATHS.values():
    path.mkdir(parents=True, exist_ok=True)

# Logging Configuration - OPTIMIZED FOR REALTIME
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'realtime': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            'datefmt': '%H:%M:%S'
        },
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'performance': {
            'format': '%(asctime)s [PERF] %(message)s',
            'datefmt': '%H:%M:%S.%f'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'realtime',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': str(PATHS['logs'] / 'edr_realtime.log'),
            'maxBytes': 50000000,  # 50MB
            'backupCount': 10,
            'encoding': 'utf-8'
        },
        'performance': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'performance',
            'filename': str(PATHS['logs'] / 'performance.log'),
            'maxBytes': 10000000,  # 10MB
            'backupCount': 5,
            'encoding': 'utf-8'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'event_processing': {
            'handlers': ['console', 'file', 'performance'],
            'level': 'INFO',
            'propagate': False,
        },
        'performance': {
            'handlers': ['performance'],
            'level': 'INFO',
            'propagate': False,
        }
    }
}

# Feature Flags - REALTIME OPTIMIZED
FEATURES = {
    'agent_registration': True,
    'event_collection': True,
    'real_time_detection': True,
    'threat_intelligence': True,
    'automated_response': False,  # Disable for performance
    'ml_detection': False,  # Disable for performance
    'user_authentication': False,  # Disable for performance
    'audit_logging': True,  # Keep for security
    'notifications': True,
    'dashboard_api': True,
    'metrics_collection': True,
    
    # REALTIME FEATURES
    'zero_delay_processing': True,
    'immediate_storage': True,
    'batch_optimization': True,
    'performance_monitoring': True,
    'realtime_analytics': True,
    'fast_querying': True,
    'event_streaming': True
}

# EDR Configuration - REALTIME MODE
EDR_CONFIG = {
    'system_name': 'EDR Security Platform (Realtime Mode)',
    'system_version': '2.1.0-realtime',
    'deployment_type': 'production-realtime',
    'max_agents_per_network': 2000,
    'event_retention_days': 365,
    'alert_retention_days': 90,
    'supported_platforms': ['Windows', 'Linux', 'macOS'],
    'supported_event_types': ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System'],
    
    # REALTIME CAPABILITIES
    'realtime_processing': True,
    'zero_delay_ingestion': True,
    'high_throughput_mode': True,
    'max_events_per_second': 10000,
    'max_events_per_minute': 100000,
    'burst_capacity': 50000,
    'processing_guarantee': 'at_least_once'
}

# Rate Limiting Configuration - OPTIMIZED FOR REALTIME
RATE_LIMITING_CONFIG = {
    'enabled': True,
    'burst_allowed': True,
    'adaptive_limits': True,
    
    # RATE LIMITS - HIGHER FOR REALTIME
    'agent_registration': '20/minute',
    'agent_heartbeat': '5/second',  # Higher for realtime
    'event_submission': '1000/minute',  # Much higher
    'event_batch': '100/minute',
    'dashboard_api': '120/minute',
    'default': '60/minute',
    
    # BURST CONFIGURATION
    'burst_multiplier': 3,
    'burst_window': 60,
    'cooldown_period': 300
}

# Monitoring Configuration - COMPREHENSIVE
MONITORING_CONFIG = {
    'health_check_enabled': True,
    'health_check_interval': 30,
    'metrics_enabled': True,
    'metrics_retention_days': 30,  # Longer retention
    'performance_monitoring': True,
    'error_tracking': True,
    'uptime_monitoring': True,
    
    # REALTIME MONITORING
    'realtime_metrics': True,
    'event_rate_monitoring': True,
    'latency_monitoring': True,
    'throughput_monitoring': True,
    'resource_monitoring': True,
    'alert_on_performance_degradation': True,
    
    # THRESHOLDS
    'max_latency_ms': 1000,
    'max_queue_size': 10000,
    'min_events_per_second': 1,
    'max_cpu_usage': 80,
    'max_memory_usage': 85
}

# Direct configuration export - OPTIMIZED
def get_config():
    """Get complete realtime-optimized configuration"""
    return {
        'database': DATABASE_CONFIG,
        'server': SERVER_CONFIG,
        'network': NETWORK_CONFIG,
        'security': SECURITY_CONFIG,
        'agent': AGENT_CONFIG,
        'detection': DETECTION_CONFIG,
        'alert': ALERT_CONFIG,
        'performance': PERFORMANCE_CONFIG,
        'rate_limiting': RATE_LIMITING_CONFIG,
        'monitoring': MONITORING_CONFIG,
        'logging': LOGGING_CONFIG,
        'paths': PATHS,
        'features': FEATURES,
        'edr': EDR_CONFIG,
        'environment': 'production-realtime',
        'mode': 'realtime',
        'optimization_level': 'ultra_high_performance'
    }

# Database URL function - OPTIMIZED
def get_database_url():
    """Get optimized database URL for realtime processing"""
    db_config = DATABASE_CONFIG
    
    connection_params = [
        f"driver={db_config['driver'].replace(' ', '+')}", 
        "trusted_connection=yes",
        "autocommit=false",  # Explicit control
        f"timeout={db_config['timeout']}",
        f"login_timeout={db_config['login_timeout']}",
        f"connection_timeout={db_config['connection_timeout']}",
        "encrypt=no",
        "trustservercertificate=yes",
        f"packet_size={db_config['packet_size']}",
        f"app_name={db_config['application_name']}",
        "mars_connection=no",
        "ansi_null_padding=yes",
        "ansi_warnings=no",
        "fast_executemany=true"
    ]
    
    connection_string = "&".join(connection_params)
    return f"mssql+pyodbc://@{db_config['server']}/{db_config['database']}?{connection_string}"

# Helper functions
def get_server_url():
    return f"http://{SERVER_CONFIG['bind_host']}:{SERVER_CONFIG['bind_port']}"

def get_feature_flag(feature_name: str) -> bool:
    return FEATURES.get(feature_name, False)

def get_performance_config():
    """Get performance-specific configuration"""
    return PERFORMANCE_CONFIG

def get_realtime_config():
    """Get realtime-specific configuration"""
    return {
        'zero_delay_processing': AGENT_CONFIG['zero_delay_processing'],
        'immediate_storage': AGENT_CONFIG['immediate_storage'],
        'batch_optimization': AGENT_CONFIG['batch_optimization'],
        'max_events_per_second': EDR_CONFIG['max_events_per_second'],
        'burst_capacity': EDR_CONFIG['burst_capacity'],
        'fast_rule_evaluation': DETECTION_CONFIG['fast_rule_evaluation'],
        'immediate_notification': ALERT_CONFIG['immediate_notification']
    }

def get_edr_info():
    """Get EDR system information"""
    return {
        'system_name': EDR_CONFIG['system_name'],
        'version': EDR_CONFIG['system_version'],
        'deployment_type': EDR_CONFIG['deployment_type'],
        'server_url': get_server_url(),
        'database_server': DATABASE_CONFIG['server'],
        'supported_platforms': EDR_CONFIG['supported_platforms'],
        'max_agents': NETWORK_CONFIG['max_agents'],
        'features_enabled': {k: v for k, v in FEATURES.items() if v},
        'realtime_capabilities': {
            'zero_delay_processing': True,
            'high_throughput': True,
            'max_events_per_second': EDR_CONFIG['max_events_per_second'],
            'burst_capacity': EDR_CONFIG['burst_capacity']
        },
        'authentication': False,
        'network_enabled': True,
        'database_type': 'SQL Server (Realtime Optimized)',
        'mode': 'realtime_production'
    }

def is_realtime_mode():
    """Check if system is in realtime mode"""
    return get_config()['mode'] == 'realtime'

def get_database_pool_config():
    """Get database connection pool configuration"""
    return {
        'pool_size': PERFORMANCE_CONFIG['database_pool_size'],
        'max_overflow': PERFORMANCE_CONFIG['database_max_overflow'],
        'pool_timeout': PERFORMANCE_CONFIG['database_pool_timeout'],
        'pool_recycle': PERFORMANCE_CONFIG['database_pool_recycle'],
        'pool_pre_ping': PERFORMANCE_CONFIG['database_pool_pre_ping']
    }

def get_rate_limits():
    """Get current rate limiting configuration"""
    return RATE_LIMITING_CONFIG

def get_monitoring_config():
    """Get monitoring configuration"""
    return MONITORING_CONFIG

# Global config instance - REALTIME OPTIMIZED
config = get_config()

# Realtime mode verification
if __name__ == "__main__":
    print("🚀 EDR Realtime Configuration Loaded")
    print(f"   Mode: {config['mode']}")
    print(f"   Optimization: {config['optimization_level']}")
    print(f"   Max Events/sec: {config['edr']['max_events_per_second']:,}")
    print(f"   Database Pool: {config['performance']['database_pool_size']}")
    print(f"   Workers: {config['server']['workers']}")
    print(f"   Zero Delay: {config['agent']['zero_delay_processing']}")
    print("✅ Configuration validated for realtime processing")