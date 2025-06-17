# run_server.py - Final Fixed Version
"""
EDR Agent Communication Server Launcher
Standalone server runner with proper initialization and logging
"""

import os
import sys
import logging
import logging.config
import uvicorn
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Import configuration after path setup
try:
    from app.config import config, get_database_url
    from app.database import init_database
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all __init__.py files are created and app structure is correct")
    sys.exit(1)

def setup_logging():
    """Setup logging configuration"""
    try:
        # Configure logging using the config
        logging.config.dictConfig(config['logging'])
        logger = logging.getLogger(__name__)
        logger.info("Logging configured successfully")
        return logger
    except Exception as e:
        # Fallback to basic logging if config fails
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('server.log', encoding='utf-8')
            ]
        )
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to configure logging: {e}")
        return logger

def print_banner(logger):
    """Print server banner with configuration info"""
    banner = f"""
============================================================
🚀 EDR AGENT COMMUNICATION SERVER
============================================================
📍 Server Address: {config['server']['bind_host']}:{config['server']['bind_port']}
🌐 Agents connect to: http://{config['server']['bind_host']}:{config['server']['bind_port']}
🔒 Allowed Network: {config['network']['allowed_agent_network']}
🗃️  Database: {config['database']['server']}/{config['database']['database']}
🌍 Environment: {config['environment']}
🛡️  Detection Engine: {'Enabled' if config['detection']['rules_enabled'] else 'Disabled'}
📊 Threat Intel: {'Enabled' if config['detection']['threat_intel_enabled'] else 'Disabled'}
============================================================
📋 API Endpoints:
  • Health Check: http://{config['server']['bind_host']}:{config['server']['bind_port']}/health
  • API Docs: http://{config['server']['bind_host']}:{config['server']['bind_port']}/docs
  • Agent Registration: POST /api/v1/agents/register
  • Agent Heartbeat: POST /api/v1/agents/heartbeat
  • Event Submission: POST /api/v1/events/submit
  • Dashboard Data: GET /api/v1/dashboard/*
============================================================
🔧 Configuration:
  • Heartbeat Interval: {config['agent']['heartbeat_interval']}s
  • Event Batch Size: {config['agent']['event_batch_size']}
  • Risk Threshold: {config['detection']['risk_score_threshold']}
============================================================
"""
    logger.info(banner)

def check_environment(logger):
    """Check environment and dependencies"""
    logger.info("🔍 Checking environment...")
    
    # Check required directories
    for path_name, path in config['paths'].items():
        if not path.exists():
            logger.info(f"Creating directory: {path}")
            path.mkdir(parents=True, exist_ok=True)
    
    # Check database configuration
    logger.info("🗃️  Testing database connection...")
    if not init_database():
        logger.error("❌ Database initialization failed")
        return False
    
    logger.info("✅ Environment check completed")
    return True

def get_database_info(logger):
    """Get and display database information"""
    try:
        from app.database import get_database_status
        
        db_status = get_database_status()
        
        if db_status.get('healthy'):
            db_info = db_status.get('database_info', {})
            logger.info(f"✅ Database connected: {db_info.get('database_name')} on {db_info.get('server_name')}")
            
            # Log table counts
            table_counts = db_status.get('table_counts', {})
            for table, count in table_counts.items():
                logger.info(f"📊 Table {table}: {count} records")
        else:
            logger.error("❌ Database connection failed")
            return False
            
    except Exception as e:
        logger.error(f"Database info error: {e}")
        return False
    
    return True

def main():
    """Main server entry point"""
    try:
        # Setup logging first
        logger = setup_logging()
        logger.info("🚀 Starting EDR Agent Communication Server...")
        
        # Print banner
        print_banner(logger)
        
        # Check environment
        if not check_environment(logger):
            logger.error("❌ Environment check failed")
            sys.exit(1)
        
        # Get database info
        if not get_database_info(logger):
            logger.error("❌ Database check failed")
            sys.exit(1)
        
        # Start server
        server_config = config['server']
        logger.info(f"🌐 Starting server on {server_config['bind_host']}:{server_config['bind_port']}")
        
        # Run uvicorn server - FIXED: Removed debug parameter
        uvicorn.run(
            "app.main:app",
            host=server_config['bind_host'],
            port=server_config['bind_port'],
            reload=server_config['reload'],
            log_level="info",
            access_log=True,
            use_colors=True
        )
        
    except KeyboardInterrupt:
        logger.info("👋 Server shutdown requested")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please create missing __init__.py files:")
        print("- app/__init__.py")
        print("- app/api/__init__.py")
        print("- app/api/v1/__init__.py")
        print("- app/models/__init__.py")
        print("- app/schemas/__init__.py")
        print("- app/services/__init__.py")
        print("- app/utils/__init__.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()