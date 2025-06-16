"""
EDR Agent Communication Server Startup Script
Starts the FastAPI server on 192.168.20.85:5000
"""

import os
import sys
import logging
import uvicorn
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from app.config import config
from app.database import get_database_status

def setup_logging():
    """Setup basic logging for startup"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def check_environment():
    """Check if environment is ready for server startup"""
    logger = logging.getLogger(__name__)
    
    logger.info("🔍 Checking environment...")
    
    # Create required directories
    for path_name, path in config['paths'].items():
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
            logger.info(f"📁 Created directory: {path}")
    
    # Test database connection
    logger.info("🗃️  Testing database connection...")
    db_status = get_database_status()
    
    if not db_status.get('healthy'):
        logger.error("❌ Database connection failed!")
        logger.error(f"Database error: {db_status.get('errors', [])}")
        return False
    
    logger.info(f"✅ Database connected: {db_status.get('database_info', {}).get('database_name')}")
    
    # Check table counts
    table_counts = db_status.get('table_counts', {})
    for table, count in table_counts.items():
        logger.info(f"📊 Table {table}: {count} records")
    
    return True

def print_server_info():
    """Print server information"""
    logger = logging.getLogger(__name__)
    
    server_config = config['api_server']
    network_config = config['network']
    
    print("\n" + "="*60)
    print("🚀 EDR AGENT COMMUNICATION SERVER")
    print("="*60)
    print(f"📍 Server Address: {server_config['bind_host']}:{server_config['bind_port']}")
    print(f"🌐 Agents connect to: http://{server_config['bind_host']}:{server_config['bind_port']}")
    print(f"🔒 Allowed Network: {network_config['allowed_agent_network']}")
    print(f"🗃️  Database: {config['database']['server']}/{config['database']['database']}")
    print(f"🌍 Environment: {config['environment']}")
    print(f"🛡️  Detection Engine: {'Enabled' if config['detection']['rules_enabled'] else 'Disabled'}")
    print(f"📊 Threat Intel: {'Enabled' if config['detection']['threat_intel_enabled'] else 'Disabled'}")
    print("="*60)
    print("📋 API Endpoints:")
    print(f"  • Health Check: http://{server_config['bind_host']}:{server_config['bind_port']}/health")
    print(f"  • API Docs: http://{server_config['bind_host']}:{server_config['bind_port']}/docs")
    print(f"  • Agent Registration: POST /api/v1/agents/register")
    print(f"  • Agent Heartbeat: POST /api/v1/agents/heartbeat") 
    print(f"  • Event Submission: POST /api/v1/events/submit")
    print(f"  • Dashboard Data: GET /api/v1/dashboard/*")
    print("="*60)
    print("🔧 Configuration:")
    print(f"  • Heartbeat Interval: {config['agent']['heartbeat_interval']}s")
    print(f"  • Event Batch Size: {config['agent']['event_batch_size']}")
    print(f"  • Risk Threshold: {config['detection']['risk_score_threshold']}")
    print("="*60 + "\n")

def main():
    """Main server startup function"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("🚀 Starting EDR Agent Communication Server...")
    
    # Print server information
    print_server_info()
    
    # Check environment
    if not check_environment():
        logger.error("❌ Environment check failed")
        sys.exit(1)
    
    # Set environment variable
    os.environ['EDR_ENV'] = config['environment']
    
    # Get server configuration
    server_config = config['api_server']
    
    try:
        logger.info(f"🌐 Starting server on {server_config['bind_host']}:{server_config['bind_port']}")
        
        # Start server
        uvicorn.run(
            "app.main:app",
            host=server_config['bind_host'],
            port=server_config['bind_port'],
            reload=server_config['reload'],
            workers=server_config['workers'],
            log_level="info",
            access_log=True,
            server_header=False,
            date_header=False
        )
        
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user (Ctrl+C)")
        
    except Exception as e:
        logger.error(f"❌ Server startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()