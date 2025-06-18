# run_server.py - EDR Server Launcher (Updated)
"""
EDR Agent Communication Server Launcher
Updated for simplified database schema (no authentication)
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
    from app.config import config, get_database_url, get_edr_info
    from app.database import init_database
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all required files exist and app structure is correct")
    sys.exit(1)

def setup_logging():
    """Setup logging configuration for EDR system"""
    try:
        # Configure logging using the config
        logging.config.dictConfig(config['logging'])
        logger = logging.getLogger(__name__)
        logger.info("✅ Logging configured successfully")
        return logger
    except Exception as e:
        # Fallback to basic logging if config fails
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('edr_server.log', encoding='utf-8')
            ]
        )
        logger = logging.getLogger(__name__)
        logger.error(f"⚠️ Failed to configure advanced logging: {e}")
        logger.info("📝 Using fallback logging configuration")
        return logger

def print_edr_banner(logger):
    """Print EDR server banner with configuration info"""
    edr_info = get_edr_info()
    server_config = config['server']
    
    banner = f"""
════════════════════════════════════════════════════════════════
🛡️  EDR AGENT COMMUNICATION SERVER - {edr_info['version']}
════════════════════════════════════════════════════════════════
🚀 Server Details:
   • Host: {server_config['bind_host']}:{server_config['bind_port']}
   • Environment: {config['environment'].upper()}
   • Deployment: {edr_info['deployment_type'].title()}
   • Authentication: {edr_info['authentication']} (Simplified Version)

🌐 Network Configuration:
   • Allowed Network: {config['network']['allowed_agent_network']}
   • Max Agents: {config['network']['max_agents']:,}
   • Agent URL: http://{server_config['bind_host']}:{server_config['bind_port']}

🗄️  Database Configuration:
   • Server: {config['database']['server']}
   • Database: {config['database']['database']}
   • Connection: Trusted ({config['database']['driver']})

🛡️  Detection & Security:
   • Detection Engine: {'✅ Enabled' if config['detection']['rules_enabled'] else '❌ Disabled'}
   • Threat Intelligence: {'✅ Enabled' if config['detection']['threat_intel_enabled'] else '❌ Disabled'}
   • Risk Threshold: {config['detection']['risk_score_threshold']}
   • Real-time Processing: {'✅ Enabled' if config['features']['real_time_detection'] else '❌ Disabled'}

⚙️  Agent Configuration:
   • Heartbeat Interval: {config['agent']['heartbeat_interval']}s
   • Event Batch Size: {config['agent']['event_batch_size']:,}
   • Auto Registration: {'✅ Enabled' if config['agent']['auto_approve_registration'] else '❌ Disabled'}
   • Supported Platforms: {', '.join(edr_info['supported_platforms'])}

📡 API Endpoints:
   • Health Check: http://{server_config['bind_host']}:{server_config['bind_port']}/health
   • API Documentation: http://{server_config['bind_host']}:{server_config['bind_port']}/docs
   • Agent Discovery: http://{server_config['bind_host']}:{server_config['bind_port']}/api/discover
   • Agent Registration: POST /api/v1/agents/register
   • Agent Heartbeat: POST /api/v1/agents/heartbeat
   • Event Submission: POST /api/v1/events/submit
   • Dashboard API: GET /api/v1/dashboard/*

🎯 Features Enabled:
{chr(10).join([f'   • {feature.replace("_", " ").title()}: ✅' for feature, enabled in edr_info['features_enabled'].items() if enabled])}

📊 Monitoring:
   • Log Files: {config['paths']['logs']}
   • Performance Pool: {config['performance']['database_pool_size']} connections
   • Cache TTL: {config['performance']['cache_ttl']}s
════════════════════════════════════════════════════════════════
"""
    
    # Print to console
    print(banner)
    
    # Log the startup info
    logger.info("🛡️ EDR Agent Communication Server Starting Up")
    logger.info(f"🌐 Binding to: {server_config['bind_host']}:{server_config['bind_port']}")
    logger.info(f"🗄️ Database: {config['database']['server']}/{config['database']['database']}")
    logger.info(f"🛡️ Detection Engine: {'Enabled' if config['detection']['rules_enabled'] else 'Disabled'}")
    logger.info(f"📊 Threat Intelligence: {'Enabled' if config['detection']['threat_intel_enabled'] else 'Disabled'}")

def check_environment(logger):
    """Check environment and dependencies"""
    logger.info("🔍 Performing environment checks...")
    
    # Check required directories
    for path_name, path in config['paths'].items():
        if not path.exists():
            logger.info(f"📁 Creating directory: {path}")
            path.mkdir(parents=True, exist_ok=True)
        else:
            logger.debug(f"📁 Directory exists: {path}")
    
    # Check database configuration
    logger.info("🗄️ Testing database connection...")
    try:
        if not init_database():
            logger.error("❌ Database initialization failed")
            return False
        logger.info("✅ Database connection successful")
    except Exception as e:
        logger.error(f"❌ Database error: {e}")
        return False
    
    # Check feature flags
    logger.info("🎯 Checking feature configuration...")
    enabled_features = [k for k, v in config['features'].items() if v]
    logger.info(f"✅ {len(enabled_features)} features enabled: {', '.join(enabled_features[:5])}{'...' if len(enabled_features) > 5 else ''}")
    
    logger.info("✅ Environment check completed successfully")
    return True

def get_database_info(logger):
    """Get and display database information"""
    try:
        from app.database import get_database_status
        
        logger.info("📊 Retrieving database information...")
        db_status = get_database_status()
        
        if db_status.get('healthy'):
            db_info = db_status.get('database_info', {})
            logger.info(f"✅ Database connected: {db_info.get('database_name')} on {db_info.get('server_name')}")
            logger.info(f"⏱️ Response time: {db_status.get('response_time_ms', 0)}ms")
            
            # Log EDR table counts
            table_counts = db_status.get('table_counts', {})
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            
            for table in edr_tables:
                count = table_counts.get(table, 0)
                logger.info(f"📊 {table}: {count:,} records")
            
            # Log EDR system status
            edr_status = db_status.get('edr_system_status', {})
            if edr_status:
                logger.info(f"🔄 Active agents (last 10min): {edr_status.get('active_agents_last_10min', 0)}")
                logger.info(f"📈 Events (last hour): {edr_status.get('events_last_hour', 0)}")
                logger.info(f"🚨 Open alerts: {edr_status.get('open_alerts', 0)}")
                logger.info(f"🛡️ Active detection rules: {edr_status.get('active_detection_rules', 0)}")
                logger.info(f"🔍 Active threat indicators: {edr_status.get('active_threat_indicators', 0)}")
        else:
            logger.error("❌ Database connection failed")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database info error: {e}")
        return False
    
    return True

def main():
    """Main server entry point"""
    try:
        # Setup logging first
        logger = setup_logging()
        logger.info("🚀 EDR Agent Communication Server - Startup Initiated")
        
        # Print banner
        print_edr_banner(logger)
        
        # Check environment
        if not check_environment(logger):
            logger.error("❌ Environment check failed - cannot start server")
            sys.exit(1)
        
        # Get database info
        if not get_database_info(logger):
            logger.error("❌ Database check failed - cannot start server")
            sys.exit(1)
        
        # Final startup checks
        server_config = config['server']
        logger.info("🎯 Final startup preparations...")
        logger.info(f"🌐 Server will bind to: {server_config['bind_host']}:{server_config['bind_port']}")
        logger.info(f"🔄 Reload mode: {'Enabled' if server_config['reload'] else 'Disabled'}")
        logger.info(f"🐛 Debug mode: {'Enabled' if server_config['debug'] else 'Disabled'}")
        
        # Start uvicorn server
        logger.info("🚀 Starting EDR Agent Communication Server...")
        print(f"\n🌐 EDR Server starting on http://{server_config['bind_host']}:{server_config['bind_port']}")
        print(f"📚 API Documentation: http://{server_config['bind_host']}:{server_config['bind_port']}/docs")
        print(f"🔍 Health Check: http://{server_config['bind_host']}:{server_config['bind_port']}/health")
        print("════════════════════════════════════════════════════════════════\n")
        
        # Run uvicorn server
        uvicorn.run(
            "app.main:app",
            host=server_config['bind_host'],
            port=server_config['bind_port'],
            reload=server_config['reload'],
            log_level="info",
            access_log=True,
            use_colors=True,
            server_header=False,
            date_header=False
        )
        
    except KeyboardInterrupt:
        logger.info("👋 Server shutdown requested by user")
        print("\n🛑 EDR Server shutdown requested - Goodbye!")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("\n💡 Please ensure all required files exist:")
        print("   • app/__init__.py")
        print("   • app/main.py")
        print("   • app/config.py")
        print("   • app/database.py")
        print("   • app/api/__init__.py")
        print("   • app/api/v1/__init__.py")
        print("   • app/models/__init__.py")
        print("   • app/schemas/__init__.py")
        print("   • app/services/__init__.py")
        print("   • app/utils/__init__.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        if 'logger' in locals():
            logger.error(f"💥 Critical startup failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Set console title if on Windows
    if sys.platform.startswith('win'):
        try:
            os.system('title EDR Agent Communication Server')
        except:
            pass
    
    main()