# run_server.py - EDR Server Launcher (Fixed and Complete)
"""
EDR Agent Communication Server Launcher
Database schema compliant with comprehensive error handling
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

def setup_logging():
    """Setup basic logging for startup"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('edr_server.log', encoding='utf-8')
        ]
    )
    return logging.getLogger(__name__)

def print_edr_banner(logger):
    """Print EDR server banner with configuration info"""
    try:
        from app.config import config, get_edr_info
        
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
   • Agent Registration: POST /api/v1/agents/register
   • Agent Heartbeat: POST /api/v1/agents/heartbeat
   • Event Submission: POST /api/v1/events/submit
   • Dashboard API: GET /api/v1/dashboard/*

🎯 Features Enabled:
{chr(10).join([f'   • {feature.replace("_", " ").title()}: ✅' for feature, enabled in edr_info['features_enabled'].items() if enabled])}
════════════════════════════════════════════════════════════════
"""
        
        print(banner)
        logger.info("🛡️ EDR Agent Communication Server Starting Up")
        
    except Exception as e:
        print(f"❌ Error printing banner: {e}")

def check_environment(logger):
    """Check environment and dependencies"""
    logger.info("🔍 Performing environment checks...")
    
    try:
        from app.config import config
        from app.database import init_database
        
        # Check required directories
        for path_name, path in config['paths'].items():
            if not path.exists():
                logger.info(f"📁 Creating directory: {path}")
                path.mkdir(parents=True, exist_ok=True)
        
        # Check database configuration
        logger.info("🗄️ Testing database connection...")
        if not init_database():
            logger.error("❌ Database initialization failed")
            return False
        
        logger.info("✅ Database connection successful")
        logger.info("✅ Environment check completed successfully")
        return True
        
    except ImportError as e:
        logger.error(f"❌ Missing required modules: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Environment check failed: {e}")
        return False

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

def test_database_schema():
    """Test database schema compliance"""
    try:
        from app.database import db_manager
        from app.models.agent import Agent
        from app.models.event import Event
        from app.models.alert import Alert
        from datetime import datetime
        
        logger = logging.getLogger(__name__)
        logger.info("🧪 Testing database schema compliance...")
        
        with db_manager.get_db_session() as session:
            # Test agent operations
            test_agent = Agent.create_agent(
                hostname="TEST-SCHEMA-001",
                ip_address="192.168.20.200",
                operating_system="Windows 11 Pro"
            )
            session.add(test_agent)
            session.commit()
            logger.info(f"✅ Agent test successful: {test_agent.AgentID}")
            
            # Test event operations
            test_event = Event.create_event(
                agent_id=str(test_agent.AgentID),
                event_type="Process",
                event_action="Create",
                event_timestamp=datetime.now(),
                ProcessName="test.exe",
                ProcessID=9999
            )
            session.add(test_event)
            session.commit()
            logger.info(f"✅ Event test successful: {test_event.EventID}")
            
            # Test alert operations
            test_alert = Alert.create_alert(
                agent_id=str(test_agent.AgentID),
                alert_type="Test Alert",
                title="Schema Test Alert",
                severity="Low",
                detection_method="Test",
                EventID=test_event.EventID
            )
            session.add(test_alert)
            session.commit()
            logger.info(f"✅ Alert test successful: {test_alert.AlertID}")
            
            # Cleanup test data
            session.delete(test_alert)
            session.delete(test_event)
            session.delete(test_agent)
            session.commit()
            
            logger.info("✅ Database schema test completed successfully")
            return True
            
    except Exception as e:
        logger.error(f"❌ Database schema test failed: {e}")
        return False

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
        
        # Test database schema
        if not test_database_schema():
            logger.error("❌ Database schema test failed - cannot start server")
            sys.exit(1)
        
        # Import configuration after checks
        from app.config import config
        
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
        print("   • All model files in app/models/")
        print("   • All API files in app/api/v1/")
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