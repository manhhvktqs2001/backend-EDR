# run_server.py - EDR Server Launcher (Fixed for Local SQL Server)
"""
EDR Agent Communication Server Launcher
Fixed for local SQL Server connection
"""

import os
import sys
import logging
import logging.config
import uvicorn
import uuid
import time
import socket
import pyodbc
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

def test_local_sql_connection(logger):
    """Test different local SQL Server connection options"""
    
    logger.info("🔍 Testing local SQL Server connections...")
    
    # Different server names to try for local SQL Server
    server_options = [
        "localhost",
        "127.0.0.1", 
        ".",
        "(local)",
        "localhost\\SQLEXPRESS",
        ".\\SQLEXPRESS",
        "(local)\\SQLEXPRESS"
    ]
    
    connection_strings = []
    
    for server in server_options:
        conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE=EDR_System;Trusted_Connection=yes;"
        connection_strings.append((server, conn_str))
    
    # Test each connection string
    for server_name, conn_str in connection_strings:
        logger.info(f"🔌 Testing: {server_name}")
        
        try:
            # Test connection with short timeout
            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 as test, @@VERSION as version")
            row = cursor.fetchone()
            
            # Check if EDR_System database exists
            cursor.execute("SELECT name FROM sys.databases WHERE name = 'EDR_System'")
            db_exists = cursor.fetchone()
            
            conn.close()
            
            logger.info(f"✅ SUCCESS! Connected to SQL Server via: {server_name}")
            logger.info(f"   SQL Version: {row.version[:60]}...")
            
            if db_exists:
                logger.info("✅ EDR_System database found")
            else:
                logger.warning("⚠️ EDR_System database not found - creating it...")
                try:
                    # Try to create database
                    master_conn_str = conn_str.replace("DATABASE=EDR_System;", "DATABASE=master;")
                    master_conn = pyodbc.connect(master_conn_str, timeout=5)
                    master_cursor = master_conn.cursor()
                    master_cursor.execute("CREATE DATABASE EDR_System")
                    master_conn.commit()
                    master_conn.close()
                    logger.info("✅ EDR_System database created successfully")
                except Exception as e:
                    logger.error(f"❌ Failed to create database: {e}")
            
            # Update environment variable for successful connection
            os.environ['DB_SERVER'] = server_name
            logger.info(f"🎯 Using SQL Server: {server_name}")
            return True
            
        except pyodbc.Error as e:
            logger.debug(f"   ❌ Failed: {e}")
            continue
        except Exception as e:
            logger.debug(f"   ❌ Error: {e}")
            continue
    
    logger.error("❌ No working SQL Server connection found")
    return False

def check_sql_server_service():
    """Check if SQL Server services are running"""
    logger = logging.getLogger(__name__)
    
    logger.info("🔍 Checking SQL Server services...")
    
    services_to_check = [
        "MSSQLSERVER",
        "MSSQL$SQLEXPRESS", 
        "SQLBrowser"
    ]
    
    running_services = []
    
    for service in services_to_check:
        try:
            import subprocess
            result = subprocess.run(
                ["sc", "query", service], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if "RUNNING" in result.stdout:
                running_services.append(service)
                logger.info(f"✅ {service} is running")
            elif result.returncode == 0:
                logger.warning(f"⚠️ {service} exists but not running")
            
        except Exception:
            continue
    
    if running_services:
        logger.info(f"✅ Found {len(running_services)} running SQL Server service(s)")
        return True
    else:
        logger.error("❌ No SQL Server services running")
        logger.error("💡 Start SQL Server service with: net start MSSQLSERVER")
        return False

def print_edr_banner(logger):
    """Print EDR server banner with configuration info"""
    try:
        from app.config import config, get_edr_info
        
        edr_info = get_edr_info()
        server_config = config['server']
        
        banner = f"""
════════════════════════════════════════════════════════════════
🛡️  EDR AGENT COMMUNICATION SERVER - {edr_info['version']} (LOCAL)
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

🗄️  Database Configuration (LOCAL):
   • Server: {config['database']['server']} (Auto-detected)
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
        # 1. Check SQL Server services first
        if not check_sql_server_service():
            logger.error("❌ SQL Server services not running")
            logger.error("💡 Please start SQL Server service:")
            logger.error("   net start MSSQLSERVER")
            logger.error("   or")
            logger.error("   net start \"MSSQL$SQLEXPRESS\"")
            return False
        
        # 2. Test SQL Server connection
        if not test_local_sql_connection(logger):
            logger.error("❌ Cannot connect to local SQL Server")
            logger.error("💡 Please check:")
            logger.error("   • SQL Server is installed and running")
            logger.error("   • Windows Authentication is enabled")
            logger.error("   • Your user has access to SQL Server")
            logger.error("   • Try connecting with SSMS first")
            return False
        
        # 3. Import and test application configuration
        from app.config import config
        from app.database import init_database
        
        # Check required directories
        for path_name, path in config['paths'].items():
            if not path.exists():
                logger.info(f"📁 Creating directory: {path}")
                path.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        logger.info("🗄️ Initializing database...")
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

def cleanup_old_test_agents(session):
    """Clean up old test agents before running new test"""
    try:
        from app.models.agent import Agent
        
        # Delete old test agents
        old_test_agents = session.query(Agent).filter(
            Agent.HostName.like('TEST-SCHEMA-%')
        ).all()
        
        if old_test_agents:
            for agent in old_test_agents:
                session.delete(agent)
            session.commit()
            return len(old_test_agents)
        return 0
        
    except Exception as e:
        session.rollback()
        raise e

def test_database_schema():
    """Test database schema compliance - FIXED with unique hostname"""
    try:
        from app.database import db_manager
        from app.models.agent import Agent
        from datetime import datetime
        
        logger = logging.getLogger(__name__)
        logger.info("🧪 Testing database schema compliance...")
        
        with db_manager.get_db_session() as session:
            # Clean up old test agents first
            cleaned_count = cleanup_old_test_agents(session)
            if cleaned_count > 0:
                logger.info(f"🧹 Cleaned up {cleaned_count} old test agents")
            
            # Generate unique hostname for test
            timestamp = int(time.time())
            unique_id = str(uuid.uuid4())[:8]
            test_hostname = f"TEST-SCHEMA-{timestamp}-{unique_id}"
            
            # Test agent operations with unique hostname
            test_agent = Agent.create_agent(
                hostname=test_hostname,
                ip_address="192.168.20.200",
                operating_system="Windows 11 Pro"
            )
            session.add(test_agent)
            session.commit()
            logger.info(f"✅ Agent test successful: {test_agent.AgentID}")
            logger.info(f"✅ Test hostname: {test_hostname}")
            
            # Cleanup test data immediately
            session.delete(test_agent)
            session.commit()
            logger.info("🧹 Test agent cleaned up")
            
            logger.info("✅ Database schema test completed successfully")
            return True
            
    except Exception as e:
        logger.error(f"❌ Database schema test failed: {e}")
        # Don't fail startup for this - it's just a test
        logger.warning("⚠️ Continuing server startup despite test failure...")
        return True

def main():
    """Main server entry point"""
    try:
        # Setup logging first
        logger = setup_logging()
        logger.info("🚀 EDR Agent Communication Server - Local SQL Startup")
        
        # Print banner
        print_edr_banner(logger)
        
        # Check environment
        if not check_environment(logger):
            logger.error("❌ Environment check failed - cannot start server")
            logger.error("💡 Quick fixes to try:")
            logger.error("   1. Start SQL Server: net start MSSQLSERVER")
            logger.error("   2. Or start SQL Express: net start \"MSSQL$SQLEXPRESS\"")
            logger.error("   3. Connect with SSMS to verify SQL Server works")
            logger.error("   4. Check Windows Authentication is enabled")
            sys.exit(1)
        
        # Get database info
        if not get_database_info(logger):
            logger.error("❌ Database check failed - cannot start server")
            sys.exit(1)
        
        # Test database schema (non-critical)
        test_database_schema()
        
        # Import configuration after checks
        from app.config import config
        
        # Final startup checks
        server_config = config['server']
        logger.info("🎯 Final startup preparations...")
        logger.info(f"🌐 Server will bind to: {server_config['bind_host']}:{server_config['bind_port']}")
        logger.info(f"🔄 Reload mode: {'Enabled' if server_config['reload'] else 'Disabled'}")
        logger.info(f"🐛 Debug mode: {'Enabled' if server_config['debug'] else 'Disabled'}")
        
        # Important notes for user
        logger.info("🔧 LOCAL SQL SERVER MODE:")
        logger.info("   • Connected to local SQL Server instance")
        logger.info("   • Using Windows Authentication")
        logger.info("   • EDR_System database ready")
        logger.info("   • All services operational")
        
        # Start uvicorn server
        logger.info("🚀 Starting EDR Agent Communication Server...")
        print(f"\n🌐 EDR Server starting on http://{server_config['bind_host']}:{server_config['bind_port']}")
        print(f"📚 API Documentation: http://{server_config['bind_host']}:{server_config['bind_port']}/docs")
        print(f"🔍 Health Check: http://{server_config['bind_host']}:{server_config['bind_port']}/health")
        print(f"📊 Dashboard API: http://{server_config['bind_host']}:{server_config['bind_port']}/api/v1/dashboard/stats")
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
            os.system('title EDR Agent Communication Server - Local SQL Mode')
        except:
            pass
    
    main()