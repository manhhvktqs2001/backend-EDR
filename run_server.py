# run_server.py - EDR Server Launcher (FIXED for Better SQL Server Detection)
"""
EDR Agent Communication Server Launcher
Enhanced with better SQL Server detection and error handling
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
import subprocess
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

def check_sql_server_service():
    """Check and attempt to start SQL Server services"""
    logger = logging.getLogger(__name__)
    
    logger.info("🔍 Checking SQL Server services...")
    
    services_to_check = [
        ("MSSQLSERVER", "SQL Server (Default Instance)"),
        ("MSSQL$SQLEXPRESS", "SQL Server Express"),
        ("MSSQL$DEVELOPER", "SQL Server Developer"),
        ("SQLBrowser", "SQL Browser Service")
    ]
    
    running_services = []
    
    for service_name, display_name in services_to_check:
        try:
            result = subprocess.run(
                ["sc", "query", service_name], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if "RUNNING" in result.stdout:
                running_services.append((service_name, display_name))
                logger.info(f"✅ {display_name} is running")
            elif result.returncode == 0:
                logger.warning(f"⚠️ {display_name} exists but not running")
                # Try to start the service
                logger.info(f"🔄 Attempting to start {display_name}...")
                try:
                    start_result = subprocess.run(
                        ["net", "start", service_name],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if start_result.returncode == 0:
                        logger.info(f"✅ Successfully started {display_name}")
                        running_services.append((service_name, display_name))
                    else:
                        logger.warning(f"⚠️ Failed to start {display_name}: {start_result.stderr}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not start {display_name}: {e}")
                    
        except Exception as e:
            logger.debug(f"Could not check {service_name}: {e}")
            continue
    
    if running_services:
        logger.info(f"✅ Found {len(running_services)} running SQL Server service(s)")
        return running_services
    else:
        logger.error("❌ No SQL Server services running")
        logger.error("💡 To start SQL Server manually:")
        logger.error("   Default: net start MSSQLSERVER")
        logger.error("   Express: net start \"MSSQL$SQLEXPRESS\"")
        return []

def test_local_sql_connection(logger):
    """Test different local SQL Server connection options with enhanced detection"""
    
    logger.info("🔍 Testing local SQL Server connections...")
    
    # First check services
    running_services = check_sql_server_service()
    if not running_services:
        logger.error("❌ No SQL Server services running - cannot test connections")
        return False
    
    # Build server options based on running services
    server_options = []
    
    # Check for default instance (MSSQLSERVER)
    if any("MSSQLSERVER" in svc[0] for svc in running_services):
        server_options.extend([
            "localhost",
            "127.0.0.1",
            ".",
            "(local)"
        ])
    
    # Check for SQL Express instances
    if any("SQLEXPRESS" in svc[0] for svc in running_services):
        server_options.extend([
            "localhost\\SQLEXPRESS",
            ".\\SQLEXPRESS", 
            "(local)\\SQLEXPRESS"
        ])
    
    # Check for Developer instances
    if any("DEVELOPER" in svc[0] for svc in running_services):
        server_options.extend([
            "localhost\\DEVELOPER",
            ".\\DEVELOPER",
            "(local)\\DEVELOPER"
        ])
    
    # Test each server option
    for server in server_options:
        logger.info(f"🔌 Testing: {server}")
        
        try:
            # Build connection string with optimized timeouts
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server};"
                f"DATABASE=master;"
                f"Trusted_Connection=yes;"
                f"Connection Timeout=15;"
                f"Login Timeout=15;"
                f"Encrypt=no;"
                f"TrustServerCertificate=yes;"
            )
            
            # Test connection with timeout
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 as test, @@SERVERNAME as server_name, @@VERSION as version")
            row = cursor.fetchone()
            
            if row and row[0] == 1:
                server_name = row[1] or server
                sql_version = row[2]
                
                logger.info(f"✅ SUCCESS! Connected to SQL Server via: {server}")
                logger.info(f"   Server Name: {server_name}")
                logger.info(f"   SQL Version: {sql_version[:80]}...")
                
                # Check if EDR_System database exists
                cursor.execute("SELECT name FROM sys.databases WHERE name = 'EDR_System'")
                db_exists = cursor.fetchone()
                
                if db_exists:
                    logger.info("✅ EDR_System database found")
                else:
                    logger.warning("⚠️ EDR_System database not found - will create automatically")
                    try:
                        cursor.execute("CREATE DATABASE EDR_System")
                        conn.commit()
                        logger.info("✅ EDR_System database created successfully")
                    except Exception as e:
                        logger.warning(f"⚠️ Could not create database: {e}")
                        logger.info("   Database will be created later by the application")
                
                conn.close()
                
                # Update environment variable for successful connection
                os.environ['DB_SERVER'] = server
                logger.info(f"🎯 Using SQL Server: {server}")
                return True
                
        except pyodbc.Error as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower():
                logger.debug(f"   ⏰ Connection timeout: {server}")
            elif "login failed" in error_msg.lower():
                logger.debug(f"   🔐 Authentication failed: {server}")
            elif "server is not found" in error_msg.lower():
                logger.debug(f"   🔍 Server not found: {server}")
            else:
                logger.debug(f"   ❌ Failed: {e}")
            continue
        except Exception as e:
            logger.debug(f"   💥 Error: {e}")
            continue
    
    logger.error("❌ No working SQL Server connection found")
    return False

def check_odbc_driver():
    """Check if ODBC Driver for SQL Server is installed"""
    logger = logging.getLogger(__name__)
    
    logger.info("🔍 Checking ODBC Driver for SQL Server...")
    
    try:
        drivers = pyodbc.drivers()
        sql_drivers = [d for d in drivers if 'SQL Server' in d]
        
        if sql_drivers:
            logger.info(f"✅ Found SQL Server ODBC drivers: {sql_drivers}")
            return True
        else:
            logger.error("❌ No SQL Server ODBC drivers found")
            logger.error("💡 Please install Microsoft ODBC Driver for SQL Server")
            logger.error("   Download from: https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error checking ODBC drivers: {e}")
        return False

def print_edr_banner(logger):
    """Print EDR server banner with configuration info"""
    try:
        from app.config import config, get_edr_info
        
        edr_info = get_edr_info()
        server_config = config['server']
        
        banner = f"""
════════════════════════════════════════════════════════════════
🛡️  EDR AGENT COMMUNICATION SERVER - {edr_info['version']} (LOCAL SQL)
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

🗄️  Database Configuration (LOCAL SQL):
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
    """Check environment and dependencies with better error handling"""
    logger.info("🔍 Performing comprehensive environment checks...")
    
    try:
        # 1. Check ODBC drivers first
        if not check_odbc_driver():
            logger.error("❌ ODBC Driver check failed")
            return False
        
        # 2. Check SQL Server services and connections
        if not test_local_sql_connection(logger):
            logger.error("❌ Cannot connect to local SQL Server")
            logger.error("")
            logger.error("💡 TROUBLESHOOTING STEPS:")
            logger.error("   1. Check if SQL Server is installed:")
            logger.error("      • SQL Server Management Studio (SSMS)")
            logger.error("      • SQL Server Express")
            logger.error("      • LocalDB")
            logger.error("")
            logger.error("   2. Start SQL Server service:")
            logger.error("      net start MSSQLSERVER")
            logger.error("      or")
            logger.error("      net start \"MSSQL$SQLEXPRESS\"")
            logger.error("")
            logger.error("   3. Check Windows Authentication:")
            logger.error("      • Run as Administrator")
            logger.error("      • Your user must have SQL Server access")
            logger.error("")
            logger.error("   4. Test connection manually:")
            logger.error("      • Open SSMS")
            logger.error("      • Connect to localhost or .\\SQLEXPRESS")
            logger.error("      • Use Windows Authentication")
            logger.error("")
            return False
        
        # 3. Import and test application configuration
        from app.config import config
        from app.database import init_database
        
        # Check required directories
        for path_name, path in config['paths'].items():
            if not path.exists():
                logger.info(f"📁 Creating directory: {path}")
                path.mkdir(parents=True, exist_ok=True)
        
        # Initialize database with enhanced error handling
        logger.info("🗄️ Initializing database connection...")
        if not init_database():
            logger.error("❌ Database initialization failed")
            logger.error("💡 This usually means:")
            logger.error("   • SQL Server connection issues")
            logger.error("   • Permission problems")
            logger.error("   • Missing database schema")
            return False
        
        logger.info("✅ Database connection successful")
        logger.info("✅ Environment check completed successfully")
        return True
        
    except ImportError as e:
        logger.error(f"❌ Missing required modules: {e}")
        logger.error("💡 Run: pip install -r requirements.txt")
        return False
    except Exception as e:
        logger.error(f"❌ Environment check failed: {e}")
        return False

def get_database_info(logger):
    """Get and display database information with enhanced reporting"""
    try:
        from app.database import get_database_status
        
        logger.info("📊 Retrieving database information...")
        db_status = get_database_status()
        
        if db_status.get('healthy'):
            # Enhanced server info display
            server_info = db_status.get('server_info', {})
            if server_info:
                logger.info(f"✅ Connected to: {server_info.get('server_name', 'Unknown')}")
                logger.info(f"📊 Database: {server_info.get('database_name', 'EDR_System')}")
                logger.info(f"👤 Login: {server_info.get('login_name', 'Unknown')}")
                logger.info(f"🗄️ Total Databases: {server_info.get('total_databases', 'Unknown')}")
            
            logger.info(f"⏱️ Response time: {db_status.get('response_time_ms', 0)}ms")
            
            # Auto-detection info
            if db_status.get('detected_server'):
                logger.info(f"🎯 Auto-detected server: {db_status['detected_server']}")
            
            # Log EDR table counts
            table_counts = db_status.get('table_counts', {})
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            
            total_records = sum(count for count in table_counts.values() if count > 0)
            logger.info(f"📈 EDR Schema: {len([t for t in edr_tables if table_counts.get(t, 0) >= 0])} tables, {total_records:,} total records")
            
            for table in edr_tables:
                count = table_counts.get(table, 0)
                if count >= 0:
                    logger.info(f"   📋 {table}: {count:,} records")
                else:
                    logger.warning(f"   ⚠️ {table}: Table check failed")
        else:
            logger.error("❌ Database connection failed")
            errors = db_status.get('errors', [])
            for error in errors:
                logger.error(f"   💥 {error}")
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
    """Test database schema compliance with enhanced error reporting"""
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
        logger.warning("⚠️ This might indicate schema issues, but continuing startup...")
        return True  # Don't fail startup for this

def main():
    """Main server entry point with enhanced error handling"""
    try:
        # Setup logging first
        logger = setup_logging()
        logger.info("🚀 EDR Agent Communication Server - Enhanced Local SQL Startup")
        
        # Print banner
        print_edr_banner(logger)
        
        # Check environment with detailed error reporting
        if not check_environment(logger):
            logger.error("❌ Environment check failed - cannot start server")
            logger.error("")
            logger.error("🔧 QUICK FIX CHECKLIST:")
            logger.error("   ☐ SQL Server is installed")
            logger.error("   ☐ SQL Server service is running")
            logger.error("   ☐ Windows Authentication works")
            logger.error("   ☐ ODBC Driver 17 is installed")
            logger.error("   ☐ User has SQL Server permissions")
            logger.error("")
            sys.exit(1)
        
        # Get database info with enhanced reporting
        if not get_database_info(logger):
            logger.error("❌ Database status check failed - cannot start server")
            sys.exit(1)
        
        # Test database schema (non-critical)
        test_database_schema()
        
        # Import configuration after all checks pass
        from app.config import config
        
        # Final startup preparations
        server_config = config['server']
        logger.info("🎯 Final startup preparations...")
        logger.info(f"🌐 Server will bind to: {server_config['bind_host']}:{server_config['bind_port']}")
        logger.info(f"🔄 Reload mode: {'Enabled' if server_config['reload'] else 'Disabled'}")
        logger.info(f"🐛 Debug mode: {'Enabled' if server_config['debug'] else 'Disabled'}")
        
        # Success message
        logger.info("🔧 LOCAL SQL SERVER MODE - READY:")
        logger.info("   ✅ Connected to local SQL Server instance")
        logger.info("   ✅ Using Windows Authentication")
        logger.info("   ✅ EDR_System database operational")
        logger.info("   ✅ All services ready")
        
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
        print("\n💡 Please ensure all required files exist and run:")
        print("   pip install -r requirements.txt")
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
            os.system('title EDR Agent Communication Server - Enhanced Local SQL Mode')
        except:
            pass
    
    main()