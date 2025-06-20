# app/database.py - FIXED VERSION (Better SQL Server Detection & Connection)
"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server - FIXED with better local detection
"""

import logging
from contextlib import contextmanager
from typing import Generator, Dict, List, Any, Optional, Tuple
from sqlalchemy import create_engine, text, event, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.exc import SQLAlchemyError, OperationalError, IntegrityError
import time
import pyodbc
import subprocess
from datetime import datetime, timedelta

from .config import config, get_database_url

# Configure logging
logger = logging.getLogger(__name__)

# SQLAlchemy Base for all models
Base = declarative_base()

class DatabaseManager:
    """Enhanced Database connection and session manager for EDR System with better auto-detection"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 3
        self._last_health_check = None
        self._health_check_interval = 300  # 5 minutes
        self._detected_server = None
        self._initialize_engine()
    
    def _check_sql_server_services(self):
        """Check if SQL Server services are running"""
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
            return []
    
    def _auto_detect_server(self):
        """Auto-detect working SQL Server connection with service check"""
        logger.info("🔍 Auto-detecting SQL Server connection...")
        
        # First check if services are running
        running_services = self._check_sql_server_services()
        if not running_services:
            logger.error("❌ No SQL Server services running - cannot proceed")
            return False
        
        # Build server options based on running services
        server_options = []
        
        # Check for default instance (MSSQLSERVER)
        if any("MSSQLSERVER" in svc[0] for svc in running_services):
            server_options.extend([
                "localhost",
                "127.0.0.1",
                ".",
                "(local)",
                "localhost,1433",
                "127.0.0.1,1433"
            ])
        
        # Check for SQL Express instances
        if any("SQLEXPRESS" in svc[0] for svc in running_services):
            server_options.extend([
                "localhost\\SQLEXPRESS",
                ".\\SQLEXPRESS", 
                "(local)\\SQLEXPRESS",
                "127.0.0.1\\SQLEXPRESS"
            ])
        
        # Check for Developer instances
        if any("DEVELOPER" in svc[0] for svc in running_services):
            server_options.extend([
                "localhost\\DEVELOPER",
                ".\\DEVELOPER",
                "(local)\\DEVELOPER"
            ])
        
        # Add original config as fallback
        original_server = config['database']['server']
        if original_server not in server_options:
            server_options.insert(0, original_server)
        
        # Test each server option
        for server in server_options:
            try:
                logger.info(f"🔌 Testing connection to: {server}")
                
                # Test with shorter timeout for faster detection
                if self._test_server_connection(server, timeout=10):
                    logger.info(f"✅ Auto-detected working server: {server}")
                    
                    # Update config to use detected server
                    config['database']['server'] = server
                    self._detected_server = server
                    return True
                    
            except Exception as e:
                logger.debug(f"   ❌ Failed: {server} - {e}")
                continue
        
        logger.error("❌ No working SQL Server connection found")
        return False
    
    def _test_server_connection(self, server: str, timeout: int = 10) -> bool:
        """Test connection to specific server"""
        try:
            # Build connection string
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server};"
                f"DATABASE=master;"  # Test with master first
                f"Trusted_Connection=yes;"
                f"Connection Timeout={timeout};"
                f"Login Timeout={timeout};"
                f"Encrypt=no;"
                f"TrustServerCertificate=yes;"
            )
            
            # Test connection
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 as test, @@SERVERNAME as server_name, DB_NAME() as current_db")
            row = cursor.fetchone()
            
            if row and row[0] == 1:
                server_name = row[1] or server
                current_db = row[2]
                logger.info(f"   ✅ Connected to: {server_name} (Database: {current_db})")
                
                # Check if EDR_System database exists
                cursor.execute("SELECT name FROM sys.databases WHERE name = 'EDR_System'")
                edr_db_exists = cursor.fetchone()
                
                if not edr_db_exists:
                    logger.info("   📦 Creating EDR_System database...")
                    try:
                        cursor.execute("CREATE DATABASE EDR_System")
                        conn.commit()
                        logger.info("   ✅ EDR_System database created")
                    except Exception as e:
                        logger.warning(f"   ⚠️ Could not create EDR_System database: {e}")
                else:
                    logger.info("   ✅ EDR_System database found")
                
                conn.close()
                return True
            
            conn.close()
            return False
            
        except pyodbc.Error as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower():
                logger.debug(f"   ⏰ Connection timeout to {server}")
            elif "login failed" in error_msg.lower():
                logger.debug(f"   🔐 Authentication failed to {server}")
            elif "server is not found" in error_msg.lower():
                logger.debug(f"   🔍 Server not found: {server}")
            else:
                logger.debug(f"   ❌ Connection error to {server}: {e}")
            return False
        except Exception as e:
            logger.debug(f"   💥 Unexpected error testing {server}: {e}")
            return False
    
    def _build_connection_url(self, db_config):
        """Build enhanced connection URL with optimized settings"""
        server = db_config['server']
        database = db_config['database']
        
        # Enhanced connection parameters for better reliability
        connection_params = [
            f"driver={db_config['driver'].replace(' ', '+')}", 
            "trusted_connection=yes",
            "autocommit=false",  # Let SQLAlchemy manage transactions
            f"timeout={min(db_config['timeout'], 30)}",  # Cap at 30 seconds
            f"login_timeout={min(db_config.get('login_timeout', 30), 30)}",
            f"connection_timeout={min(db_config.get('connection_timeout', 30), 30)}",
            "encrypt=no",  # Usually not needed for local connections
            "trustservercertificate=yes",
            "multisubnetfailover=no",
            "mars_connection=no",
            "app_name=EDR_Agent_Server",
            # Performance optimizations
            "packet_size=4096",
            "fast_first_row=no",
            "query_notification=false"
        ]
        
        connection_string = "&".join(connection_params)
        
        return f"mssql+pyodbc://@{server}/{database}?{connection_string}"
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with better error handling"""
        try:
            # First, try auto-detection if original config fails
            original_server = config['database']['server']
            
            logger.info(f"🔗 Initializing database connection to: {original_server}/{config['database']['database']}")
            
            # Try original config first
            try:
                if self._test_server_connection(original_server, timeout=15):
                    logger.info("✅ Using original database configuration")
                else:
                    raise ConnectionError("Original config failed")
            except Exception as e:
                logger.warning(f"⚠️ Original config failed: {e}")
                logger.info("🔄 Attempting auto-detection...")
                
                if not self._auto_detect_server():
                    raise RuntimeError("Could not establish database connection")
            
            # Build connection URL with detected/configured server
            database_url = self._build_connection_url(config['database'])
            
            perf_config = config['performance']
            
            # Create engine with optimized settings for local SQL Server
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=min(perf_config['database_pool_size'], 10),  # Smaller for local
                max_overflow=min(perf_config['database_max_overflow'], 20),
                pool_timeout=30,  # Reasonable timeout
                pool_pre_ping=True,  # Essential for detecting stale connections
                pool_recycle=3600,  # 1 hour recycle for local connections
                echo=config['server']['debug'],
                echo_pool=False,
                future=True,
                isolation_level="READ_COMMITTED",
                connect_args={
                    "timeout": 30,
                    "autocommit": False,
                    "check_same_thread": False,
                    "fast_executemany": True,  # Performance boost
                    "login_timeout": 30,
                    "connection_timeout": 30
                }
            )
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
                expire_on_commit=False,
                class_=Session
            )
            
            # Initialize metadata
            self.metadata = MetaData()
            
            # Add event listeners
            self._add_event_listeners()
            
            logger.info("✅ Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database engine: {e}")
            raise DatabaseConnectionError(f"Database initialization failed: {e}")
    
    def _add_event_listeners(self):
        """Add SQLAlchemy event listeners for monitoring"""
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            logger.debug("🔗 New database connection established")
            try:
                if hasattr(dbapi_connection, 'execute'):
                    # Set connection properties for SQL Server
                    dbapi_connection.execute("SET LOCK_TIMEOUT 30000")
                    dbapi_connection.execute("SET ARITHABORT ON")
                    dbapi_connection.execute("SET ANSI_NULLS ON")
                    dbapi_connection.execute("SET QUOTED_IDENTIFIER ON")
            except Exception as e:
                logger.debug(f"Could not set connection properties: {e}")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug("📤 Connection checked out from pool")
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            logger.debug("📥 Connection checked in to pool")
        
        @event.listens_for(self.engine, "invalidate")
        def receive_invalidate(dbapi_connection, connection_record, exception):
            logger.warning(f"🔄 Connection invalidated: {exception}")
    
    def test_connection(self, retry_count: int = 3) -> bool:
        """Enhanced connection test with better error reporting"""
        for attempt in range(retry_count):
            try:
                with self.engine.connect() as connection:
                    result = connection.execute(text("""
                        SELECT 
                            1 as test, 
                            GETDATE() as server_time,
                            @@SERVERNAME as server_name,
                            DB_NAME() as database_name,
                            SUSER_NAME() as login_name,
                            USER_NAME() as user_name
                    """))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        self.is_connected = True
                        server_time = row[1]
                        server_name = row[2]
                        database_name = row[3]
                        login_name = row[4]
                        user_name = row[5]
                        
                        logger.info(f"✅ Database connection verified (attempt {attempt + 1}/{retry_count})")
                        logger.info(f"🕐 Server time: {server_time}")
                        logger.info(f"🖥️ Server: {server_name}, Database: {database_name}")
                        logger.info(f"👤 Login: {login_name}, User: {user_name}")
                        
                        if self._detected_server:
                            logger.info(f"🎯 Auto-detected server: {self._detected_server}")
                        
                        return True
                    else:
                        raise Exception("Unexpected test query result")
                        
            except Exception as e:
                self.is_connected = False
                error_msg = str(e)
                
                # Better error categorization
                if "timeout" in error_msg.lower():
                    logger.error(f"⏰ Connection timeout (attempt {attempt + 1}/{retry_count}): {e}")
                elif "login failed" in error_msg.lower():
                    logger.error(f"🔐 Authentication failed (attempt {attempt + 1}/{retry_count}): {e}")
                elif "server is not found" in error_msg.lower():
                    logger.error(f"🔍 Server not found (attempt {attempt + 1}/{retry_count}): {e}")
                else:
                    logger.error(f"❌ Database connection test failed (attempt {attempt + 1}/{retry_count}): {e}")
                
                if attempt < retry_count - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"⏳ Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    
        return False
    
    def get_session(self) -> Session:
        """Get new database session with enhanced error handling"""
        if not self.SessionLocal:
            raise DatabaseConnectionError("Database not initialized")
        
        try:
            session = self.SessionLocal()
            # Quick test with shorter timeout
            session.execute(text("SELECT 1"))
            logger.debug("🔗 New database session established")
            return session
        except Exception as e:
            logger.error(f"Failed to create database session: {e}")
            raise DatabaseSessionError(f"Session creation failed: {e}")
    
    @contextmanager
    def get_db_session(self) -> Generator[Session, None, None]:
        """Enhanced context manager for database sessions"""
        session = None
        try:
            session = self.get_session()
            yield session
            session.commit()
            logger.debug("✅ Database session committed successfully")
            
        except IntegrityError as e:
            if session:
                session.rollback()
            logger.error(f"🔒 Database integrity error: {e}")
            raise DatabaseIntegrityError(f"Data integrity violation: {e}")
            
        except OperationalError as e:
            if session:
                session.rollback()
            logger.error(f"🔌 Database operational error: {e}")
            raise DatabaseOperationalError(f"Database operation failed: {e}")
            
        except SQLAlchemyError as e:
            if session:
                session.rollback()
            logger.error(f"💥 SQLAlchemy error: {e}")
            raise DatabaseError(f"Database error: {e}")
            
        except Exception as e:
            if session:
                session.rollback()
            logger.error(f"💥 Unexpected error in database session: {e}")
            raise DatabaseError(f"Unexpected database error: {e}")
            
        finally:
            if session:
                session.close()
                logger.debug("🔐 Database session closed")
    
    def check_tables_exist(self) -> Dict[str, bool]:
        """Check if EDR tables exist - FASTER VERSION"""
        try:
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            table_status = {}
            
            with self.get_db_session() as session:
                # Check all tables in one query
                table_check_query = """
                    SELECT TABLE_NAME
                    FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_SCHEMA = 'dbo' 
                    AND TABLE_NAME IN ({})
                """.format(','.join([f"'{table}'" for table in edr_tables]))
                
                result = session.execute(text(table_check_query))
                existing_tables = [row[0] for row in result.fetchall()]
                
                for table in edr_tables:
                    table_status[table] = table in existing_tables
                    
            return table_status
            
        except Exception as e:
            logger.error(f"❌ Error checking table existence: {e}")
            return {table: False for table in ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']}
    
    def get_table_counts(self) -> Dict[str, int]:
        """Get record counts for all EDR tables - OPTIMIZED"""
        try:
            table_counts = {}
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            
            with self.get_db_session() as session:
                for table in edr_tables:
                    try:
                        query = f"SELECT COUNT(*) as count FROM [{table}]"
                        result = session.execute(text(query))
                        row = result.fetchone()
                        table_counts[table] = row[0] if row else 0
                    except Exception as e:
                        logger.debug(f"Could not get count for {table}: {e}")
                        table_counts[table] = -1
                        
            return table_counts
            
        except Exception as e:
            logger.error(f"❌ Error getting table counts: {e}")
            return {}
    
    def health_check(self, force_check: bool = False) -> Dict:
        """FASTER database health check with better diagnostics"""
        start_time = time.time()
        health_status = {
            'healthy': False,
            'response_time_ms': 0,
            'detected_server': self._detected_server,
            'server_info': {},
            'table_counts': {},
            'errors': [],
            'last_checked': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Quick connection test
            if not self.test_connection(retry_count=1):
                health_status['errors'].append('Database connection failed')
                return health_status
            
            # Step 2: Get server information
            try:
                with self.get_db_session() as session:
                    result = session.execute(text("""
                        SELECT 
                            @@SERVERNAME as server_name,
                            @@VERSION as version,
                            DB_NAME() as database_name,
                            SUSER_NAME() as login_name,
                            (SELECT COUNT(*) FROM sys.databases) as db_count
                    """))
                    row = result.fetchone()
                    if row:
                        health_status['server_info'] = {
                            'server_name': row[0],
                            'version': row[1][:100] + '...' if len(row[1]) > 100 else row[1],
                            'database_name': row[2],
                            'login_name': row[3],
                            'total_databases': row[4]
                        }
            except Exception as e:
                health_status['errors'].append(f'Server info error: {str(e)}')
            
            # Step 3: Check tables exist
            table_status = self.check_tables_exist()
            missing_tables = [table for table, exists in table_status.items() if not exists]
            
            if missing_tables:
                health_status['errors'].append(f"Missing tables: {', '.join(missing_tables)}")
            
            # Step 4: Get table counts (only if tables exist)
            if not missing_tables:
                health_status['table_counts'] = self.get_table_counts()
            
            # Step 5: Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Step 6: Determine overall health
            health_status['healthy'] = len(health_status['errors']) == 0
            
            if health_status['healthy']:
                logger.info(f"✅ Database health check passed in {health_status['response_time_ms']}ms")
            else:
                logger.warning(f"⚠️ Database health check issues: {health_status['errors']}")
            
        except Exception as e:
            health_status['errors'].append(f'Health check failed: {str(e)}')
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            logger.error(f"💥 Database health check failed: {e}")
        
        return health_status
    
    def cleanup(self):
        """Clean up database connections and resources"""
        try:
            if self.engine:
                self.engine.dispose()
                logger.info("🧹 Database engine disposed successfully")
            
            self.is_connected = False
            logger.info("🧹 Database cleanup completed")
            
        except Exception as e:
            logger.error(f"❌ Error during database cleanup: {e}")

# Custom Exception Classes
class DatabaseError(Exception):
    """Base database error"""
    pass

class DatabaseConnectionError(DatabaseError):
    """Database connection error"""
    pass

class DatabaseSessionError(DatabaseError):
    """Database session error"""
    pass

class DatabaseIntegrityError(DatabaseError):
    """Database integrity constraint error"""
    pass

class DatabaseOperationalError(DatabaseError):
    """Database operational error"""
    pass

# Global database manager instance
db_manager = DatabaseManager()

# FastAPI dependency function
def get_db() -> Generator[Session, None, None]:
    """Enhanced database dependency for FastAPI endpoints"""
    session = None
    try:
        session = db_manager.get_session()
        yield session
    except DatabaseError:
        raise
    except Exception as e:
        if session:
            session.rollback()
        logger.error(f"💥 Database session error in dependency: {e}")
        raise DatabaseError(f"Database session error: {e}")
    finally:
        if session:
            session.close()

# IMPROVED initialization function
def init_database() -> bool:
    """Initialize database connection and verify EDR schema - ENHANCED VERSION"""
    try:
        logger.info("🔄 Initializing EDR database connection...")
        
        # Test database connection with better error reporting
        if not db_manager.test_connection(retry_count=2):
            logger.error("❌ Database connection test failed")
            logger.error("💡 Check if:")
            logger.error("   • SQL Server service is running")
            logger.error("   • Windows Authentication is enabled")
            logger.error("   • Your user has SQL Server access")
            logger.error("   • Firewall allows SQL Server connections")
            return False
        
        # Enhanced health check
        health_status = db_manager.health_check()
        if not health_status['healthy']:
            logger.error(f"❌ Database health check failed: {health_status['errors']}")
            
            # Print helpful diagnostics
            if health_status.get('server_info'):
                server_info = health_status['server_info']
                logger.info(f"📊 Server Info: {server_info.get('server_name')} / {server_info.get('database_name')}")
                logger.info(f"👤 Login: {server_info.get('login_name')}")
            
            return False
        
        # Log success info
        if db_manager._detected_server:
            logger.info(f"🎯 Using auto-detected server: {db_manager._detected_server}")
        
        # Enhanced success reporting
        server_info = health_status.get('server_info', {})
        table_counts = health_status.get('table_counts', {})
        total_records = sum(count for count in table_counts.values() if count > 0)
        
        logger.info(f"📊 Connected to: {server_info.get('server_name', 'Unknown')} / {server_info.get('database_name', 'EDR_System')}")
        logger.info(f"👤 Authenticated as: {server_info.get('login_name', 'Unknown')}")
        logger.info(f"📈 Database ready - {len(table_counts)} tables, {total_records:,} total records")
        logger.info(f"⚡ Response time: {health_status['response_time_ms']}ms")
        
        # Log table summary
        for table, count in table_counts.items():
            if count >= 0:
                logger.info(f"   📋 {table}: {count:,} records")
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Database initialization failed: {e}")
        return False

def get_database_status() -> Dict:
    """Get current database status for monitoring"""
    try:
        return db_manager.health_check()
    except Exception as e:
        logger.error(f"Failed to get database status: {e}")
        return {
            'healthy': False,
            'error': str(e),
            'last_checked': datetime.now().isoformat()
        }

def shutdown_database():
    """Gracefully shutdown database connections"""
    try:
        logger.info("🔄 Shutting down database connections...")
        db_manager.cleanup()
        logger.info("✅ Database shutdown completed")
    except Exception as e:
        logger.error(f"❌ Database shutdown error: {e}")

# Module-level cleanup on exit
import atexit
atexit.register(shutdown_database)