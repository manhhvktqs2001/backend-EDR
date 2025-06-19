# app/database.py - Database Manager (FIXED for Network Connection)
"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server - FIXED for network database access
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
from datetime import datetime, timedelta

from .config import config, get_database_url

# Configure logging
logger = logging.getLogger(__name__)

# SQLAlchemy Base for all models
Base = declarative_base()

class DatabaseManager:
    """Enhanced Database connection and session manager for EDR System with network support"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 5  # FIXED: Increased retries for network
        self._last_health_check = None
        self._health_check_interval = 300  # 5 minutes
        self._initialize_engine()
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with enhanced network configuration"""
        try:
            database_url = get_database_url()
            perf_config = config['performance']
            
            logger.info(f"🔗 Initializing database connection to: {config['database']['server']}/{config['database']['database']}")
            
            # Network-optimized engine configuration
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=perf_config['database_pool_size'],
                max_overflow=perf_config['database_max_overflow'],
                pool_timeout=perf_config['database_pool_timeout'],
                pool_pre_ping=True,  # Essential for network connections
                pool_recycle=1800,   # FIXED: Shorter recycle for network stability (30 min)
                echo=config['server']['debug'],
                echo_pool=False,
                future=True,
                isolation_level="READ_COMMITTED",
                connect_args={
                    "timeout": config['database']['timeout'],
                    "autocommit": False,
                    "check_same_thread": False,
                    # FIXED: Network connection optimizations
                    "login_timeout": config['database']['login_timeout'],
                    "connection_timeout": config['database']['connection_timeout'],
                    "packet_size": 4096,  # Optimize packet size for network
                    "app_name": "EDR_Agent_Server"  # Identify connection in SQL Server
                }
            )
            
            # Create session factory with enhanced configuration
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
                expire_on_commit=False,  # Keep objects usable after commit
                class_=Session
            )
            
            # Initialize metadata
            self.metadata = MetaData()
            
            # Add comprehensive event listeners
            self._add_event_listeners()
            
            logger.info("✅ Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database engine: {e}")
            raise DatabaseConnectionError(f"Database initialization failed: {e}")
    
    def _add_event_listeners(self):
        """Add comprehensive SQLAlchemy event listeners for monitoring and debugging"""
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            logger.debug("🔗 New database connection established")
            # Set connection properties for SQL Server
            try:
                if hasattr(dbapi_connection, 'execute'):
                    # FIXED: Enhanced connection settings for network stability
                    dbapi_connection.execute("SET LOCK_TIMEOUT 30000")  # 30 seconds
                    dbapi_connection.execute("SET QUERY_GOVERNOR_COST_LIMIT 0")  # No query cost limit
                    dbapi_connection.execute("SET ARITHABORT ON")  # Better error handling
                    dbapi_connection.execute("SET ANSI_NULLS ON")  # Standard compliance
                    dbapi_connection.execute("SET QUOTED_IDENTIFIER ON")  # Standard compliance
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
    
    def test_connection(self, retry_count: int = 5) -> bool:
        """Enhanced connection test with retry logic for network"""
        for attempt in range(retry_count):
            try:
                with self.engine.connect() as connection:
                    # Enhanced test with server info
                    result = connection.execute(text("""
                        SELECT 
                            1 as test, 
                            GETDATE() as server_time,
                            @@VERSION as version,
                            @@SERVERNAME as server_name,
                            DB_NAME() as database_name
                    """))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        self.is_connected = True
                        server_time = row[1]
                        server_name = row[3]
                        database_name = row[4]
                        logger.info(f"✅ Database connection test successful (attempt {attempt + 1}/{retry_count})")
                        logger.debug(f"🕐 Server time: {server_time}")
                        logger.debug(f"🖥️ Server: {server_name}, Database: {database_name}")
                        return True
                    else:
                        raise Exception("Unexpected test query result")
                        
            except Exception as e:
                self.is_connected = False
                logger.error(f"❌ Database connection test failed (attempt {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    wait_time = min(2 ** attempt, 10)  # Cap at 10 seconds
                    logger.info(f"⏳ Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    
        return False
    
    def get_session(self) -> Session:
        """Get new database session with enhanced error handling"""
        if not self.SessionLocal:
            raise DatabaseConnectionError("Database not initialized")
        
        try:
            session = self.SessionLocal()
            # Test the session with a simple query
            session.execute(text("SELECT 1"))
            logger.debug("🔗 New database session established")
            return session
        except Exception as e:
            logger.error(f"Failed to create database session: {e}")
            raise DatabaseSessionError(f"Session creation failed: {e}")
    
    @contextmanager
    def get_db_session(self) -> Generator[Session, None, None]:
        """Enhanced context manager for database sessions with comprehensive error handling"""
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
            # Check if it's a network-related error
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['timeout', 'connection', 'network', 'tcp']):
                logger.error("🌐 Network-related database error detected")
                # Try to recreate engine for network issues
                try:
                    self._initialize_engine()
                except Exception as reinit_error:
                    logger.error(f"❌ Failed to reinitialize engine: {reinit_error}")
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
    
    def get_table_count(self, table_name: str) -> int:
        """Get record count for a table with error handling"""
        try:
            query = f"SELECT COUNT(*) as count FROM [{table_name}]"
            with self.get_db_session() as session:
                result = session.execute(text(query))
                row = result.fetchone()
                return row[0] if row else 0
        except Exception as e:
            logger.error(f"❌ Error getting count for table {table_name}: {e}")
            return -1
    
    def check_table_exists(self, table_name: str, schema: str = 'dbo') -> bool:
        """Check if table exists in database with schema support"""
        try:
            query = """
                SELECT COUNT(*) as table_count
                FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_NAME = :table_name
                AND TABLE_SCHEMA = :schema
            """
            with self.get_db_session() as session:
                result = session.execute(text(query), {
                    "table_name": table_name,
                    "schema": schema
                })
                row = result.fetchone()
                return row and row[0] > 0
                
        except Exception as e:
            logger.error(f"❌ Error checking table existence {table_name}: {e}")
            return False
    
    def get_database_info(self) -> Dict:
        """Get comprehensive database information and statistics"""
        try:
            info = {}
            
            with self.get_db_session() as session:
                # Enhanced database info for network diagnosis
                basic_info_query = """
                    SELECT 
                        @@VERSION as version,
                        DB_NAME() as database_name,
                        @@SERVERNAME as server_name,
                        GETDATE() as current_datetime,
                        @@SPID as session_id,
                        HOST_NAME() as host_name,
                        SUSER_NAME() as user_name,
                        @@CONNECTIONS as total_connections,
                        @@CPU_BUSY as cpu_busy,
                        @@IDLE as idle_time
                """
                result = session.execute(text(basic_info_query))
                row = result.fetchone()
                if row:
                    info = {
                        'version': row.version,
                        'database_name': row.database_name,
                        'server_name': row.server_name,
                        'current_datetime': row.current_datetime.isoformat() if row.current_datetime else None,
                        'session_id': row.session_id,
                        'host_name': row.host_name,
                        'user_name': row.user_name,
                        'total_connections': row.total_connections,
                        'cpu_busy': row.cpu_busy,
                        'idle_time': row.idle_time
                    }
                
                # EDR system tables information
                edr_tables = [
                    'Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 
                    'SystemConfig', 'AgentConfigs'
                ]
                
                tables_info = []
                for table in edr_tables:
                    if self.check_table_exists(table):
                        record_count = self.get_table_count(table)
                        tables_info.append({
                            'table_name': table,
                            'record_count': record_count,
                            'exists': True
                        })
                    else:
                        tables_info.append({
                            'table_name': table,
                            'exists': False
                        })
                
                info['edr_tables'] = tables_info
                
                # Database size info
                try:
                    size_query = """
                        SELECT 
                            SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint) * 8192.) / 1024 / 1024 as used_space_mb,
                            SUM(CAST(size AS bigint) * 8192.) / 1024 / 1024 as allocated_space_mb
                        FROM sys.database_files 
                        WHERE type_desc = 'ROWS'
                    """
                    result = session.execute(text(size_query))
                    row = result.fetchone()
                    if row:
                        info['size_mb'] = row.used_space_mb
                        info['allocated_mb'] = row.allocated_space_mb
                except Exception as e:
                    logger.debug(f"Could not get database size: {e}")
                    info['size_mb'] = 0
                    info['allocated_mb'] = 0
                
            return info
            
        except Exception as e:
            logger.error(f"❌ Error getting database info: {e}")
            return {'error': str(e)}
    
    def health_check(self, force_check: bool = False) -> Dict:
        """Comprehensive database health check for EDR system with network diagnostics"""
        start_time = time.time()
        health_status = {
            'healthy': False,
            'response_time_ms': 0,
            'database_info': {},
            'table_counts': {},
            'edr_system_status': {},
            'network_status': {},
            'errors': [],
            'warnings': [],
            'last_checked': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Test basic connection with network diagnostics
            logger.debug("🔍 Testing database connection...")
            connection_start = time.time()
            if not self.test_connection():
                health_status['errors'].append('Database connection failed')
                health_status['network_status'] = {
                    'connection_time_ms': int((time.time() - connection_start) * 1000),
                    'status': 'failed'
                }
                return health_status
            
            connection_time = int((time.time() - connection_start) * 1000)
            health_status['network_status'] = {
                'connection_time_ms': connection_time,
                'status': 'success'
            }
            
            # Step 2: Get database info
            logger.debug("🔍 Retrieving database information...")
            db_info = self.get_database_info()
            health_status['database_info'] = db_info
            
            # Step 3: Check EDR core tables
            logger.debug("🔍 Checking EDR tables...")
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            missing_tables = []
            
            for table in edr_tables:
                if self.check_table_exists(table):
                    count = self.get_table_count(table)
                    health_status['table_counts'][table] = count
                    logger.debug(f"📊 Table {table}: {count:,} records")
                else:
                    missing_tables.append(table)
                    health_status['errors'].append(f'Critical table {table} not found')
            
            if missing_tables:
                health_status['errors'].append(f"Missing tables: {', '.join(missing_tables)}")
            
            # Step 4: EDR system specific health checks
            logger.debug("🔍 Checking EDR system health...")
            edr_status = self._check_edr_system_health()
            health_status['edr_system_status'] = edr_status
            
            # Step 5: Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Step 6: Network performance analysis
            if health_status['response_time_ms'] > 1000:
                health_status['warnings'].append(f"Slow database response time: {health_status['response_time_ms']}ms")
            
            # Step 7: Determine overall health
            health_status['healthy'] = len(health_status['errors']) == 0
            
            # Log results
            if health_status['healthy']:
                logger.info(f"✅ Database health check passed in {health_status['response_time_ms']}ms")
            else:
                logger.warning(f"⚠️ Database health check issues found in {health_status['response_time_ms']}ms")
                for error in health_status['errors']:
                    logger.error(f"   ❌ {error}")
            
        except Exception as e:
            health_status['errors'].append(f'Health check failed: {str(e)}')
            logger.error(f"💥 Database health check failed: {e}")
        
        return health_status
    
    def _check_edr_system_health(self) -> Dict:
        """Check EDR system specific health metrics"""
        edr_status = {}
        
        try:
            with self.get_db_session() as session:
                # Check for recent agent activity (last 10 minutes)
                recent_agents_query = """
                    SELECT COUNT(*) as count 
                    FROM Agents 
                    WHERE LastHeartbeat >= DATEADD(minute, -10, GETDATE())
                    AND Status = 'Active'
                """
                result = session.execute(text(recent_agents_query))
                row = result.fetchone()
                edr_status['active_agents_last_10min'] = row[0] if row else 0
                
                # Check for recent events (last hour)
                recent_events_query = """
                    SELECT COUNT(*) as count 
                    FROM Events 
                    WHERE CreatedAt >= DATEADD(hour, -1, GETDATE())
                """
                result = session.execute(text(recent_events_query))
                row = result.fetchone()
                edr_status['events_last_hour'] = row[0] if row else 0
                
                # Check for open alerts
                open_alerts_query = """
                    SELECT COUNT(*) as count 
                    FROM Alerts 
                    WHERE Status IN ('Open', 'Investigating')
                """
                result = session.execute(text(open_alerts_query))
                row = result.fetchone()
                edr_status['open_alerts'] = row[0] if row else 0
                
                # Check for critical alerts
                critical_alerts_query = """
                    SELECT COUNT(*) as count 
                    FROM Alerts 
                    WHERE Status IN ('Open', 'Investigating')
                    AND Severity IN ('High', 'Critical')
                """
                result = session.execute(text(critical_alerts_query))
                row = result.fetchone()
                edr_status['critical_alerts'] = row[0] if row else 0
                
                # Check detection rules
                active_rules_query = """
                    SELECT COUNT(*) as count 
                    FROM DetectionRules 
                    WHERE IsActive = 1
                """
                result = session.execute(text(active_rules_query))
                row = result.fetchone()
                edr_status['active_detection_rules'] = row[0] if row else 0
                
                # Check threat indicators
                active_threats_query = """
                    SELECT COUNT(*) as count 
                    FROM Threats 
                    WHERE IsActive = 1
                """
                result = session.execute(text(active_threats_query))
                row = result.fetchone()
                edr_status['active_threat_indicators'] = row[0] if row else 0
                
        except Exception as e:
            logger.error(f"❌ EDR system health check failed: {e}")
            edr_status['error'] = str(e)
        
        return edr_status
    
    def cleanup(self):
        """Clean up database connections and resources"""
        try:
            if self.engine:
                # Close all connections
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
        # Re-raise database errors
        raise
    except Exception as e:
        if session:
            session.rollback()
        logger.error(f"💥 Database session error in dependency: {e}")
        raise DatabaseError(f"Database session error: {e}")
    finally:
        if session:
            session.close()

# Initialization and utility functions
def init_database() -> bool:
    """Initialize database connection and verify EDR schema with network support"""
    try:
        logger.info("🔄 Initializing EDR database connection...")
        
        # Test database connection with retries for network
        if not db_manager.test_connection(retry_count=5):
            logger.error("❌ Database connection test failed after retries")
            logger.error("💡 Check network connectivity to SQL Server")
            logger.error(f"💡 Verify SQL Server is running on {config['database']['server']}")
            return False
        
        # Get database info
        db_info = db_manager.get_database_info()
        if 'error' in db_info:
            logger.error(f"❌ Database info retrieval failed: {db_info['error']}")
            return False
        
        logger.info(f"🗄️ Connected to: {db_info.get('database_name')} on {db_info.get('server_name')}")
        logger.info(f"📊 SQL Server Version: {db_info.get('version', 'Unknown')[:50]}...")
        logger.info(f"👤 Connection User: {db_info.get('user_name', 'Unknown')}")
        logger.info(f"🖥️ Host: {db_info.get('host_name', 'Unknown')}")
        
        # Verify EDR critical tables exist
        edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
        missing_tables = []
        existing_tables = []
        
        for table in edr_tables:
            if db_manager.check_table_exists(table):
                existing_tables.append(table)
            else:
                missing_tables.append(table)
        
        if missing_tables:
            logger.error(f"❌ Missing critical EDR tables: {missing_tables}")
            logger.error("💡 Please run the database creation script first")
            logger.info(f"✅ Found existing tables: {existing_tables}")
            return False
        
        logger.info(f"✅ All EDR tables verified: {edr_tables}")
        
        # Log table counts for monitoring
        total_records = 0
        for table in edr_tables:
            count = db_manager.get_table_count(table)
            logger.info(f"📊 {table}: {count:,} records")
            if count > 0:
                total_records += count
        
        logger.info(f"📈 Total EDR records: {total_records:,}")
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Database initialization failed: {e}")
        logger.error("💡 Common issues:")
        logger.error("   • SQL Server not running or not accessible")
        logger.error("   • Firewall blocking connection")
        logger.error("   • Authentication failure")
        logger.error("   • Database does not exist")
        return False

def get_database_status() -> Dict:
    """Get current database status for monitoring and health checks"""
    try:
        return db_manager.health_check()
    except Exception as e:
        logger.error(f"Failed to get database status: {e}")
        return {
            'healthy': False,
            'error': str(e),
            'last_checked': datetime.now().isoformat()
        }

# Shutdown cleanup
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