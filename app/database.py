# app/database.py - IMPROVED VERSION (Fixed for Network Server Detection)
"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server - IMPROVED for auto-detection
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
    """Enhanced Database connection and session manager for EDR System with auto-detection"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 3  # Reduced for faster startup
        self._last_health_check = None
        self._health_check_interval = 300  # 5 minutes
        self._detected_server = None
        self._initialize_engine()
    
    def _auto_detect_server(self):
        """Auto-detect working SQL Server connection"""
        logger.info("🔍 Auto-detecting SQL Server connection...")
        
        # Try different server options based on run_server.py detection
        server_options = [
            "localhost,1433",
            "localhost",
            "127.0.0.1,1433", 
            "127.0.0.1",
            "192.168.20.85,1433",  # Original config
            "192.168.20.85"
        ]
        
        for server in server_options:
            try:
                logger.debug(f"🔌 Testing: {server}")
                
                # Create test connection string
                test_config = config['database'].copy()
                test_config['server'] = server
                
                test_url = self._build_connection_url(test_config)
                test_engine = create_engine(
                    test_url,
                    pool_timeout=5,
                    connect_args={"timeout": 5, "login_timeout": 5}
                )
                
                # Test connection
                with test_engine.connect() as conn:
                    result = conn.execute(text("SELECT 1 as test, DB_NAME() as db_name"))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        logger.info(f"✅ Auto-detected working server: {server}")
                        logger.info(f"📊 Database: {row[1]}")
                        
                        # Update config to use detected server
                        config['database']['server'] = server
                        self._detected_server = server
                        test_engine.dispose()
                        return True
                
                test_engine.dispose()
                
            except Exception as e:
                logger.debug(f"   ❌ Failed: {server} - {e}")
                continue
        
        logger.error("❌ No working SQL Server connection found")
        return False
    
    def _build_connection_url(self, db_config):
        """Build connection URL with given config"""
        server = db_config['server']
        
        connection_params = [
            f"driver={db_config['driver'].replace(' ', '+')}", 
            "trusted_connection=yes" if db_config['trusted_connection'] else "trusted_connection=no",
            "autocommit=true" if db_config['autocommit'] else "autocommit=false",
            f"timeout={db_config['timeout']}",
            f"login_timeout={db_config.get('login_timeout', 30)}",
            f"connection_timeout={db_config.get('connection_timeout', 30)}",
            "encrypt=no",
            "trustservercertificate=yes"
        ]
        
        connection_string = "&".join(connection_params)
        return f"mssql+pyodbc://@{server}/{db_config['database']}?{connection_string}"
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with auto-detection"""
        try:
            # First, try auto-detection if original config fails
            original_server = config['database']['server']
            
            logger.info(f"🔗 Initializing database connection to: {original_server}/{config['database']['database']}")
            
            # Try original config first
            try:
                database_url = get_database_url()
                self._test_url(database_url)
                logger.info("✅ Using original database configuration")
            except Exception as e:
                logger.warning(f"⚠️ Original config failed: {e}")
                logger.info("🔄 Attempting auto-detection...")
                
                if not self._auto_detect_server():
                    raise RuntimeError("Could not establish database connection")
                
                # Rebuild URL with detected server
                database_url = get_database_url()
            
            perf_config = config['performance']
            
            # Create engine with optimized settings
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=perf_config['database_pool_size'],
                max_overflow=perf_config['database_max_overflow'],
                pool_timeout=perf_config['database_pool_timeout'],
                pool_pre_ping=True,  # Essential for network connections
                pool_recycle=perf_config.get('database_pool_recycle', 1800),
                echo=config['server']['debug'],
                echo_pool=False,
                future=True,
                isolation_level="READ_COMMITTED",
                connect_args={
                    "timeout": config['database']['timeout'],
                    "autocommit": False,
                    "check_same_thread": False,
                    "login_timeout": config['database'].get('login_timeout', 30),
                    "connection_timeout": config['database'].get('connection_timeout', 30),
                    "packet_size": config['database'].get('packet_size', 4096),
                    "app_name": config['database'].get('application_name', 'EDR_Agent_Server')
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
    
    def _test_url(self, url):
        """Test database URL"""
        test_engine = create_engine(url, pool_timeout=5)
        with test_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        test_engine.dispose()
    
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
        """Enhanced connection test with faster retry"""
        for attempt in range(retry_count):
            try:
                with self.engine.connect() as connection:
                    result = connection.execute(text("""
                        SELECT 
                            1 as test, 
                            GETDATE() as server_time,
                            @@SERVERNAME as server_name,
                            DB_NAME() as database_name
                    """))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        self.is_connected = True
                        server_time = row[1]
                        server_name = row[2]
                        database_name = row[3]
                        logger.info(f"✅ Database connection verified (attempt {attempt + 1}/{retry_count})")
                        logger.info(f"🕐 Server time: {server_time}")
                        logger.info(f"🖥️ Server: {server_name}, Database: {database_name}")
                        return True
                    else:
                        raise Exception("Unexpected test query result")
                        
            except Exception as e:
                self.is_connected = False
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
            # Quick test
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
        """FASTER database health check"""
        start_time = time.time()
        health_status = {
            'healthy': False,
            'response_time_ms': 0,
            'detected_server': self._detected_server,
            'table_counts': {},
            'errors': [],
            'last_checked': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Quick connection test
            if not self.test_connection(retry_count=1):
                health_status['errors'].append('Database connection failed')
                return health_status
            
            # Step 2: Check tables exist
            table_status = self.check_tables_exist()
            missing_tables = [table for table, exists in table_status.items() if not exists]
            
            if missing_tables:
                health_status['errors'].append(f"Missing tables: {', '.join(missing_tables)}")
            
            # Step 3: Get table counts
            health_status['table_counts'] = self.get_table_counts()
            
            # Step 4: Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Step 5: Determine overall health
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

# Custom Exception Classes (same as before)
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
    """Initialize database connection and verify EDR schema - FASTER VERSION"""
    try:
        logger.info("🔄 Initializing EDR database connection...")
        
        # Test database connection
        if not db_manager.test_connection(retry_count=2):
            logger.error("❌ Database connection test failed")
            return False
        
        # Quick health check
        health_status = db_manager.health_check()
        if not health_status['healthy']:
            logger.error(f"❌ Database health check failed: {health_status['errors']}")
            return False
        
        # Log success info
        if db_manager._detected_server:
            logger.info(f"🎯 Using auto-detected server: {db_manager._detected_server}")
        
        table_counts = health_status.get('table_counts', {})
        total_records = sum(count for count in table_counts.values() if count > 0)
        
        logger.info(f"📊 Database ready - {len(table_counts)} tables, {total_records:,} total records")
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