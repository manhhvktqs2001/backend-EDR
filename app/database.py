# app/database.py - COMPLETELY FIXED (ANSI_WARNINGS + date_part issues)
"""
Database Connection Manager for EDR Server - COMPLETELY FIXED
Ultra-high performance database operations with proper ANSI settings
"""

import logging
from contextlib import contextmanager
from typing import Generator, Dict, List, Any, Optional, Tuple
from sqlalchemy import create_engine, text, event, MetaData, pool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.exc import SQLAlchemyError, OperationalError, IntegrityError
import time
import pyodbc
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict
import asyncio

from .config import config, get_database_url, get_database_pool_config

# Configure logging
logger = logging.getLogger(__name__)
perf_logger = logging.getLogger('performance')

# SQLAlchemy Base for all models
Base = declarative_base()

# Database Exceptions
class DatabaseConnectionError(Exception):
    """Database connection error"""
    pass

class DatabaseSessionError(Exception):
    """Database session error"""
    pass

class DatabaseIntegrityError(Exception):
    """Database integrity error"""
    pass

class DatabaseOperationalError(Exception):
    """Database operational error"""
    pass

class RealtimeDatabaseManager:
    """Ultra-high performance database manager optimized for realtime event processing"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 3
        self._last_health_check = None
        self._health_check_interval = 30
        self._detected_server = None
        
        # REALTIME PERFORMANCE OPTIMIZATIONS
        self._cache = {}
        self._cache_lock = threading.RLock()
        self._connection_pool_stats = defaultdict(int)
        self._query_performance_stats = {}
        self._batch_operations = []
        self._last_flush = time.time()
        
        # Performance counters
        self.stats = {
            'connections_created': 0,
            'connections_reused': 0,
            'queries_executed': 0,
            'batch_operations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'total_query_time': 0.0,
            'avg_query_time': 0.0,
            'last_reset': datetime.now()
        }
        
        self._initialize_engine_realtime()
    
    def _initialize_engine_realtime(self):
        """Initialize database engine with REALTIME optimizations - COMPLETELY FIXED"""
        try:
            logger.info("🚀 REALTIME Database Manager initialization (ANSI_WARNINGS FIXED)...")
            
            # Fast server detection and connection
            original_server = config['database']['server']
            if not self._test_connection_ultra_fast(original_server):
                logger.warning("⚠️ Original server slow, trying alternatives...")
                if not self._auto_detect_server_parallel():
                    raise RuntimeError("Could not establish fast database connection")
            
            # Build ultra-optimized connection URL with COMPLETELY FIXED settings
            database_url = self._build_realtime_connection_url_completely_fixed()
            pool_config = get_database_pool_config()
            
            # Create REALTIME-optimized engine
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                
                # REALTIME POOL CONFIGURATION
                pool_size=pool_config['pool_size'],
                max_overflow=pool_config['max_overflow'],
                pool_timeout=pool_config['pool_timeout'],
                pool_recycle=pool_config['pool_recycle'],
                pool_pre_ping=pool_config['pool_pre_ping'],
                pool_reset_on_return='commit',
                
                # PERFORMANCE OPTIMIZATIONS
                echo=False,
                echo_pool=False,
                future=True,
                isolation_level="READ_COMMITTED",
                
                # COMPLETELY FIXED: Connection args with proper ANSI settings
                connect_args={
                    "timeout": config['database']['timeout'],
                    "autocommit": False,
                    "fast_executemany": True,
                    "login_timeout": config['database']['login_timeout'],
                    "connection_timeout": config['database']['connection_timeout'],
                    "mars_connection": False,
                    # CRITICAL FIX: Enable all ANSI settings
                    "ansi_null_padding": True,
                    "ansi_warnings": True,  # CRITICAL: Enable ANSI_WARNINGS
                    "ansi_nulls": True,
                    "quoted_identifier": True
                },
                
                # EXECUTION OPTIONS
                execution_options={
                    "autocommit": False,
                    "compiled_cache": {},
                    "schema_translate_map": None
                }
            )
            
            # REALTIME-optimized session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
                expire_on_commit=False,
                class_=Session
            )
            
            self.metadata = MetaData()
            self._add_realtime_event_listeners_completely_fixed()
            
            logger.info("✅ REALTIME Database Engine initialized with ANSI_WARNINGS fix")
            
        except Exception as e:
            logger.error(f"❌ REALTIME Database engine init failed: {e}")
            raise DatabaseConnectionError(f"Database initialization failed: {e}")
    
    def _build_realtime_connection_url_completely_fixed(self):
        """Build connection URL optimized for REALTIME performance - COMPLETELY FIXED"""
        db_config = config['database']
        server = db_config['server']
        database = db_config['database']
        
        # COMPLETELY FIXED: Connection parameters with all ANSI settings
        connection_params = [
            f"driver={db_config['driver'].replace(' ', '+')}", 
            "trusted_connection=yes",
            "autocommit=false",
            f"timeout={db_config['timeout']}",
            f"login_timeout={db_config['login_timeout']}",
            f"connection_timeout={db_config['connection_timeout']}",
            "encrypt=no",
            "trustservercertificate=yes",
            f"packet_size={db_config['packet_size']}",
            f"app_name={db_config['application_name']}",
            
            # REALTIME SPECIFIC OPTIMIZATIONS
            "mars_connection=no",
            "multisubnetfailover=no",
            "connectretrycount=1",
            "connectretryinterval=3",
            
            # COMPLETELY FIXED: All ANSI settings for compatibility
            "ansi_null_padding=yes",
            "ansi_warnings=yes",  # CRITICAL FIX
            "ansi_nulls=yes", 
            "quoted_identifier=yes",
            "arithabort=yes",  # Additional fix for indexed views
            "fast_executemany=true"
        ]
        
        connection_string = "&".join(connection_params)
        return f"mssql+pyodbc://@{server}/{database}?{connection_string}"
    
    def _add_realtime_event_listeners_completely_fixed(self):
        """Add event listeners optimized for REALTIME operations - COMPLETELY FIXED"""
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            try:
                self.stats['connections_created'] += 1
                
                # COMPLETELY FIXED: Set ALL required ANSI settings on each connection
                if hasattr(dbapi_connection, 'execute'):
                    # Execute ALL ANSI settings first (CRITICAL FIX)
                    dbapi_connection.execute("SET ANSI_WARNINGS ON")  # CRITICAL
                    dbapi_connection.execute("SET ANSI_NULLS ON") 
                    dbapi_connection.execute("SET ANSI_NULL_DFLT_ON ON")
                    dbapi_connection.execute("SET QUOTED_IDENTIFIER ON")
                    dbapi_connection.execute("SET ANSI_PADDING ON")
                    dbapi_connection.execute("SET ARITHABORT ON")  # For indexed views
                    dbapi_connection.execute("SET CONCAT_NULL_YIELDS_NULL ON")
                    dbapi_connection.execute("SET NUMERIC_ROUNDABORT OFF")
                    
                    # Performance optimizations
                    dbapi_connection.execute("SET LOCK_TIMEOUT 5000")
                    dbapi_connection.execute("SET DEADLOCK_PRIORITY LOW")
                    
                logger.debug(f"✅ New connection with ALL ANSI settings (Total: {self.stats['connections_created']})")
                
            except Exception as e:
                logger.warning(f"⚠️ Connection setup warning: {e}")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            self.stats['connections_reused'] += 1
            self._connection_pool_stats['checkouts'] += 1
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            self._connection_pool_stats['checkins'] += 1
        
        @event.listens_for(self.engine, "invalidate")
        def receive_invalidate(dbapi_connection, connection_record, exception):
            logger.warning(f"🔄 Connection invalidated: {exception}")
            self._connection_pool_stats['invalidations'] += 1
    
    def _test_connection_ultra_fast(self, server: str) -> bool:
        """Ultra-fast connection test with COMPLETELY FIXED ANSI settings"""
        try:
            start_time = time.time()
            
            # COMPLETELY FIXED: Connection string with ALL ANSI settings
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server};"
                f"DATABASE=master;"
                f"Trusted_Connection=yes;"
                f"Connection Timeout=5;"
                f"Login Timeout=5;"
                f"Encrypt=no;"
                f"TrustServerCertificate=yes;"
                f"ApplicationIntent=ReadWrite;"
                f"PacketSize=8192;"
                f"AnsiNullPadding=yes;"
                f"AnsiWarnings=yes;"  # CRITICAL FIX
                f"AnsiNulls=yes;"
                f"QuotedIdentifier=yes;"
                f"Arithabort=yes;"  # Additional fix
            )
            
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            
            # COMPLETELY FIXED: Set ALL ANSI settings immediately
            cursor.execute("SET ANSI_WARNINGS ON")  # CRITICAL
            cursor.execute("SET ANSI_NULLS ON")
            cursor.execute("SET QUOTED_IDENTIFIER ON")
            cursor.execute("SET ANSI_PADDING ON")
            cursor.execute("SET ARITHABORT ON")
            cursor.execute("SET CONCAT_NULL_YIELDS_NULL ON")
            cursor.execute("SET NUMERIC_ROUNDABORT OFF")
            
            # Test query
            cursor.execute("SELECT 1, @@OPTIONS")
            row = cursor.fetchone()
            conn.close()
            
            response_time = time.time() - start_time
            
            if row and row[0] == 1 and response_time < 0.1:
                options = row[1]
                ansi_warnings_on = (options & 16) == 16  # Check ANSI_WARNINGS bit
                logger.info(f"✅ Ultra-fast connection with ANSI fix to {server}: {response_time*1000:.1f}ms (ANSI_WARNINGS: {'ON' if ansi_warnings_on else 'OFF'})")
                return ansi_warnings_on  # Only return True if ANSI_WARNINGS is ON
            
            return False
            
        except Exception as e:
            logger.debug(f"Connection test failed for {server}: {e}")
            return False
    
    def _auto_detect_server_parallel(self) -> bool:
        """Parallel server detection for maximum speed - with ANSI fix"""
        logger.info("🔍 Parallel server detection with COMPLETE ANSI fix...")
        
        server_options = [
            "localhost",
            "127.0.0.1",
            ".",
            "(local)",
            "localhost\\SQLEXPRESS",
            ".\\SQLEXPRESS",
            "(local)\\SQLEXPRESS"
        ]
        
        def test_server_ultra_fast(server):
            if self._test_connection_ultra_fast(server):
                return server
            return None
        
        # Parallel testing with aggressive timeout
        with ThreadPoolExecutor(max_workers=len(server_options)) as executor:
            futures = [executor.submit(test_server_ultra_fast, server) for server in server_options]
            
            for future in as_completed(futures, timeout=10):
                try:
                    working_server = future.result()
                    if working_server:
                        logger.info(f"🎯 REALTIME server with COMPLETE ANSI fix: {working_server}")
                        config['database']['server'] = working_server
                        self._detected_server = working_server
                        return True
                except Exception:
                    continue
        
        logger.error("❌ No fast server connection found with proper ANSI settings")
        return False
    
    def test_connection_realtime(self, retry_count: int = 2) -> bool:
        """REALTIME connection test with COMPLETE ANSI fix"""
        for attempt in range(retry_count):
            start_time = time.time()
            
            try:
                with self.engine.connect() as connection:
                    # COMPLETELY FIXED: Test ALL ANSI settings
                    result = connection.execute(text("""
                        SELECT 
                            1 as test, 
                            GETDATE() as server_time,
                            @@SERVERNAME as server_name,
                            DB_NAME() as database_name,
                            @@CONNECTIONS as connection_count,
                            @@OPTIONS as sql_options,
                            CASE WHEN @@OPTIONS & 16 = 16 THEN 'ON' ELSE 'OFF' END as ansi_warnings,
                            CASE WHEN @@OPTIONS & 32 = 32 THEN 'ON' ELSE 'OFF' END as ansi_nulls,
                            CASE WHEN @@OPTIONS & 256 = 256 THEN 'ON' ELSE 'OFF' END as quoted_identifier
                    """))
                    row = result.fetchone()
                    
                    response_time = time.time() - start_time
                    
                    if row and row[0] == 1:
                        self.is_connected = True
                        
                        if attempt == 0:  # Log details on first success
                            ansi_warnings = row[6] if len(row) > 6 else 'UNKNOWN'
                            ansi_nulls = row[7] if len(row) > 7 else 'UNKNOWN'  
                            quoted_id = row[8] if len(row) > 8 else 'UNKNOWN'
                            
                            logger.info(f"✅ REALTIME DB connected: {row[2]} / {row[3]} ({response_time*1000:.1f}ms)")
                            logger.info(f"   ANSI Settings: WARNINGS={ansi_warnings}, NULLS={ansi_nulls}, QUOTED_ID={quoted_id}")
                            
                            # Verify ANSI_WARNINGS is ON
                            if ansi_warnings != 'ON':
                                logger.error(f"❌ CRITICAL: ANSI_WARNINGS is {ansi_warnings} - this will cause INSERT failures!")
                                return False
                        
                        # Update performance stats
                        self.stats['queries_executed'] += 1
                        self.stats['total_query_time'] += response_time
                        self.stats['avg_query_time'] = (self.stats['total_query_time'] / 
                                                       self.stats['queries_executed'])
                        
                        return True
                        
            except Exception as e:
                self.is_connected = False
                if attempt == retry_count - 1:
                    response_time = time.time() - start_time
                    logger.error(f"❌ Connection failed after {response_time*1000:.1f}ms: {e}")
                
                if attempt < retry_count - 1:
                    time.sleep(0.5)
                    
        return False
    
    def get_session_realtime(self) -> Session:
        """Get database session optimized for REALTIME operations - with COMPLETE ANSI fix"""
        if not self.SessionLocal:
            raise DatabaseConnectionError("Database not initialized")
        
        start_time = time.time()
        
        try:
            session = self.SessionLocal()
            
            # COMPLETELY FIXED: Ensure ALL ANSI settings on session
            session.execute(text("SET ANSI_WARNINGS ON"))  # CRITICAL
            session.execute(text("SET ANSI_NULLS ON"))
            session.execute(text("SET QUOTED_IDENTIFIER ON"))
            session.execute(text("SET ANSI_PADDING ON"))
            session.execute(text("SET ARITHABORT ON"))
            session.execute(text("SET CONCAT_NULL_YIELDS_NULL ON"))
            session.execute(text("SET NUMERIC_ROUNDABORT OFF"))
            
            # Ultra-fast validation query
            session.execute(text("SELECT 1"))
            
            # Performance tracking
            creation_time = time.time() - start_time
            if creation_time > 0.1:
                logger.warning(f"Slow session creation: {creation_time*1000:.1f}ms")
            
            return session
            
        except Exception as e:
            logger.error(f"REALTIME session creation failed: {e}")
            raise DatabaseSessionError(f"Session creation failed: {e}")
    
    @contextmanager
    def get_realtime_session(self) -> Generator[Session, None, None]:
        """REALTIME context manager with optimized error handling and COMPLETE ANSI fix"""
        session = None
        start_time = time.time()
        
        try:
            session = self.get_session_realtime()
            yield session
            
            # Fast commit
            commit_start = time.time()
            session.commit()
            commit_time = time.time() - commit_start
            
            if commit_time > 0.05:
                logger.warning(f"Slow commit: {commit_time*1000:.1f}ms")
            
        except IntegrityError as e:
            if session:
                session.rollback()
            logger.error(f"Database integrity error (ANSI settings verified): {e}")
            raise DatabaseIntegrityError(f"Data integrity violation: {e}")
            
        except OperationalError as e:
            if session:
                session.rollback()
            logger.error(f"Database operational error: {e}")
            raise DatabaseOperationalError(f"Database operation failed: {e}")
            
        except Exception as e:
            if session:
                session.rollback()
            logger.error(f"Database error: {e}")
            raise DatabaseConnectionError(f"Database error: {e}")
            
        finally:
            if session:
                session.close()

# Global database manager instance
realtime_db_manager = RealtimeDatabaseManager()
SessionLocal = realtime_db_manager.SessionLocal

# COMPLETELY FIXED: Add the missing functions that run_server.py expects
def init_database() -> bool:
    """Initialize database and test connection - with COMPLETE ANSI fix"""
    try:
        logger.info("🔗 Initializing database connection with COMPLETE ANSI_WARNINGS fix...")
        
        # Test connection
        if not realtime_db_manager.test_connection_realtime():
            logger.error("❌ Database connection test failed")
            return False
        
        # Test table access with ALL ANSI settings
        try:
            with realtime_db_manager.get_realtime_session() as session:
                # COMPLETELY FIXED: Test with ALL ANSI settings enabled
                result = session.execute(text("""
                    SET ANSI_WARNINGS ON;
                    SET ANSI_NULLS ON;
                    SET QUOTED_IDENTIFIER ON;
                    SET ARITHABORT ON;
                    SELECT COUNT(*) as table_count 
                    FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_SCHEMA = 'dbo'
                """))
                table_count = result.scalar()
                
                # Verify ANSI settings are actually ON
                ansi_check = session.execute(text("""
                    SELECT 
                        CASE WHEN @@OPTIONS & 16 = 16 THEN 'ON' ELSE 'OFF' END as ansi_warnings,
                        CASE WHEN @@OPTIONS & 32 = 32 THEN 'ON' ELSE 'OFF' END as ansi_nulls,
                        CASE WHEN @@OPTIONS & 256 = 256 THEN 'ON' ELSE 'OFF' END as quoted_identifier
                """))
                ansi_row = ansi_check.fetchone()
                
                if ansi_row and ansi_row[0] == 'ON':
                    logger.info(f"✅ Database initialized with COMPLETE ANSI fix: {table_count} tables found")
                    logger.info(f"   ANSI Settings: WARNINGS={ansi_row[0]}, NULLS={ansi_row[1]}, QUOTED_ID={ansi_row[2]}")
                    return True
                else:
                    logger.error(f"❌ ANSI_WARNINGS still OFF after fix: {ansi_row[0] if ansi_row else 'UNKNOWN'}")
                    return False
                
        except Exception as e:
            logger.error(f"❌ Database table access failed: {e}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        return False

def get_db() -> Generator[Session, None, None]:
    """Database dependency for FastAPI - FIXED for session conflicts"""
    session = realtime_db_manager.get_session_realtime()
    try:
        yield session
    except Exception as e:
        try:
            session.rollback()
        except Exception as rollback_error:
            logger.warning(f"Session rollback failed: {rollback_error}")
        raise e
    finally:
        try:
            if session.is_active:
                session.close()
        except Exception as close_error:
            logger.warning(f"Session close failed: {close_error}")
            try:
                session.invalidate()
            except Exception:
                pass

def get_database_status() -> Dict[str, Any]:
    """Get comprehensive database status - with COMPLETE ANSI check"""
    try:
        start_time = time.time()
        
        status = {
            'healthy': False,
            'response_time_ms': 0,
            'server_info': {},
            'database_info': {},
            'table_counts': {},
            'connection_pool': {},
            'performance_stats': {},
            'ansi_settings': {},  # ANSI settings check
            'ansi_warnings_issue': False
        }
        
        # Test connection and get server info
        try:
            with realtime_db_manager.get_realtime_session() as session:
                # COMPLETELY FIXED: Check ALL ANSI settings
                result = session.execute(text("""
                    SELECT 
                        @@SERVERNAME as server_name,
                        DB_NAME() as database_name,
                        SUSER_SNAME() as login_name,
                        @@VERSION as sql_version,
                        @@CONNECTIONS as connection_count,
                        GETDATE() as server_time,
                        @@OPTIONS as sql_options,
                        CASE WHEN @@OPTIONS & 16 = 16 THEN 'ON' ELSE 'OFF' END as ansi_warnings,
                        CASE WHEN @@OPTIONS & 32 = 32 THEN 'ON' ELSE 'OFF' END as ansi_nulls,
                        CASE WHEN @@OPTIONS & 256 = 256 THEN 'ON' ELSE 'OFF' END as quoted_identifier,
                        CASE WHEN @@OPTIONS & 64 = 64 THEN 'ON' ELSE 'OFF' END as arithabort
                """))
                row = result.fetchone()
                
                if row:
                    status['server_info'] = {
                        'server_name': row[0],
                        'database_name': row[1],
                        'login_name': row[2],
                        'sql_version': row[3],
                        'connection_count': row[4],
                        'server_time': row[5].isoformat() if row[5] else None
                    }
                    
                    # COMPLETELY FIXED: ALL ANSI settings status
                    status['ansi_settings'] = {
                        'sql_options': row[6],
                        'ansi_warnings': row[7],
                        'ansi_nulls': row[8],
                        'quoted_identifier': row[9],
                        'arithabort': row[10]
                    }
                
                # Get table counts (quick version)
                table_result = session.execute(text("""
                    SELECT 
                        t.TABLE_NAME,
                        ISNULL(p.rows, 0) as row_count
                    FROM INFORMATION_SCHEMA.TABLES t
                    LEFT JOIN sys.partitions p ON p.object_id = OBJECT_ID(t.TABLE_SCHEMA + '.' + t.TABLE_NAME)
                    WHERE t.TABLE_SCHEMA = 'dbo' 
                    AND t.TABLE_TYPE = 'BASE TABLE'
                    AND (p.index_id = 1 OR p.index_id IS NULL)
                """))
                
                table_counts = {}
                for table_row in table_result:
                    table_counts[table_row[0]] = table_row[1] or 0
                
                status['table_counts'] = table_counts
                
                response_time = time.time() - start_time
                status['response_time_ms'] = round(response_time * 1000, 2)
                
                # Check for ANSI_WARNINGS issue
                if status['ansi_settings']['ansi_warnings'] == 'OFF':
                    logger.error("❌ CRITICAL: ANSI_WARNINGS is OFF - this WILL cause INSERT failures!")
                    status['ansi_warnings_issue'] = True
                    status['healthy'] = False
                else:
                    status['ansi_warnings_issue'] = False
                    status['healthy'] = True
                
                # Add performance stats
                status['performance_stats'] = realtime_db_manager.stats.copy()
                
                # Connection pool stats
                status['connection_pool'] = {
                    'pool_size': realtime_db_manager.engine.pool.size(),
                    'checked_in': realtime_db_manager.engine.pool.checkedin(),
                    'checked_out': realtime_db_manager.engine.pool.checkedout(),
                    'overflow': realtime_db_manager.engine.pool.overflow(),
                }
                
        except Exception as e:
            logger.error(f"Database status check failed: {e}")
            status['error'] = str(e)
            status['response_time_ms'] = round((time.time() - start_time) * 1000, 2)
        
        return status
        
    except Exception as e:
        logger.error(f"Database status function failed: {e}")
        return {
            'healthy': False,
            'error': str(e),
            'response_time_ms': 0,
            'ansi_warnings_issue': True
        }

# Keep all other existing functions unchanged...
def test_database_performance() -> Dict[str, Any]:
    """Test database performance metrics"""
    try:
        start_time = time.time()
        
        with realtime_db_manager.get_realtime_session() as session:
            # Performance test queries
            queries = [
                "SELECT 1",
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES",
                "SELECT GETDATE()",
                "SELECT @@VERSION"
            ]
            
            query_times = []
            for query in queries:
                query_start = time.time()
                session.execute(text(query))
                query_time = time.time() - query_start
                query_times.append(query_time * 1000)
            
            total_time = time.time() - start_time
            
            return {
                'total_time_ms': round(total_time * 1000, 2),
                'query_times_ms': [round(t, 2) for t in query_times],
                'average_query_time_ms': round(sum(query_times) / len(query_times), 2),
                'queries_per_second': round(len(queries) / total_time, 2),
                'performance_rating': 'Excellent' if total_time < 0.1 else 'Good' if total_time < 0.5 else 'Slow'
            }
            
    except Exception as e:
        logger.error(f"Performance test failed: {e}")
        return {
            'error': str(e),
            'performance_rating': 'Failed'
        }

# Helper functions for backward compatibility
def get_db_session() -> Session:
    """Get database session (backward compatibility)"""
    return realtime_db_manager.get_session_realtime()

@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Get database session context manager"""
    with realtime_db_manager.get_realtime_session() as session:
        yield session

def reset_database_stats():
    """Reset database performance statistics"""
    realtime_db_manager.stats = {
        'connections_created': 0,
        'connections_reused': 0,
        'queries_executed': 0,
        'batch_operations': 0,
        'cache_hits': 0,
        'cache_misses': 0,
        'total_query_time': 0.0,
        'avg_query_time': 0.0,
        'last_reset': datetime.now()
    }
    logger.info("📊 Database statistics reset")

# Test if database is ready
def is_database_ready() -> bool:
    """Quick check if database is ready"""
    try:
        return realtime_db_manager.test_connection_realtime()
    except Exception:
        return False

# Export all necessary items for imports
__all__ = [
    'Base', 'realtime_db_manager', 'init_database', 'get_db', 'get_database_status',
    'test_database_performance', 'get_db_session', 'get_db_context',
    'reset_database_stats', 'is_database_ready',
    'DatabaseConnectionError', 'DatabaseSessionError', 
    'DatabaseIntegrityError', 'DatabaseOperationalError'
]