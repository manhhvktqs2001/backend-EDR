# app/database.py - SPEED OPTIMIZED (Keep All Features, Make Faster)
"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server - SPEED OPTIMIZED while keeping all features
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
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .config import config, get_database_url

# Configure logging
logger = logging.getLogger(__name__)

# SQLAlchemy Base for all models
Base = declarative_base()

class DatabaseManager:
    """Speed optimized Database connection manager - keeps all features but faster"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 3
        self._last_health_check = None
        self._health_check_interval = 300
        self._detected_server = None
        self._cache = {}  # Cache for repeated operations
        self._cache_lock = threading.Lock()
        self._initialize_engine()
    
    def _check_sql_server_services_parallel(self):
        """Parallel service checking for speed"""
        logger.info("🔍 Fast service check...")
        
        services_to_check = [
            ("MSSQLSERVER", "SQL Server (Default Instance)"),
            ("MSSQL$SQLEXPRESS", "SQL Server Express"),
            ("MSSQL$DEVELOPER", "SQL Server Developer"),
            ("SQLBrowser", "SQL Browser Service")
        ]
        
        running_services = []
        
        def check_service(service_info):
            service_name, display_name = service_info
            try:
                result = subprocess.run(
                    ["sc", "query", service_name], 
                    capture_output=True, 
                    text=True, 
                    timeout=3  # Faster timeout
                )
                
                if "RUNNING" in result.stdout:
                    return (service_name, display_name, True)
                elif result.returncode == 0:
                    # Try quick start
                    try:
                        start_result = subprocess.run(
                            ["net", "start", service_name],
                            capture_output=True,
                            text=True,
                            timeout=15  # Faster start timeout
                        )
                        if start_result.returncode == 0:
                            return (service_name, display_name, True)
                    except:
                        pass
                    return (service_name, display_name, False)
            except:
                return (service_name, display_name, False)
            return None
        
        # Parallel execution for speed
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(check_service, service) for service in services_to_check]
            
            for future in as_completed(futures, timeout=10):
                try:
                    result = future.result()
                    if result and result[2]:  # Service is running
                        running_services.append((result[0], result[1]))
                        logger.info(f"✅ {result[1]} running")
                except:
                    continue
        
        if running_services:
            logger.info(f"✅ {len(running_services)} SQL Server services ready")
            return running_services
        else:
            logger.error("❌ No SQL Server services running")
            return []
    
    def _auto_detect_server_fast(self):
        """Fast auto-detection with parallel testing"""
        logger.info("🔍 Fast server detection...")
        
        # Check cache first
        with self._cache_lock:
            if 'working_server' in self._cache:
                cached_server = self._cache['working_server']
                if self._test_server_connection_fast(cached_server):
                    logger.info(f"🎯 Using cached server: {cached_server}")
                    config['database']['server'] = cached_server
                    self._detected_server = cached_server
                    return True
        
        # Fast service check
        running_services = self._check_sql_server_services_parallel()
        if not running_services:
            return False
        
        # Build server options based on running services
        server_options = []
        
        # Prioritize by speed (localhost first)
        if any("MSSQLSERVER" in svc[0] for svc in running_services):
            server_options.extend([
                "localhost",           # Fastest
                "127.0.0.1", 
                ".",
                "(local)"
            ])
        
        if any("SQLEXPRESS" in svc[0] for svc in running_services):
            server_options.extend([
                "localhost\\SQLEXPRESS",
                ".\\SQLEXPRESS", 
                "(local)\\SQLEXPRESS"
            ])
        
        if any("DEVELOPER" in svc[0] for svc in running_services):
            server_options.extend([
                "localhost\\DEVELOPER",
                ".\\DEVELOPER"
            ])
        
        # Add original as fallback
        original_server = config['database']['server']
        if original_server not in server_options:
            server_options.append(original_server)
        
        # Parallel connection testing for speed
        def test_server_parallel(server):
            try:
                if self._test_server_connection_fast(server):
                    return server
            except:
                pass
            return None
        
        # Test servers in parallel
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(test_server_parallel, server) for server in server_options]
            
            for future in as_completed(futures, timeout=20):  # 20s total timeout
                try:
                    working_server = future.result()
                    if working_server:
                        logger.info(f"✅ Fast detected: {working_server}")
                        config['database']['server'] = working_server
                        self._detected_server = working_server
                        
                        # Cache the result
                        with self._cache_lock:
                            self._cache['working_server'] = working_server
                        
                        return True
                except:
                    continue
        
        logger.error("❌ No working server found")
        return False
    
    def _test_server_connection_fast(self, server: str) -> bool:
        """Fast server connection test"""
        try:
            # Optimized connection string for speed
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server};"
                f"DATABASE=master;"
                f"Trusted_Connection=yes;"
                f"Connection Timeout=8;"   # Faster timeout
                f"Login Timeout=8;"
                f"Encrypt=no;"
                f"TrustServerCertificate=yes;"
                f"ApplicationIntent=ReadWrite;"
                f"ConnectRetryCount=1;"   # Single retry
            )
            
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            cursor.execute("SELECT 1, @@SERVERNAME")
            row = cursor.fetchone()
            
            if row and row[0] == 1:
                # Quick database check/creation
                cursor.execute("SELECT name FROM sys.databases WHERE name = 'EDR_System'")
                edr_db_exists = cursor.fetchone()
                
                if not edr_db_exists:
                    logger.info(f"   📦 Creating EDR_System on {server}...")
                    try:
                        cursor.execute("CREATE DATABASE EDR_System")
                        conn.commit()
                    except:
                        pass  # Don't fail if already exists
                
                conn.close()
                return True
            
            conn.close()
            return False
            
        except:
            return False
    
    def _build_connection_url_optimized(self, db_config):
        """Build optimized connection URL for speed"""
        server = db_config['server']
        database = db_config['database']
        
        # Speed-optimized connection parameters
        connection_params = [
            f"driver={db_config['driver'].replace(' ', '+')}", 
            "trusted_connection=yes",
            "autocommit=false",
            "timeout=20",              # Balanced timeout
            "login_timeout=15",        # Faster login
            "connection_timeout=15",
            "encrypt=no",
            "trustservercertificate=yes",
            "multisubnetfailover=no",
            "mars_connection=no",
            "app_name=EDR_Agent_Server",
            "packet_size=4096",
            "connectretrycount=2",     # Quick retry
            "connectretryinterval=5"   # Fast retry interval
        ]
        
        connection_string = "&".join(connection_params)
        return f"mssql+pyodbc://@{server}/{database}?{connection_string}"
    
    def _initialize_engine(self):
        """Speed optimized engine initialization"""
        try:
            original_server = config['database']['server']
            logger.info(f"🚀 Speed optimized database init: {original_server}")
            
            # Try original config first (with faster timeout)
            try:
                if self._test_server_connection_fast(original_server):
                    logger.info("✅ Original config works")
                else:
                    raise ConnectionError("Original config failed")
            except Exception as e:
                logger.warning(f"⚠️ Original config failed, auto-detecting...")
                if not self._auto_detect_server_fast():
                    raise RuntimeError("Could not establish database connection")
            
            # Build optimized connection URL
            database_url = self._build_connection_url_optimized(config['database'])
            
            perf_config = config['performance']
            
            # Create speed-optimized engine
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=min(perf_config['database_pool_size'], 15),  # Optimized size
                max_overflow=min(perf_config['database_max_overflow'], 25),
                pool_timeout=20,           # Faster timeout
                pool_pre_ping=True,        # Keep for reliability
                pool_recycle=1800,         # 30 min
                echo=config['server']['debug'],
                echo_pool=False,
                future=True,
                isolation_level="READ_COMMITTED",
                connect_args={
                    "timeout": 20,
                    "autocommit": False,
                    "fast_executemany": True,  # Speed boost
                    "login_timeout": 15,
                    "connection_timeout": 15
                }
            )
            
            # Optimized session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
                expire_on_commit=False,
                class_=Session
            )
            
            self.metadata = MetaData()
            self._add_event_listeners()
            
            logger.info("✅ Speed optimized database engine ready")
            
        except Exception as e:
            logger.error(f"❌ Database engine init failed: {e}")
            raise DatabaseConnectionError(f"Database initialization failed: {e}")
    
    def _add_event_listeners(self):
        """Optimized event listeners"""
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            try:
                if hasattr(dbapi_connection, 'execute'):
                    # Fast connection setup
                    dbapi_connection.execute("SET LOCK_TIMEOUT 20000")  # Faster timeout
                    dbapi_connection.execute("SET ARITHABORT ON")
            except:
                pass  # Don't fail on setup issues
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            pass  # Minimal logging for speed
        
        @event.listens_for(self.engine, "invalidate")
        def receive_invalidate(dbapi_connection, connection_record, exception):
            logger.warning(f"🔄 Connection invalidated: {exception}")
    
    def test_connection(self, retry_count: int = 2) -> bool:  # Reduced retries
        """Speed optimized connection test"""
        for attempt in range(retry_count):
            try:
                with self.engine.connect() as connection:
                    result = connection.execute(text("""
                        SELECT 
                            1 as test, 
                            GETDATE() as server_time,
                            @@SERVERNAME as server_name,
                            DB_NAME() as database_name,
                            SUSER_NAME() as login_name
                    """))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        self.is_connected = True
                        
                        if attempt == 0:  # Only log details on first success
                            logger.info(f"✅ Database connected: {row[2]} / {row[3]}")
                            logger.info(f"👤 User: {row[4]}")
                            if self._detected_server:
                                logger.info(f"🎯 Server: {self._detected_server}")
                        
                        return True
                        
            except Exception as e:
                self.is_connected = False
                if attempt == retry_count - 1:  # Only log on final failure
                    logger.error(f"❌ Connection failed: {e}")
                
                if attempt < retry_count - 1:
                    time.sleep(1)  # Faster retry
                    
        return False
    
    def get_session(self) -> Session:
        """Optimized session creation"""
        if not self.SessionLocal:
            raise DatabaseConnectionError("Database not initialized")
        
        try:
            session = self.SessionLocal()
            # Quick validation
            session.execute(text("SELECT 1"))
            return session
        except Exception as e:
            logger.error(f"Session creation failed: {e}")
            raise DatabaseSessionError(f"Session creation failed: {e}")
    
    @contextmanager
    def get_db_session(self) -> Generator[Session, None, None]:
        """Optimized context manager"""
        session = None
        try:
            session = self.get_session()
            yield session
            session.commit()
            
        except IntegrityError as e:
            if session:
                session.rollback()
            raise DatabaseIntegrityError(f"Data integrity violation: {e}")
            
        except OperationalError as e:
            if session:
                session.rollback()
            raise DatabaseOperationalError(f"Database operation failed: {e}")
            
        except SQLAlchemyError as e:
            if session:
                session.rollback()
            raise DatabaseError(f"Database error: {e}")
            
        except Exception as e:
            if session:
                session.rollback()
            raise DatabaseError(f"Unexpected database error: {e}")
            
        finally:
            if session:
                session.close()
    
    def check_tables_exist(self) -> Dict[str, bool]:
        """Cached table existence check"""
        cache_key = 'table_existence'
        
        # Check cache first
        with self._cache_lock:
            if cache_key in self._cache:
                cache_time, cached_result = self._cache[cache_key]
                if time.time() - cache_time < 60:  # 1 minute cache
                    return cached_result
        
        try:
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            table_status = {}
            
            with self.get_db_session() as session:
                # Single query for all tables
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
            
            # Cache the result
            with self._cache_lock:
                self._cache[cache_key] = (time.time(), table_status)
                    
            return table_status
            
        except Exception as e:
            logger.error(f"❌ Error checking table existence: {e}")
            return {table: False for table in ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']}
    
    def get_table_counts(self) -> Dict[str, int]:
        """Cached and optimized table counts"""
        cache_key = 'table_counts'
        
        # Check cache first
        with self._cache_lock:
            if cache_key in self._cache:
                cache_time, cached_result = self._cache[cache_key]
                if time.time() - cache_time < 30:  # 30 second cache
                    return cached_result
        
        try:
            table_counts = {}
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            
            with self.get_db_session() as session:
                # Parallel count queries for speed
                count_queries = []
                for table in edr_tables:
                    count_queries.append(f"SELECT '{table}' as table_name, COUNT(*) as count FROM [{table}]")
                
                # Single UNION query for all counts
                union_query = " UNION ALL ".join(count_queries)
                
                result = session.execute(text(union_query))
                for row in result.fetchall():
                    table_counts[row[0]] = row[1]
            
            # Cache the result
            with self._cache_lock:
                self._cache[cache_key] = (time.time(), table_counts)
                        
            return table_counts
            
        except Exception as e:
            logger.error(f"❌ Error getting table counts: {e}")
            return {}
    
    def health_check(self, force_check: bool = False) -> Dict:
        """Speed optimized health check with caching"""
        cache_key = 'health_check'
        
        # Use cache if not forced
        if not force_check:
            with self._cache_lock:
                if cache_key in self._cache:
                    cache_time, cached_result = self._cache[cache_key]
                    if time.time() - cache_time < 15:  # 15 second cache
                        return cached_result
        
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
            # Quick connection test
            if not self.test_connection(retry_count=1):
                health_status['errors'].append('Database connection failed')
                return health_status
            
            # Single query for server info and basic health
            try:
                with self.get_db_session() as session:
                    result = session.execute(text("""
                        SELECT 
                            @@SERVERNAME as server_name,
                            DB_NAME() as database_name,
                            SUSER_NAME() as login_name,
                            (SELECT COUNT(*) FROM sys.databases) as db_count
                    """))
                    row = result.fetchone()
                    if row:
                        health_status['server_info'] = {
                            'server_name': row[0],
                            'database_name': row[1],
                            'login_name': row[2],
                            'total_databases': row[3]
                        }
            except Exception as e:
                health_status['errors'].append(f'Server info error: {str(e)}')
            
            # Get table status (cached)
            table_status = self.check_tables_exist()
            missing_tables = [table for table, exists in table_status.items() if not exists]
            
            if missing_tables:
                health_status['errors'].append(f"Missing tables: {', '.join(missing_tables)}")
            
            # Get table counts (cached)
            if not missing_tables:
                health_status['table_counts'] = self.get_table_counts()
            
            # Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Determine overall health
            health_status['healthy'] = len(health_status['errors']) == 0
            
            # Cache successful results
            if health_status['healthy']:
                with self._cache_lock:
                    self._cache[cache_key] = (time.time(), health_status)
            
            if health_status['healthy']:
                logger.info(f"✅ Health check passed in {health_status['response_time_ms']}ms")
            else:
                logger.warning(f"⚠️ Health issues: {health_status['errors']}")
            
        except Exception as e:
            health_status['errors'].append(f'Health check failed: {str(e)}')
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            logger.error(f"💥 Health check failed: {e}")
        
        return health_status
    
    def cleanup(self):
        """Optimized cleanup"""
        try:
            if self.engine:
                self.engine.dispose()
                logger.info("🧹 Database cleaned up")
            
            # Clear cache
            with self._cache_lock:
                self._cache.clear()
            
            self.is_connected = False
            
        except Exception as e:
            logger.error(f"❌ Cleanup error: {e}")

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
    """Optimized database dependency"""
    session = None
    try:
        session = db_manager.get_session()
        yield session
    except DatabaseError:
        raise
    except Exception as e:
        if session:
            session.rollback()
        raise DatabaseError(f"Database session error: {e}")
    finally:
        if session:
            session.close()

# Speed optimized initialization function
def init_database() -> bool:
    """Speed optimized database initialization - keeps all features"""
    try:
        logger.info("⚡ Speed optimized database initialization...")
        
        # Quick connection test
        if not db_manager.test_connection(retry_count=2):
            logger.error("❌ Database connection failed")
            return False
        
        # Fast health check
        health_status = db_manager.health_check()
        if not health_status['healthy']:
            logger.error(f"❌ Health check failed: {health_status['errors']}")
            return False
        
        # Enhanced success reporting (but faster)
        server_info = health_status.get('server_info', {})
        table_counts = health_status.get('table_counts', {})
        total_records = sum(count for count in table_counts.values() if count > 0)
        
        logger.info(f"📊 Connected: {server_info.get('server_name', 'Unknown')} / {server_info.get('database_name', 'EDR_System')}")
        logger.info(f"👤 User: {server_info.get('login_name', 'Unknown')}")
        logger.info(f"📈 Ready: {len(table_counts)} tables, {total_records:,} records - {health_status['response_time_ms']}ms")
        
        # Quick table summary
        if table_counts:
            key_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules']
            summary = ", ".join([f"{table}: {table_counts.get(table, 0)}" for table in key_tables])
            logger.info(f"📋 {summary}")
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Database initialization failed: {e}")
        return False

def get_database_status() -> Dict:
    """Fast database status with caching"""
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
    """Optimized database shutdown"""
    try:
        logger.info("🔄 Database shutdown...")
        db_manager.cleanup()
        logger.info("✅ Database shutdown completed")
    except Exception as e:
        logger.error(f"❌ Database shutdown error: {e}")

# Module-level cleanup on exit
import atexit
atexit.register(shutdown_database)