# app/database.py - Complete Database Manager (Updated for New Schema)
"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server - Updated for new simplified schema
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
    """Enhanced Database connection and session manager for EDR System"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 3
        self._last_health_check = None
        self._health_check_interval = 300  # 5 minutes
        self._initialize_engine()
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with enhanced configuration"""
        try:
            database_url = get_database_url()
            perf_config = config['performance']
            
            logger.info(f"🔗 Initializing database connection to: {config['database']['server']}/{config['database']['database']}")
            
            # Enhanced engine configuration for EDR workload
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=perf_config['database_pool_size'],
                max_overflow=perf_config['database_max_overflow'],
                pool_timeout=perf_config['database_pool_timeout'],
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=3600,   # Recycle connections every hour
                echo=config['server']['debug'],  # Log SQL queries in debug mode
                echo_pool=False,     # Don't log pool events unless debugging
                future=True,
                isolation_level="READ_COMMITTED",  # Better for concurrent access
                connect_args={
                    "timeout": config['database']['timeout'],
                    "autocommit": False,
                    "check_same_thread": False  # For SQLite compatibility if needed
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
                    # Set connection timeout and other properties
                    dbapi_connection.execute("SET LOCK_TIMEOUT 30000")  # 30 seconds
                    dbapi_connection.execute("SET QUERY_GOVERNOR_COST_LIMIT 0")  # No query cost limit
            except Exception as e:
                logger.debug(f"Could not set connection properties: {e}")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug("📤 Database connection checked out from pool")
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            logger.debug("📥 Database connection returned to pool")
        
        @event.listens_for(self.engine, "invalidate")
        def receive_invalidate(dbapi_connection, connection_record, exception):
            logger.warning(f"🔄 Database connection invalidated: {exception}")
        
        # Add slow query logging
        @event.listens_for(self.engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.time()
        
        @event.listens_for(self.engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            total = time.time() - context._query_start_time
            if total > 1.0:  # Log queries taking more than 1 second
                logger.warning(f"⏱️ Slow query detected ({total:.2f}s): {statement[:100]}...")
    
    def test_connection(self, retry_count: int = 3) -> bool:
        """Enhanced connection test with retry logic"""
        for attempt in range(retry_count):
            try:
                with self.engine.connect() as connection:
                    # Test with a simple query
                    result = connection.execute(text("SELECT 1 as test, GETDATE() as server_time"))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        self.is_connected = True
                        server_time = row[1]
                        logger.info(f"✅ Database connection test successful (attempt {attempt + 1}/{retry_count})")
                        logger.debug(f"🕐 Server time: {server_time}")
                        return True
                    else:
                        raise Exception("Unexpected test query result")
                        
            except Exception as e:
                self.is_connected = False
                logger.error(f"❌ Database connection test failed (attempt {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    
        return False
    
    def get_session(self) -> Session:
        """Get new database session with enhanced error handling"""
        if not self.SessionLocal:
            raise DatabaseConnectionError("Database not initialized")
        
        try:
            session = self.SessionLocal()
            # Test the session
            session.execute(text("SELECT 1"))
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
    
    def execute_query(self, query: str, params: Dict = None, fetch_all: bool = True) -> List[Dict]:
        """Execute raw SQL query with enhanced error handling and result formatting"""
        try:
            with self.get_db_session() as session:
                result = session.execute(text(query), params or {})
                
                if result.returns_rows:
                    if fetch_all:
                        rows = result.fetchall()
                    else:
                        rows = [result.fetchone()]
                    
                    # Convert to dictionaries with column names
                    columns = result.keys()
                    return [dict(zip(columns, row)) for row in rows if row]
                else:
                    # For non-SELECT queries, return affected row count
                    return [{"affected_rows": result.rowcount}]
                    
        except Exception as e:
            logger.error(f"💥 Query execution failed: {e}")
            logger.error(f"📝 Query: {query}")
            if params:
                logger.error(f"📝 Params: {params}")
            raise DatabaseQueryError(f"Query execution failed: {e}")
    
    def execute_non_query(self, query: str, params: Dict = None) -> Tuple[bool, int]:
        """Execute non-query SQL statement and return success status and affected rows"""
        try:
            with self.get_db_session() as session:
                result = session.execute(text(query), params or {})
                affected_rows = result.rowcount
                logger.debug(f"✅ Non-query executed successfully, {affected_rows} rows affected")
                return True, affected_rows
                
        except Exception as e:
            logger.error(f"💥 Non-query execution failed: {e}")
            logger.error(f"📝 Query: {query}")
            return False, 0
    
    def get_table_count(self, table_name: str) -> int:
        """Get record count for a table with error handling"""
        try:
            query = f"SELECT COUNT(*) as count FROM [{table_name}]"
            result = self.execute_query(query)
            if result:
                return result[0]['count']
            return 0
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
            result = self.execute_query(query, {
                "table_name": table_name,
                "schema": schema
            })
            return result and result[0]['table_count'] > 0
            
        except Exception as e:
            logger.error(f"❌ Error checking table existence {table_name}: {e}")
            return False
    
    def get_table_schema(self, table_name: str, schema: str = 'dbo') -> List[Dict]:
        """Get table schema information"""
        try:
            query = """
                SELECT 
                    COLUMN_NAME as column_name,
                    DATA_TYPE as data_type,
                    IS_NULLABLE as is_nullable,
                    COLUMN_DEFAULT as default_value,
                    CHARACTER_MAXIMUM_LENGTH as max_length,
                    NUMERIC_PRECISION as precision,
                    NUMERIC_SCALE as scale,
                    ORDINAL_POSITION as position
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_NAME = :table_name
                AND TABLE_SCHEMA = :schema
                ORDER BY ORDINAL_POSITION
            """
            return self.execute_query(query, {
                "table_name": table_name,
                "schema": schema
            })
        except Exception as e:
            logger.error(f"❌ Error getting schema for table {table_name}: {e}")
            return []
    
    def get_database_info(self) -> Dict:
        """Get comprehensive database information and statistics"""
        try:
            info = {}
            
            # Basic database info
            basic_info_query = """
                SELECT 
                    @@VERSION as version,
                    DB_NAME() as database_name,
                    @@SERVERNAME as server_name,
                    GETDATE() as current_datetime,
                    @@SPID as session_id,
                    HOST_NAME() as host_name,
                    SUSER_NAME() as user_name
            """
            basic_info = self.execute_query(basic_info_query)
            if basic_info:
                info.update(basic_info[0])
            
            # EDR system tables information
            edr_tables = [
                'Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 
                'SystemConfig', 'AgentConfigs'
            ]
            
            tables_info = []
            for table in edr_tables:
                if self.check_table_exists(table):
                    schema_info = self.get_table_schema(table)
                    tables_info.append({
                        'table_name': table,
                        'column_count': len(schema_info),
                        'record_count': self.get_table_count(table),
                        'exists': True
                    })
                else:
                    tables_info.append({
                        'table_name': table,
                        'exists': False
                    })
            
            info['edr_tables'] = tables_info
            
            # Database size and space info
            size_query = """
                SELECT 
                    SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint) * 8192.) / 1024 / 1024 as used_space_mb,
                    SUM(CAST(size AS bigint) * 8192.) / 1024 / 1024 as allocated_space_mb
                FROM sys.database_files 
                WHERE type_desc = 'ROWS'
            """
            size_info = self.execute_query(size_query)
            if size_info:
                info.update(size_info[0])
            
            # Connection and session info
            connections_query = """
                SELECT 
                    COUNT(*) as total_connections,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as active_connections
                FROM sys.dm_exec_sessions 
                WHERE is_user_process = 1
            """
            connections_info = self.execute_query(connections_query)
            if connections_info:
                info['connections'] = connections_info[0]
            
            return info
            
        except Exception as e:
            logger.error(f"❌ Error getting database info: {e}")
            return {'error': str(e)}
    
    def get_connection_pool_status(self) -> Dict:
        """Get detailed connection pool status"""
        try:
            if not self.engine:
                return {'error': 'Engine not initialized'}
            
            pool = self.engine.pool
            status = {
                'pool_size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'total_connections': pool.size() + pool.overflow(),
                'pool_timeout': getattr(pool, '_timeout', None),
                'max_overflow': getattr(pool, '_max_overflow', None),
                'recycle_time': getattr(pool, '_recycle', None)
            }
            
            # Calculate utilization percentage
            if status['pool_size'] > 0:
                status['utilization_percent'] = (status['checked_out'] / status['total_connections']) * 100
            else:
                status['utilization_percent'] = 0
            
            return status
            
        except Exception as e:
            logger.error(f"❌ Error getting pool status: {e}")
            return {'error': str(e)}
    
    def health_check(self, force_check: bool = False) -> Dict:
        """Comprehensive database health check for EDR system"""
        # Check if we need to run health check (unless forced)
        if not force_check and self._last_health_check:
            time_since_check = time.time() - self._last_health_check
            if time_since_check < self._health_check_interval:
                return self._get_cached_health_status()
        
        start_time = time.time()
        health_status = {
            'healthy': False,
            'response_time_ms': 0,
            'connection_pool': {},
            'database_info': {},
            'table_counts': {},
            'edr_system_status': {},
            'performance_metrics': {},
            'errors': [],
            'warnings': [],
            'last_checked': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Test basic connection
            logger.debug("🔍 Testing database connection...")
            if not self.test_connection():
                health_status['errors'].append('Database connection failed')
                return health_status
            
            # Step 2: Get connection pool status
            logger.debug("🔍 Checking connection pool...")
            pool_status = self.get_connection_pool_status()
            health_status['connection_pool'] = pool_status
            
            # Check pool utilization
            if pool_status.get('utilization_percent', 0) > 80:
                health_status['warnings'].append(f"High connection pool utilization: {pool_status['utilization_percent']:.1f}%")
            
            # Step 3: Get database info
            logger.debug("🔍 Retrieving database information...")
            db_info = self.get_database_info()
            health_status['database_info'] = db_info
            
            # Step 4: Check EDR core tables
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
            
            # Step 5: EDR system specific health checks
            logger.debug("🔍 Checking EDR system health...")
            edr_status = self._check_edr_system_health()
            health_status['edr_system_status'] = edr_status
            
            # Step 6: Performance metrics
            logger.debug("🔍 Collecting performance metrics...")
            performance = self._collect_performance_metrics()
            health_status['performance_metrics'] = performance
            
            # Step 7: Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Step 8: Determine overall health
            health_status['healthy'] = len(health_status['errors']) == 0
            
            # Log results
            if health_status['healthy']:
                logger.info(f"✅ Database health check passed in {health_status['response_time_ms']}ms")
            else:
                logger.warning(f"⚠️ Database health check issues found in {health_status['response_time_ms']}ms")
                for error in health_status['errors']:
                    logger.error(f"   ❌ {error}")
            
            # Cache the results
            self._last_health_check = time.time()
            self._cached_health_status = health_status
            
        except Exception as e:
            health_status['errors'].append(f'Health check failed: {str(e)}')
            logger.error(f"💥 Database health check failed: {e}")
        
        return health_status
    
    def _get_cached_health_status(self) -> Dict:
        """Return cached health status if available"""
        if hasattr(self, '_cached_health_status'):
            cached = self._cached_health_status.copy()
            cached['cached'] = True
            return cached
        return {'healthy': False, 'error': 'No cached status available'}
    
    def _check_edr_system_health(self) -> Dict:
        """Check EDR system specific health metrics"""
        edr_status = {}
        
        try:
            # Check for recent agent activity (last 10 minutes)
            recent_agents_query = """
                SELECT COUNT(*) as count 
                FROM Agents 
                WHERE LastHeartbeat >= DATEADD(minute, -10, GETDATE())
                AND Status = 'Active'
            """
            recent_agents = self.execute_query(recent_agents_query)
            edr_status['active_agents_last_10min'] = recent_agents[0]['count'] if recent_agents else 0
            
            # Check for recent events (last hour)
            recent_events_query = """
                SELECT COUNT(*) as count 
                FROM Events 
                WHERE CreatedAt >= DATEADD(hour, -1, GETDATE())
            """
            recent_events = self.execute_query(recent_events_query)
            edr_status['events_last_hour'] = recent_events[0]['count'] if recent_events else 0
            
            # Check for open alerts
            open_alerts_query = """
                SELECT COUNT(*) as count 
                FROM Alerts 
                WHERE Status IN ('Open', 'Investigating')
            """
            open_alerts = self.execute_query(open_alerts_query)
            edr_status['open_alerts'] = open_alerts[0]['count'] if open_alerts else 0
            
            # Check for critical alerts
            critical_alerts_query = """
                SELECT COUNT(*) as count 
                FROM Alerts 
                WHERE Status IN ('Open', 'Investigating')
                AND Severity IN ('High', 'Critical')
            """
            critical_alerts = self.execute_query(critical_alerts_query)
            edr_status['critical_alerts'] = critical_alerts[0]['count'] if critical_alerts else 0
            
            # Check detection rules
            active_rules_query = """
                SELECT COUNT(*) as count 
                FROM DetectionRules 
                WHERE IsActive = 1
            """
            active_rules = self.execute_query(active_rules_query)
            edr_status['active_detection_rules'] = active_rules[0]['count'] if active_rules else 0
            
            # Check threat indicators
            active_threats_query = """
                SELECT COUNT(*) as count 
                FROM Threats 
                WHERE IsActive = 1
            """
            active_threats = self.execute_query(active_threats_query)
            edr_status['active_threat_indicators'] = active_threats[0]['count'] if active_threats else 0
            
            # Check for unanalyzed events
            unanalyzed_events_query = """
                SELECT COUNT(*) as count 
                FROM Events 
                WHERE Analyzed = 0
                AND CreatedAt >= DATEADD(hour, -24, GETDATE())
            """
            unanalyzed_events = self.execute_query(unanalyzed_events_query)
            edr_status['unanalyzed_events_24h'] = unanalyzed_events[0]['count'] if unanalyzed_events else 0
            
        except Exception as e:
            logger.error(f"❌ EDR system health check failed: {e}")
            edr_status['error'] = str(e)
        
        return edr_status
    
    def _collect_performance_metrics(self) -> Dict:
        """Collect database performance metrics"""
        metrics = {}
        
        try:
            # Query performance stats
            perf_query = """
                SELECT 
                    (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE status = 'running') as active_queries,
                    (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE status = 'suspended') as blocked_queries,
                    (SELECT COUNT(*) FROM sys.dm_tran_locks) as total_locks
            """
            perf_stats = self.execute_query(perf_query)
            if perf_stats:
                metrics.update(perf_stats[0])
            
            # Memory usage
            memory_query = """
                SELECT 
                    (total_physical_memory_kb / 1024) as total_memory_mb,
                    (available_physical_memory_kb / 1024) as available_memory_mb
                FROM sys.dm_os_sys_memory
            """
            memory_stats = self.execute_query(memory_query)
            if memory_stats:
                metrics.update(memory_stats[0])
            
            # Wait statistics (simplified)
            wait_query = """
                SELECT TOP 5
                    wait_type,
                    waiting_tasks_count,
                    wait_time_ms
                FROM sys.dm_os_wait_stats
                WHERE wait_type NOT LIKE '%SLEEP%'
                AND wait_type NOT LIKE '%IDLE%'
                ORDER BY wait_time_ms DESC
            """
            wait_stats = self.execute_query(wait_query)
            metrics['top_wait_types'] = wait_stats
            
        except Exception as e:
            logger.error(f"❌ Performance metrics collection failed: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def cleanup(self):
        """Clean up database connections and resources"""
        try:
            if self.engine:
                # Close all connections
                self.engine.dispose()
                logger.info("🧹 Database engine disposed successfully")
            
            if hasattr(self, '_cached_health_status'):
                delattr(self, '_cached_health_status')
            
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

class DatabaseQueryError(DatabaseError):
    """Database query error"""
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
    """Initialize database connection and verify EDR schema"""
    try:
        logger.info("🔄 Initializing EDR database connection...")
        
        # Test database connection with retries
        if not db_manager.test_connection(retry_count=3):
            logger.error("❌ Database connection test failed after retries")
            return False
        
        # Get database info
        db_info = db_manager.get_database_info()
        if 'error' in db_info:
            logger.error(f"❌ Database info retrieval failed: {db_info['error']}")
            return False
        
        logger.info(f"🗄️ Connected to: {db_info.get('database_name')} on {db_info.get('server_name')}")
        logger.info(f"📊 SQL Server Version: {db_info.get('version', 'Unknown')[:50]}...")
        
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
        
        # Verify system configuration
        config_count = db_manager.get_table_count('SystemConfig')
        if config_count == 0:
            logger.warning("⚠️ No system configuration found - consider loading default config")
        
        # Test connection pool
        pool_status = db_manager.get_connection_pool_status()
        logger.info(f"🏊 Connection pool: {pool_status.get('pool_size', 0)} connections, {pool_status.get('utilization_percent', 0):.1f}% utilized")
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Database initialization failed: {e}")
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

def execute_query(query: str, params: Dict = None) -> List[Dict]:
    """Execute query using global database manager"""
    return db_manager.execute_query(query, params)

def execute_non_query(query: str, params: Dict = None) -> bool:
    """Execute non-query using global database manager"""
    success, _ = db_manager.execute_non_query(query, params)
    return success

# Database maintenance and utility functions
def get_edr_statistics() -> Dict:
    """Get comprehensive EDR system statistics"""
    try:
        stats = {}
        
        # Agent statistics
        agent_stats_query = """
            SELECT 
                COUNT(*) as total_agents,
                SUM(CASE WHEN Status = 'Active' THEN 1 ELSE 0 END) as active_agents,
                SUM(CASE WHEN LastHeartbeat >= DATEADD(minute, -5, GETDATE()) AND Status = 'Active' THEN 1 ELSE 0 END) as online_agents,
                SUM(CASE WHEN OperatingSystem LIKE '%Windows%' THEN 1 ELSE 0 END) as windows_agents,
                SUM(CASE WHEN OperatingSystem LIKE '%Linux%' THEN 1 ELSE 0 END) as linux_agents
            FROM Agents
        """
        agent_stats = db_manager.execute_query(agent_stats_query)
        stats['agents'] = agent_stats[0] if agent_stats else {}
        
        # Event statistics (last 24 hours)
        event_stats_query = """
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN ThreatLevel = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_events,
                SUM(CASE WHEN ThreatLevel = 'Malicious' THEN 1 ELSE 0 END) as malicious_events,
                SUM(CASE WHEN Analyzed = 1 THEN 1 ELSE 0 END) as analyzed_events,
                COUNT(DISTINCT AgentID) as agents_with_events
            FROM Events 
            WHERE CreatedAt >= DATEADD(hour, -24, GETDATE())
        """
        event_stats = db_manager.execute_query(event_stats_query)
        stats['events'] = event_stats[0] if event_stats else {}
        
        # Alert statistics
        alert_stats_query = """
            SELECT 
                COUNT(*) as total_alerts,
                SUM(CASE WHEN Status IN ('Open', 'Investigating') THEN 1 ELSE 0 END) as open_alerts,
                SUM(CASE WHEN Severity IN ('High', 'Critical') AND Status IN ('Open', 'Investigating') THEN 1 ELSE 0 END) as critical_alerts,
                SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) as resolved_alerts,
                SUM(CASE WHEN FirstDetected >= DATEADD(hour, -24, GETDATE()) THEN 1 ELSE 0 END) as alerts_last_24h
            FROM Alerts
        """
        alert_stats = db_manager.execute_query(alert_stats_query)
        stats['alerts'] = alert_stats[0] if alert_stats else {}
        
        # Threat statistics
        threat_stats_query = """
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN IsActive = 1 THEN 1 ELSE 0 END) as active_threats,
                SUM(CASE WHEN ThreatType = 'Hash' AND IsActive = 1 THEN 1 ELSE 0 END) as hash_indicators,
                SUM(CASE WHEN ThreatType = 'IP' AND IsActive = 1 THEN 1 ELSE 0 END) as ip_indicators,
                SUM(CASE WHEN ThreatType = 'Domain' AND IsActive = 1 THEN 1 ELSE 0 END) as domain_indicators
            FROM Threats
        """
        threat_stats = db_manager.execute_query(threat_stats_query)
        stats['threats'] = threat_stats[0] if threat_stats else {}
        
        # Detection rules statistics
        rules_stats_query = """
            SELECT 
                COUNT(*) as total_rules,
                SUM(CASE WHEN IsActive = 1 THEN 1 ELSE 0 END) as active_rules,
                SUM(CASE WHEN TestMode = 1 THEN 1 ELSE 0 END) as test_rules
            FROM DetectionRules
        """
        rules_stats = db_manager.execute_query(rules_stats_query)
        stats['detection_rules'] = rules_stats[0] if rules_stats else {}
        
        # System health indicators
        stats['system_health'] = {
            'database_healthy': db_manager.is_connected,
            'total_records': sum([
                stats['agents'].get('total_agents', 0),
                stats['events'].get('total_events', 0),
                stats['alerts'].get('total_alerts', 0),
                stats['threats'].get('total_threats', 0),
                stats['detection_rules'].get('total_rules', 0)
            ]),
            'last_updated': datetime.now().isoformat()
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"❌ Failed to get EDR statistics: {e}")
        return {'error': str(e)}

def cleanup_old_data(retention_days: int = 90) -> Dict:
    """Cleanup old EDR data based on retention policy"""
    try:
        cleanup_results = {
            'events_deleted': 0,
            'alerts_deleted': 0,
            'retention_days': retention_days,
            'cleanup_date': datetime.now().isoformat(),
            'errors': []
        }
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # Cleanup old events (keep events linked to active alerts)
        old_events_query = """
            DELETE FROM Events 
            WHERE CreatedAt < :cutoff_date
            AND EventID NOT IN (
                SELECT DISTINCT EventID FROM Alerts 
                WHERE EventID IS NOT NULL 
                AND Status IN ('Open', 'Investigating')
            )
        """
        
        try:
            success, events_deleted = db_manager.execute_non_query(
                old_events_query, 
                {'cutoff_date': cutoff_date}
            )
            if success:
                cleanup_results['events_deleted'] = events_deleted
                logger.info(f"🧹 Deleted {events_deleted} old events")
            else:
                cleanup_results['errors'].append("Failed to delete old events")
        except Exception as e:
            cleanup_results['errors'].append(f"Event cleanup error: {str(e)}")
        
        # Cleanup old resolved alerts
        old_alerts_query = """
            DELETE FROM Alerts 
            WHERE ResolvedAt < :cutoff_date
            AND Status IN ('Resolved', 'False Positive')
        """
        
        try:
            success, alerts_deleted = db_manager.execute_non_query(
                old_alerts_query,
                {'cutoff_date': cutoff_date}
            )
            if success:
                cleanup_results['alerts_deleted'] = alerts_deleted
                logger.info(f"🧹 Deleted {alerts_deleted} old alerts")
            else:
                cleanup_results['errors'].append("Failed to delete old alerts")
        except Exception as e:
            cleanup_results['errors'].append(f"Alert cleanup error: {str(e)}")
        
        # Update system config with last cleanup date
        try:
            update_config_query = """
                UPDATE SystemConfig 
                SET ConfigValue = :cleanup_date, UpdatedAt = GETDATE()
                WHERE ConfigKey = 'last_data_cleanup'
            """
            db_manager.execute_non_query(
                update_config_query,
                {'cleanup_date': cleanup_results['cleanup_date']}
            )
        except Exception as e:
            cleanup_results['errors'].append(f"Config update error: {str(e)}")
        
        logger.info(f"🧹 Data cleanup completed: {events_deleted} events, {alerts_deleted} alerts deleted")
        return cleanup_results
        
    except Exception as e:
        logger.error(f"❌ Data cleanup failed: {e}")
        return {'error': str(e), 'retention_days': retention_days}

def optimize_database() -> Dict:
    """Perform database optimization tasks"""
    try:
        optimization_results = {
            'started_at': datetime.now().isoformat(),
            'tasks_completed': [],
            'errors': [],
            'performance_improvement': {}
        }
        
        # Update statistics on key tables
        edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules']
        
        for table in edr_tables:
            try:
                update_stats_query = f"UPDATE STATISTICS [{table}]"
                success, _ = db_manager.execute_non_query(update_stats_query)
                if success:
                    optimization_results['tasks_completed'].append(f"Updated statistics for {table}")
                else:
                    optimization_results['errors'].append(f"Failed to update statistics for {table}")
            except Exception as e:
                optimization_results['errors'].append(f"Statistics update error for {table}: {str(e)}")
        
        # Rebuild indexes if fragmentation is high
        index_maintenance_query = """
            SELECT 
                OBJECT_NAME(ips.object_id) AS table_name,
                i.name AS index_name,
                ips.avg_fragmentation_in_percent
            FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'SAMPLED') ips
            INNER JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
            WHERE ips.avg_fragmentation_in_percent > 30
            AND OBJECT_NAME(ips.object_id) IN ('Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules')
        """
        
        try:
            fragmented_indexes = db_manager.execute_query(index_maintenance_query)
            for idx in fragmented_indexes:
                try:
                    rebuild_query = f"ALTER INDEX [{idx['index_name']}] ON [{idx['table_name']}] REBUILD"
                    success, _ = db_manager.execute_non_query(rebuild_query)
                    if success:
                        optimization_results['tasks_completed'].append(
                            f"Rebuilt index {idx['index_name']} on {idx['table_name']} (was {idx['avg_fragmentation_in_percent']:.1f}% fragmented)"
                        )
                except Exception as e:
                    optimization_results['errors'].append(f"Index rebuild error: {str(e)}")
        except Exception as e:
            optimization_results['errors'].append(f"Index analysis error: {str(e)}")
        
        optimization_results['completed_at'] = datetime.now().isoformat()
        logger.info(f"🔧 Database optimization completed: {len(optimization_results['tasks_completed'])} tasks")
        
        return optimization_results
        
    except Exception as e:
        logger.error(f"❌ Database optimization failed: {e}")
        return {'error': str(e)}

def backup_configuration() -> Dict:
    """Backup system configuration and detection rules"""
    try:
        backup_results = {
            'backup_date': datetime.now().isoformat(),
            'backed_up_items': [],
            'errors': []
        }
        
        # Backup system configuration
        try:
            config_query = "SELECT ConfigKey, ConfigValue, ConfigDescription FROM SystemConfig"
            config_data = db_manager.execute_query(config_query)
            backup_results['system_config'] = config_data
            backup_results['backed_up_items'].append(f"System configuration ({len(config_data)} items)")
        except Exception as e:
            backup_results['errors'].append(f"Config backup error: {str(e)}")
        
        # Backup detection rules
        try:
            rules_query = """
                SELECT RuleID, RuleName, RuleType, RuleCategory, RuleCondition, 
                       AlertTitle, AlertSeverity, AlertType, MitreTactic, MitreTechnique,
                       Platform, Priority, IsActive
                FROM DetectionRules 
                WHERE IsActive = 1
            """
            rules_data = db_manager.execute_query(rules_query)
            backup_results['detection_rules'] = rules_data
            backup_results['backed_up_items'].append(f"Detection rules ({len(rules_data)} active rules)")
        except Exception as e:
            backup_results['errors'].append(f"Rules backup error: {str(e)}")
        
        # Backup agent configurations
        try:
            agent_config_query = """
                SELECT AgentID, ConfigKey, ConfigValue 
                FROM AgentConfigs
            """
            agent_configs = db_manager.execute_query(agent_config_query)
            backup_results['agent_configs'] = agent_configs
            backup_results['backed_up_items'].append(f"Agent configurations ({len(agent_configs)} configs)")
        except Exception as e:
            backup_results['errors'].append(f"Agent config backup error: {str(e)}")
        
        logger.info(f"💾 Configuration backup completed: {len(backup_results['backed_up_items'])} categories")
        return backup_results
        
    except Exception as e:
        logger.error(f"❌ Configuration backup failed: {e}")
        return {'error': str(e)}

def get_database_performance_report() -> Dict:
    """Generate comprehensive database performance report"""
    try:
        report = {
            'generated_at': datetime.now().isoformat(),
            'database_info': {},
            'performance_metrics': {},
            'table_statistics': {},
            'connection_info': {},
            'recommendations': []
        }
        
        # Get basic database info
        report['database_info'] = db_manager.get_database_info()
        
        # Get connection pool status
        report['connection_info'] = db_manager.get_connection_pool_status()
        
        # Get table statistics
        edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules']
        for table in edr_tables:
            count = db_manager.get_table_count(table)
            report['table_statistics'][table] = {
                'record_count': count,
                'exists': count >= 0
            }
        
        # Performance analysis and recommendations
        pool_util = report['connection_info'].get('utilization_percent', 0)
        if pool_util > 80:
            report['recommendations'].append("Consider increasing connection pool size - high utilization detected")
        
        total_events = report['table_statistics'].get('Events', {}).get('record_count', 0)
        if total_events > 1000000:
            report['recommendations'].append("Large Events table detected - consider implementing data archiving")
        
        total_alerts = report['table_statistics'].get('Alerts', {}).get('record_count', 0)
        if total_alerts > 100000:
            report['recommendations'].append("Large Alerts table detected - review alert retention policy")
        
        if not report['recommendations']:
            report['recommendations'].append("Database performance is optimal - no issues detected")
        
        logger.info("📊 Database performance report generated successfully")
        return report
        
    except Exception as e:
        logger.error(f"❌ Performance report generation failed: {e}")
        return {'error': str(e)}

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