# app/database.py - Updated Database Manager
"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server (No Authentication Version)
"""

import logging
from contextlib import contextmanager
from typing import Generator, Dict, List, Any, Optional
from sqlalchemy import create_engine, text, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.exc import SQLAlchemyError
import time

from .config import config, get_database_url

# Configure logging
logger = logging.getLogger(__name__)

# SQLAlchemy Base for all models
Base = declarative_base()

class DatabaseManager:
    """Database connection and session manager for EDR System"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.is_connected = False
        self._connection_attempts = 0
        self._max_retries = 3
        self._initialize_engine()
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with connection pooling"""
        try:
            database_url = get_database_url()
            perf_config = config['performance']
            
            logger.info(f"🔗 Connecting to database: {config['database']['server']}/{config['database']['database']}")
            
            # Create engine with optimized settings for EDR workload
            self.engine = create_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=perf_config['database_pool_size'],
                max_overflow=perf_config['database_max_overflow'],
                pool_timeout=perf_config['database_pool_timeout'],
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=3600,   # Recycle connections every hour
                echo=config['server']['debug'],  # Log SQL queries in debug mode
                future=True,
                connect_args={
                    "timeout": config['database']['timeout']
                }
            )
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
                expire_on_commit=False
            )
            
            # Add event listeners for monitoring
            self._add_event_listeners()
            
            logger.info("✅ Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database engine: {e}")
            raise
    
    def _add_event_listeners(self):
        """Add SQLAlchemy event listeners for monitoring"""
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            logger.debug("🔗 Database connection established")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug("📤 Database connection checked out from pool")
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            logger.debug("📥 Database connection returned to pool")
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text("SELECT 1 as test"))
                row = result.fetchone()
                if row and row[0] == 1:
                    self.is_connected = True
                    logger.info("✅ Database connection test successful")
                    return True
                else:
                    self.is_connected = False
                    logger.error("❌ Database connection test failed - unexpected result")
                    return False
        except Exception as e:
            self.is_connected = False
            logger.error(f"❌ Database connection test failed: {e}")
            return False
    
    def get_session(self) -> Session:
        """Get new database session"""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        return self.SessionLocal()
    
    @contextmanager
    def get_db_session(self) -> Generator[Session, None, None]:
        """Context manager for database sessions with automatic cleanup"""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"💥 Database session error: {e}")
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"💥 Unexpected error in database session: {e}")
            raise
        finally:
            session.close()
    
    def execute_query(self, query: str, params: Dict = None) -> List[Dict]:
        """Execute raw SQL query and return results as dictionaries"""
        try:
            with self.get_db_session() as session:
                result = session.execute(text(query), params or {})
                columns = result.keys()
                rows = result.fetchall()
                return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            logger.error(f"💥 Query execution failed: {e}")
            logger.error(f"📝 Query: {query}")
            if params:
                logger.error(f"📝 Params: {params}")
            return []
    
    def execute_non_query(self, query: str, params: Dict = None) -> bool:
        """Execute non-query SQL statement"""
        try:
            with self.get_db_session() as session:
                session.execute(text(query), params or {})
                return True
        except Exception as e:
            logger.error(f"💥 Non-query execution failed: {e}")
            return False
    
    def get_table_count(self, table_name: str) -> int:
        """Get record count for a table"""
        try:
            query = f"SELECT COUNT(*) as count FROM {table_name}"
            result = self.execute_query(query)
            if result:
                return result[0]['count']
            return 0
        except Exception as e:
            logger.error(f"❌ Error getting count for table {table_name}: {e}")
            return -1
    
    def check_table_exists(self, table_name: str) -> bool:
        """Check if table exists in database"""
        try:
            query = """
                SELECT COUNT(*) as table_count
                FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_NAME = :table_name
                AND TABLE_SCHEMA = 'dbo'
            """
            result = self.execute_query(query, {"table_name": table_name})
            return result and result[0]['table_count'] > 0
        except Exception as e:
            logger.error(f"❌ Error checking table existence {table_name}: {e}")
            return False
    
    def get_database_info(self) -> Dict:
        """Get database information and statistics"""
        try:
            info = {}
            
            # Basic database info
            basic_info = self.execute_query("""
                SELECT 
                    @@VERSION as version,
                    DB_NAME() as database_name,
                    @@SERVERNAME as server_name,
                    GETDATE() as current_datetime
            """)
            if basic_info:
                info.update(basic_info[0])
            
            # Table information for EDR system
            tables_info = self.execute_query("""
                SELECT 
                    TABLE_NAME,
                    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = t.TABLE_NAME) as column_count
                FROM INFORMATION_SCHEMA.TABLES t
                WHERE TABLE_SCHEMA = 'dbo' 
                AND TABLE_TYPE = 'BASE TABLE'
                AND TABLE_NAME IN ('Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs')
                ORDER BY TABLE_NAME
            """)
            info['tables'] = tables_info
            
            # Database size
            size_info = self.execute_query("""
                SELECT 
                    SUM(size) * 8 / 1024 as size_mb
                FROM sys.master_files 
                WHERE database_id = DB_ID()
            """)
            if size_info:
                info['size_mb'] = size_info[0]['size_mb']
            
            return info
            
        except Exception as e:
            logger.error(f"❌ Error getting database info: {e}")
            return {'error': str(e)}
    
    def get_connection_pool_status(self) -> Dict:
        """Get connection pool status"""
        try:
            pool = self.engine.pool
            return {
                'pool_size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'total_connections': pool.size() + pool.overflow()
            }
        except Exception as e:
            logger.error(f"❌ Error getting pool status: {e}")
            return {}
    
    def health_check(self) -> Dict:
        """Comprehensive database health check for EDR system"""
        start_time = time.time()
        health_status = {
            'healthy': False,
            'response_time_ms': 0,
            'connection_pool': {},
            'database_info': {},
            'table_counts': {},
            'edr_system_status': {},
            'errors': []
        }
        
        try:
            # Test basic connection
            if not self.test_connection():
                health_status['errors'].append('Database connection failed')
                return health_status
            
            # Get connection pool status
            health_status['connection_pool'] = self.get_connection_pool_status()
            
            # Get database info
            health_status['database_info'] = self.get_database_info()
            
            # Check EDR core tables
            edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
            for table in edr_tables:
                if self.check_table_exists(table):
                    count = self.get_table_count(table)
                    health_status['table_counts'][table] = count
                    logger.debug(f"📊 Table {table}: {count} records")
                else:
                    health_status['errors'].append(f'Critical table {table} not found')
            
            # EDR system specific checks
            health_status['edr_system_status'] = self._check_edr_system_health()
            
            # Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Determine overall health
            health_status['healthy'] = len(health_status['errors']) == 0
            
            if health_status['healthy']:
                logger.info(f"✅ Database health check passed in {health_status['response_time_ms']}ms")
            else:
                logger.warning(f"⚠️ Database health check issues: {health_status['errors']}")
            
        except Exception as e:
            health_status['errors'].append(f'Health check failed: {str(e)}')
            logger.error(f"💥 Database health check failed: {e}")
        
        return health_status
    
    def _check_edr_system_health(self) -> Dict:
        """Check EDR system specific health metrics"""
        edr_status = {}
        
        try:
            # Check for recent agent activity
            recent_agents = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM Agents 
                WHERE LastHeartbeat >= DATEADD(minute, -10, GETDATE())
            """)
            edr_status['active_agents_last_10min'] = recent_agents[0]['count'] if recent_agents else 0
            
            # Check for recent events
            recent_events = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM Events 
                WHERE CreatedAt >= DATEADD(hour, -1, GETDATE())
            """)
            edr_status['events_last_hour'] = recent_events[0]['count'] if recent_events else 0
            
            # Check for open alerts
            open_alerts = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM Alerts 
                WHERE Status IN ('Open', 'Investigating')
            """)
            edr_status['open_alerts'] = open_alerts[0]['count'] if open_alerts else 0
            
            # Check detection rules
            active_rules = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM DetectionRules 
                WHERE IsActive = 1
            """)
            edr_status['active_detection_rules'] = active_rules[0]['count'] if active_rules else 0
            
            # Check threat indicators
            active_threats = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM Threats 
                WHERE IsActive = 1
            """)
            edr_status['active_threat_indicators'] = active_threats[0]['count'] if active_threats else 0
            
        except Exception as e:
            logger.error(f"❌ EDR system health check failed: {e}")
            edr_status['error'] = str(e)
        
        return edr_status
    
    def cleanup(self):
        """Clean up database connections"""
        try:
            if self.engine:
                self.engine.dispose()
                logger.info("🧹 Database connections cleaned up")
        except Exception as e:
            logger.error(f"❌ Error during database cleanup: {e}")

# Global database manager instance
db_manager = DatabaseManager()

# FastAPI dependency function
def get_db() -> Generator[Session, None, None]:
    """Database dependency for FastAPI endpoints"""
    session = db_manager.get_session()
    try:
        yield session
    except Exception as e:
        session.rollback()
        logger.error(f"💥 Database session error in dependency: {e}")
        raise
    finally:
        session.close()

# Initialization and utility functions
def init_database() -> bool:
    """Initialize database connection and verify EDR schema"""
    try:
        logger.info("🔄 Initializing EDR database connection...")
        
        # Test database connection
        if not db_manager.test_connection():
            logger.error("❌ Database connection test failed")
            return False
        
        # Get database info
        db_info = db_manager.get_database_info()
        if 'error' in db_info:
            logger.error(f"❌ Database info retrieval failed: {db_info['error']}")
            return False
        
        logger.info(f"🗄️ Connected to: {db_info.get('database_name')} on {db_info.get('server_name')}")
        
        # Verify EDR critical tables exist
        edr_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules', 'SystemConfig', 'AgentConfigs']
        missing_tables = []
        
        for table in edr_tables:
            if not db_manager.check_table_exists(table):
                missing_tables.append(table)
        
        if missing_tables:
            logger.error(f"❌ Missing critical EDR tables: {missing_tables}")
            logger.error("💡 Please run the database creation script first")
            return False
        
        logger.info(f"✅ All EDR tables verified: {edr_tables}")
        
        # Log table counts for monitoring
        for table in edr_tables:
            count = db_manager.get_table_count(table)
            logger.info(f"📊 {table}: {count:,} records")
        
        # Verify system configuration
        config_count = db_manager.get_table_count('SystemConfig')
        if config_count == 0:
            logger.warning("⚠️ No system configuration found - consider loading default config")
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Database initialization failed: {e}")
        return False

def get_database_status() -> Dict:
    """Get current database status for monitoring"""
    return db_manager.health_check()

def execute_query(query: str, params: Dict = None) -> List[Dict]:
    """Execute query using global database manager"""
    return db_manager.execute_query(query, params)

def execute_non_query(query: str, params: Dict = None) -> bool:
    """Execute non-query using global database manager"""
    return db_manager.execute_non_query(query, params)

# Database maintenance functions
def get_edr_statistics() -> Dict:
    """Get EDR system statistics"""
    try:
        stats = {}
        
        # Agent statistics
        stats['agents'] = db_manager.execute_query("""
            SELECT 
                COUNT(*) as total_agents,
                SUM(CASE WHEN Status = 'Active' THEN 1 ELSE 0 END) as active_agents,
                SUM(CASE WHEN LastHeartbeat >= DATEADD(minute, -5, GETDATE()) THEN 1 ELSE 0 END) as online_agents
        """)[0]
        
        # Event statistics (last 24 hours)
        stats['events'] = db_manager.execute_query("""
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN ThreatLevel != 'None' THEN 1 ELSE 0 END) as threat_events,
                SUM(CASE WHEN Analyzed = 1 THEN 1 ELSE 0 END) as analyzed_events
            FROM Events 
            WHERE CreatedAt >= DATEADD(hour, -24, GETDATE())
        """)[0]
        
        # Alert statistics
        stats['alerts'] = db_manager.execute_query("""
            SELECT 
                COUNT(*) as total_alerts,
                SUM(CASE WHEN Status IN ('Open', 'Investigating') THEN 1 ELSE 0 END) as open_alerts,
                SUM(CASE WHEN Severity IN ('High', 'Critical') AND Status IN ('Open', 'Investigating') THEN 1 ELSE 0 END) as critical_alerts
            FROM Alerts
        """)[0]
        
        # System health
        stats['system'] = {
            'detection_rules': db_manager.get_table_count('DetectionRules'),
            'threat_indicators': db_manager.get_table_count('Threats'),
            'system_configs': db_manager.get_table_count('SystemConfig')
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"❌ Failed to get EDR statistics: {e}")
        return {}

def cleanup_old_data(retention_days: int = 90) -> Dict:
    """Cleanup old EDR data based on retention policy"""
    try:
        cleanup_results = {}
        
        # Cleanup old events (keep events linked to active alerts)
        old_events_query = """
            DELETE FROM Events 
            WHERE CreatedAt < DATEADD(day, :retention_days, GETDATE())
            AND EventID NOT IN (
                SELECT EventID FROM Alerts 
                WHERE EventID IS NOT NULL 
                AND Status IN ('Open', 'Investigating')
            )
        """
        
        # Execute cleanup (would need actual implementation)
        logger.info(f"🧹 Cleanup policy: {retention_days} days retention")
        cleanup_results['retention_days'] = retention_days
        cleanup_results['status'] = 'configured'
        
        return cleanup_results
        
    except Exception as e:
        logger.error(f"❌ Data cleanup failed: {e}")
        return {'error': str(e)}