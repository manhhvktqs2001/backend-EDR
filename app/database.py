"""
Database Connection Manager for EDR Server
SQLAlchemy integration with SQL Server
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

# SQLAlchemy Base for models
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
            
            # Create engine with optimized settings
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
            
            logger.info("Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    def _add_event_listeners(self):
        """Add SQLAlchemy event listeners for monitoring"""
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            logger.debug("Database connection established")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug("Database connection checked out from pool")
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            logger.debug("Database connection returned to pool")
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text("SELECT 1 as test"))
                row = result.fetchone()
                if row and row[0] == 1:
                    self.is_connected = True
                    logger.info("Database connection test successful")
                    return True
                else:
                    self.is_connected = False
                    logger.error("Database connection test failed - unexpected result")
                    return False
        except Exception as e:
            self.is_connected = False
            logger.error(f"Database connection test failed: {e}")
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
            logger.error(f"Database session error: {e}")
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"Unexpected error in database session: {e}")
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
            logger.error(f"Query execution failed: {e}")
            logger.error(f"Query: {query}")
            if params:
                logger.error(f"Params: {params}")
            return []
    
    def execute_non_query(self, query: str, params: Dict = None) -> bool:
        """Execute non-query SQL statement"""
        try:
            with self.get_db_session() as session:
                session.execute(text(query), params or {})
                return True
        except Exception as e:
            logger.error(f"Non-query execution failed: {e}")
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
            logger.error(f"Error getting count for table {table_name}: {e}")
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
            logger.error(f"Error checking table existence {table_name}: {e}")
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
                    GETDATE() as current_time
            """)
            if basic_info:
                info.update(basic_info[0])
            
            # Table information
            tables_info = self.execute_query("""
                SELECT 
                    TABLE_NAME,
                    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = t.TABLE_NAME) as column_count
                FROM INFORMATION_SCHEMA.TABLES t
                WHERE TABLE_SCHEMA = 'dbo' AND TABLE_TYPE = 'BASE TABLE'
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
            logger.error(f"Error getting database info: {e}")
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
                'invalid': pool.invalid(),
                'total_connections': pool.size() + pool.overflow()
            }
        except Exception as e:
            logger.error(f"Error getting pool status: {e}")
            return {}
    
    def health_check(self) -> Dict:
        """Comprehensive database health check"""
        start_time = time.time()
        health_status = {
            'healthy': False,
            'response_time_ms': 0,
            'connection_pool': {},
            'database_info': {},
            'table_counts': {},
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
            
            # Check critical tables
            critical_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules']
            for table in critical_tables:
                if self.check_table_exists(table):
                    health_status['table_counts'][table] = self.get_table_count(table)
                else:
                    health_status['errors'].append(f'Table {table} not found')
            
            # Calculate response time
            health_status['response_time_ms'] = int((time.time() - start_time) * 1000)
            
            # Determine overall health
            health_status['healthy'] = len(health_status['errors']) == 0
            
        except Exception as e:
            health_status['errors'].append(f'Health check failed: {str(e)}')
            logger.error(f"Database health check failed: {e}")
        
        return health_status
    
    def cleanup(self):
        """Clean up database connections"""
        try:
            if self.engine:
                self.engine.dispose()
                logger.info("Database connections cleaned up")
        except Exception as e:
            logger.error(f"Error during database cleanup: {e}")

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
        logger.error(f"Database session error in dependency: {e}")
        raise
    finally:
        session.close()

# Initialization and utility functions
def init_database() -> bool:
    """Initialize database connection and verify schema"""
    try:
        logger.info("Initializing EDR database connection...")
        
        # Test database connection
        if not db_manager.test_connection():
            logger.error("Database connection test failed")
            return False
        
        # Get database info
        db_info = db_manager.get_database_info()
        if 'error' in db_info:
            logger.error(f"Database info retrieval failed: {db_info['error']}")
            return False
        
        logger.info(f"Connected to database: {db_info.get('database_name')} on {db_info.get('server_name')}")
        
        # Verify critical tables exist
        critical_tables = ['Agents', 'Events', 'Alerts', 'Threats', 'DetectionRules']
        missing_tables = []
        
        for table in critical_tables:
            if not db_manager.check_table_exists(table):
                missing_tables.append(table)
        
        if missing_tables:
            logger.error(f"Missing critical tables: {missing_tables}")
            return False
        
        logger.info(f"All critical tables verified: {critical_tables}")
        
        # Log table counts
        for table in critical_tables:
            count = db_manager.get_table_count(table)
            logger.info(f"Table {table}: {count} records")
        
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
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