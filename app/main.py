# app/main.py - Final Fixed Version
"""
EDR System - Main FastAPI Application
Agent Communication Server running on 192.168.20.85:5000
"""

import logging
import logging.config
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import config
from .database import init_database, get_database_status
from .api.v1 import agents, events, alerts, dashboard, threats
from .utils.network_utils import is_internal_ip

# Configure logging with Unicode support
logging.config.dictConfig(config['logging'])
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting EDR Agent Communication Server...")
    
    try:
        # Initialize database
        if not init_database():
            raise RuntimeError("Database initialization failed")
        
        logger.info("Database initialized successfully")
        
        # Log server configuration
        server_config = config['server']
        logger.info(f"Server binding to: {server_config['bind_host']}:{server_config['bind_port']}")
        logger.info(f"Network access: {config['network']['allowed_agent_network']}")
        logger.info(f"Detection engine: {'Enabled' if config['detection']['rules_enabled'] else 'Disabled'}")
        logger.info(f"Threat intelligence: {'Enabled' if config['detection']['threat_intel_enabled'] else 'Disabled'}")
        
        # Directories are already created in config.py
        logger.info("All required directories verified")
        
        yield
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    
    # Shutdown
    logger.info("Shutting down EDR Agent Communication Server...")

# Create FastAPI application
app = FastAPI(
    title=config['server']['title'],
    description=config['server']['description'],
    version=config['server']['version'],
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Trust proxy middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config['security']['cors_origins'],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Request logging and security middleware
@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    """Security validation and request logging"""
    start_time = time.time()
    client_ip = request.client.host
    
    # Network access validation for agent endpoints
    if request.url.path.startswith("/api/v1/agents") or request.url.path.startswith("/api/v1/events"):
        if not is_internal_ip(client_ip, config['network']['allowed_agent_network']):
            logger.warning(f"Unauthorized access attempt from: {client_ip} to {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access denied from this network", "client_ip": client_ip}
            )
    
    # Process request
    response = await call_next(request)
    
    # Log request
    process_time = time.time() - start_time
    logger.info(
        f"REQUEST {request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.3f}s - "
        f"Client: {client_ip}"
    )
    
    return response

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with server information"""
    server_config = config['server']
    return {
        "message": "EDR Agent Communication Server",
        "version": server_config['version'],
        "description": server_config['description'],
        "server_endpoint": f"http://{server_config['bind_host']}:{server_config['bind_port']}",
        "api_docs": "/docs",
        "health_check": "/health",
        "status": "running",
        "timestamp": time.time()
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    try:
        db_status = get_database_status()
        server_config = config['server']
        
        health_data = {
            "status": "healthy" if db_status.get('healthy') else "unhealthy",
            "timestamp": time.time(),
            "server": {
                "host": server_config['bind_host'],
                "port": server_config['bind_port'],
                "version": server_config['version'],
                "environment": config['environment']
            },
            "database": {
                "connected": db_status.get('healthy', False),
                "response_time_ms": db_status.get('response_time_ms', 0),
                "tables": db_status.get('table_counts', {})
            },
            "features": {
                "detection_engine": config['detection']['rules_enabled'],
                "threat_intelligence": config['detection']['threat_intel_enabled'],
                "agent_registration": config['features']['agent_registration'],
                "event_collection": config['features']['event_collection']
            }
        }
        
        # Return appropriate status code
        status_code = 200 if db_status.get('healthy') else 503
        return JSONResponse(content=health_data, status_code=status_code)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            content={
                "status": "unhealthy",
                "error": "Health check failed",
                "timestamp": time.time()
            },
            status_code=503
        )

# System status endpoint
@app.get("/api/status")
async def system_status():
    """Detailed system status"""
    try:
        db_status = get_database_status()
        
        return {
            "system_status": {
                "server": "running",
                "database": "connected" if db_status.get('healthy') else "disconnected",
                "detection_engine": "enabled" if config['detection']['rules_enabled'] else "disabled",
                "threat_intel": "enabled" if config['detection']['threat_intel_enabled'] else "disabled"
            },
            "database_info": db_status.get('database_info', {}),
            "performance": {
                "database_response_ms": db_status.get('response_time_ms', 0),
                "connection_pool": db_status.get('connection_pool', {})
            },
            "configuration": {
                "allowed_network": config['network']['allowed_agent_network'],
                "heartbeat_interval": config['agent']['heartbeat_interval'],
                "event_batch_size": config['agent']['event_batch_size'],
                "risk_threshold": config['detection']['risk_score_threshold']
            },
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error(f"System status check failed: {e}")
        raise HTTPException(status_code=500, detail="System status check failed")

# Include API routers
app.include_router(
    agents.router,
    prefix="/api/v1/agents",
    tags=["agents"]
)

app.include_router(
    events.router,
    prefix="/api/v1/events", 
    tags=["events"]
)

app.include_router(
    alerts.router,
    prefix="/api/v1/alerts",
    tags=["alerts"]
)

app.include_router(
    dashboard.router,
    prefix="/api/v1/dashboard",
    tags=["dashboard"]
)

app.include_router(
    threats.router,
    prefix="/api/v1/threats",
    tags=["threats"]
)

# Global exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    logger.error(f"Request: {request.method} {request.url}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "path": str(request.url.path),
            "timestamp": time.time()
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP exception handler"""
    logger.warning(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path),
            "timestamp": time.time()
        }
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Value error handler for validation errors"""
    logger.warning(f"Validation error: {exc}")
    
    return JSONResponse(
        status_code=400,
        content={
            "error": "Validation error",
            "message": str(exc),
            "path": str(request.url.path),
            "timestamp": time.time()
        }
    )

# Development server runner
if __name__ == "__main__":
    server_config = config['server']
    uvicorn.run(
        "app.main:app",
        host=server_config['bind_host'],
        port=server_config['bind_port'],
        reload=server_config['reload'],
        log_level="info"
    )