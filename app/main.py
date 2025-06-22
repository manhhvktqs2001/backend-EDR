# app/main.py - EDR Server Main Application (UPDATED - No Auto Alerts)
"""
EDR System - Main FastAPI Application
Agent Communication Server running on 192.168.20.85:5000
MODIFIED: Server chỉ gửi notifications cho agent, KHÔNG tự động tạo alerts
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
from .api.v1 import agents, events, alerts, dashboard, threats, detection, agent_response
from .utils.network_utils import is_internal_ip

# Configure logging
logging.config.dictConfig(config['logging'])
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("🚀 Starting EDR Agent Communication Server (No Auto Alerts Mode)...")
    
    try:
        # Initialize database
        if not init_database():
            raise RuntimeError("Database initialization failed")
        
        logger.info("✅ Database initialized successfully")
        
        # Log server configuration
        server_config = config['server']
        logger.info(f"🌐 Server binding to: {server_config['bind_host']}:{server_config['bind_port']}")
        logger.info(f"🔒 Network access: {config['network']['allowed_agent_network']}")
        logger.info(f"🛡️ Detection engine: {'Enabled' if config['detection']['rules_enabled'] else 'Disabled'}")
        logger.info(f"📊 Threat intelligence: {'Enabled' if config['detection']['threat_intel_enabled'] else 'Disabled'}")
        logger.info(f"🔔 Notification system: Enabled")  # MODIFIED
        logger.info(f"🚫 Auto alert creation: DISABLED")  # NEW - Important change
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    # Shutdown
    logger.info("👋 Shutting down EDR Agent Communication Server...")

# Create FastAPI application
app = FastAPI(
    title=config['server']['title'] + " (No Auto Alerts)",  # MODIFIED title
    description=config['server']['description'] + " - Server only sends notifications to agents, does not auto-create alerts",
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
    if (request.url.path.startswith("/api/v1/agents") or 
        request.url.path.startswith("/api/v1/events") or
        request.url.path.startswith("/api/v1/alerts/submit-from-agent")):  # MODIFIED: Include agent alert submission
        if not is_internal_ip(client_ip, config['network']['allowed_agent_network']):
            logger.warning(f"🚫 Unauthorized access attempt from: {client_ip} to {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access denied from this network", "client_ip": client_ip}
            )
    
    # Process request
    response = await call_next(request)
    
    # Log request
    process_time = time.time() - start_time
    logger.info(
        f"📡 {request.method} {request.url.path} - "
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
        "message": "EDR Agent Communication Server (No Auto Alerts Mode)",  # MODIFIED
        "version": server_config['version'],
        "description": server_config['description'],
        "server_endpoint": f"http://{server_config['bind_host']}:{server_config['bind_port']}",
        "api_docs": "/docs",
        "health_check": "/health",
        "status": "running",
        "mode": "notifications_only",  # NEW: Indicate mode
        "features": {
            "authentication": False,  # Simplified - no auth
            "detection_engine": config['detection']['rules_enabled'],
            "threat_intelligence": config['detection']['threat_intel_enabled'],
            "agent_registration": config['features']['agent_registration'],
            "event_collection": config['features']['event_collection'],
            "notification_system": True,  # NEW
            "auto_alert_creation": False,  # NEW - Important
            "agent_alert_submission": True  # NEW - Agents can submit alerts
        },
        "workflow": {
            "event_processing": "Server processes events and detects threats",
            "notification_sending": "Server sends notifications to agents",
            "alert_creation": "Agents create alerts and send back to server",  # NEW
            "alert_management": "Server manages alerts submitted by agents"
        },
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
            "mode": "notifications_only",  # NEW
            "server": {
                "host": server_config['bind_host'],
                "port": server_config['bind_port'],
                "version": server_config['version'],
                "environment": config['environment'],
                "authentication": False  # No auth in simplified version
            },
            "database": {
                "connected": db_status.get('healthy', False),
                "response_time_ms": db_status.get('response_time_ms', 0),
                "tables": db_status.get('table_counts', {}),
                "server": config['database']['server'],
                "database_name": config['database']['database']
            },
            "features": {
                "detection_engine": config['detection']['rules_enabled'],
                "threat_intelligence": config['detection']['threat_intel_enabled'],
                "agent_registration": config['features']['agent_registration'],
                "event_collection": config['features']['event_collection'],
                "real_time_detection": config['features']['real_time_detection'],
                "notification_system": True,  # NEW
                "auto_alert_creation": False,  # NEW - Important
                "agent_alert_submission": True  # NEW
            },
            "network": {
                "allowed_network": config['network']['allowed_agent_network'],
                "max_agents": config['network']['max_agents']
            },
            "workflow_status": {
                "event_processing": "active",
                "threat_detection": "active" if config['detection']['rules_enabled'] else "disabled",
                "notification_sending": "active",
                "alert_auto_creation": "disabled",  # NEW
                "agent_alert_reception": "active"  # NEW
            }
        }
        
        # Return appropriate status code
        status_code = 200 if db_status.get('healthy') else 503
        return JSONResponse(content=health_data, status_code=status_code)
        
    except Exception as e:
        logger.error(f"❌ Health check failed: {e}")
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
    """Detailed system status for monitoring"""
    try:
        db_status = get_database_status()
        
        return {
            "system_status": {
                "server": "running",
                "database": "connected" if db_status.get('healthy') else "disconnected",
                "detection_engine": "enabled" if config['detection']['rules_enabled'] else "disabled",
                "threat_intel": "enabled" if config['detection']['threat_intel_enabled'] else "disabled",
                "notification_system": "enabled",  # NEW
                "auto_alert_creation": "disabled",  # NEW - Important
                "agent_alert_submission": "enabled",  # NEW
                "authentication": "disabled"  # Simplified version
            },
            "database_info": {
                "server": config['database']['server'],
                "database": config['database']['database'],
                "tables": db_status.get('table_counts', {}),
                "response_time_ms": db_status.get('response_time_ms', 0)
            },
            "performance": {
                "database_response_ms": db_status.get('response_time_ms', 0)
            },
            "configuration": {
                "allowed_network": config['network']['allowed_agent_network'],
                "heartbeat_interval": config['agent']['heartbeat_interval'],
                "event_batch_size": config['agent']['event_batch_size'],
                "risk_threshold": config['detection']['risk_score_threshold'],
                "max_agents": config['network']['max_agents']
            },
            "capabilities": {
                "agent_management": True,
                "event_processing": True,
                "threat_detection": config['detection']['rules_enabled'],
                "threat_intelligence": config['detection']['threat_intel_enabled'],
                "notification_sending": True,  # NEW
                "alert_reception": True,  # NEW
                "alert_auto_creation": False,  # NEW - Important
                "dashboard_api": True,
                "detection_rules": True
            },
            "workflow": {
                "event_flow": "Agent -> Server (process & detect) -> Agent (notifications)",
                "alert_flow": "Agent (create alerts) -> Server (manage alerts)",  # NEW
                "auto_alert_creation": False  # NEW - Important
            },
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error(f"❌ System status check failed: {e}")
        raise HTTPException(status_code=500, detail="System status check failed")

# Agent discovery endpoint (for agents to find server)
@app.get("/api/discover")
async def discover_server():
    """Server discovery endpoint for agents"""
    return {
        "server_name": "EDR Agent Communication Server (No Auto Alerts)",  # MODIFIED
        "server_version": config['server']['version'],
        "mode": "notifications_only",  # NEW
        "endpoints": {
            "agent_register": "/api/v1/agents/register",
            "agent_heartbeat": "/api/v1/agents/heartbeat",
            "event_submit": "/api/v1/events/submit",
            "event_batch": "/api/v1/events/batch",
            "get_notifications": "/api/v1/agents/{agent_id}/notifications",  # NEW
            "submit_alert": "/api/v1/alerts/submit-from-agent",  # NEW
            "pending_actions": "/api/v1/agents/{agent_id}/pending-actions",
            "action_response": "/api/v1/agents/{agent_id}/action-response"
        },
        "capabilities": {
            "max_agents": config['network']['max_agents'],
            "event_batch_size": config['agent']['event_batch_size'],
            "heartbeat_interval": config['agent']['heartbeat_interval'],
            "detection_engine": config['detection']['rules_enabled'],
            "threat_intelligence": config['detection']['threat_intel_enabled'],
            "notification_system": True,  # NEW
            "auto_alert_creation": False,  # NEW - Important
            "agent_alert_submission": True  # NEW
        },
        "workflow": {
            "event_processing": "Server processes events and sends notifications",
            "alert_creation": "Agents create and submit alerts to server",  # NEW
            "alert_management": "Server manages alerts from agents"
        },
        "authentication": {
            "required": True,  # Agents still need token
            "type": "header",
            "header": "X-Agent-Token"
        }
    }

# Include API routers
app.include_router(
    agents.router,
    prefix="/api/v1/agents",
    tags=["🖥️ Agent Management & Notifications"]  # MODIFIED tag
)

app.include_router(
    events.router,
    prefix="/api/v1/events", 
    tags=["📊 Event Processing & Detection"]  # MODIFIED tag
)

app.include_router(
    alerts.router,
    prefix="/api/v1/alerts",
    tags=["🚨 Alert Management (From Agents)"]  # MODIFIED tag
)

app.include_router(
    dashboard.router,
    prefix="/api/v1/dashboard",
    tags=["📈 Dashboard API"]
)

app.include_router(
    threats.router,
    prefix="/api/v1/threats",
    tags=["🔍 Threat Intelligence"]
)

app.include_router(
    detection.router,
    prefix="/api/v1/detection",
    tags=["🎯 Detection Rules"]
)

app.include_router(
    agent_response.router,
    prefix="/api/v1",
    tags=["🔄 Agent Response & Actions"]
)

# Global exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with detailed logging"""
    logger.error(f"💥 Unhandled exception: {exc}")
    logger.error(f"📡 Request: {request.method} {request.url}")
    logger.error(f"🌐 Client: {request.client.host}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "path": str(request.url.path),
            "method": request.method,
            "timestamp": time.time()
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP exception handler with client info"""
    logger.warning(f"⚠️ HTTP Exception: {exc.status_code} - {exc.detail}")
    logger.warning(f"📡 Request: {request.method} {request.url.path}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path),
            "method": request.method,
            "timestamp": time.time()
        }
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Value error handler for validation errors"""
    logger.warning(f"⚠️ Validation error: {exc}")
    logger.warning(f"📡 Request: {request.method} {request.url.path}")
    
    return JSONResponse(
        status_code=400,
        content={
            "error": "Validation error",
            "message": str(exc),
            "path": str(request.url.path),
            "method": request.method,
            "timestamp": time.time()
        }
    )

# Development server runner
if __name__ == "__main__":
    server_config = config['server']
    print(f"""
🚀 EDR Agent Communication Server (No Auto Alerts Mode)
🌐 Starting on: http://{server_config['bind_host']}:{server_config['bind_port']}
📚 API Documentation: http://{server_config['bind_host']}:{server_config['bind_port']}/docs
🔍 Health Check: http://{server_config['bind_host']}:{server_config['bind_port']}/health

🔔 WORKFLOW MODE: Notifications Only
   • Server processes events and detects threats
   • Server sends notifications to agents
   • Agents create alerts and send back to server
   • Server manages alerts from agents
   • NO automatic alert creation by server
    """)
    
    uvicorn.run(
        "app.main:app",
        host=server_config['bind_host'],
        port=server_config['bind_port'],
        reload=server_config['reload'],
        log_level="info"
    )