# app/main.py - EDR Server Main Application
"""
EDR System - Main FastAPI Application
Agent Communication Server running on 192.168.20.85:5000
"""

import logging
import logging.config
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, FileResponse
import uvicorn
from fastapi.staticfiles import StaticFiles
import threading
import time as pytime
from datetime import datetime
import sys
import asyncio

from .config import config
from .database import init_database, get_database_status, SessionLocal
from .api.v1 import agents, events, alerts, dashboard, threats, detection, agent_response, router as v1_router
from .utils.network_utils import is_internal_ip
from .services.agent_service import agent_service
from .models.agent import Agent

# Configure logging
logging.config.dictConfig(config['logging'])
logger = logging.getLogger(__name__)

active_ws_connections = {}

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

def warmup_queries():
    from .database import SessionLocal
    from .models.agent import Agent
    from .models.event import Event
    from .models.alert import Alert
    from .models.threat import Threat
    from .models.detection_rule import DetectionRule
    session = SessionLocal()
    try:
        session.query(Agent).count()
        session.query(Event).count()
        session.query(Alert).count()
        session.query(Threat).count()
        session.query(DetectionRule).count()
    except Exception as e:
        print(f"Warmup error: {e}")
    finally:
        session.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("🚀 Starting EDR Agent Communication Server...")
    
    try:
        # Initialize database
        if not init_database():
            raise RuntimeError("Database initialization failed")
        
        logger.info("✅ Database initialized successfully")
        
        # Warm-up query để khởi tạo pool/cache/ORM mapping
        threading.Thread(target=warmup_queries, daemon=True).start()
        
        # Log server configuration
        server_config = config['server']
        logger.info(f"🌐 Server binding to: {server_config['bind_host']}:{server_config['bind_port']}")
        logger.info(f"🔒 Network access: {config['network']['allowed_agent_network']}")
        logger.info(f"🛡️ Detection engine: {'Enabled' if config['detection']['rules_enabled'] else 'Disabled'}")
        logger.info(f"📊 Threat intelligence: {'Enabled' if config['detection']['threat_intel_enabled'] else 'Disabled'}")
        
        # Start agent cleanup job
        threading.Thread(target=agent_cleanup_job, daemon=True).start()
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    # Shutdown
    logger.info("👋 Shutting down EDR Agent Communication Server...")
    
    # Close all WebSocket connections gracefully
    try:
        for agent_id, websocket in active_ws_connections.items():
            try:
                await websocket.close()
            except:
                pass
        active_ws_connections.clear()
    except Exception as e:
        logger.error(f"Error during WebSocket cleanup: {e}")

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
    if (request.url.path.startswith("/api/v1/agents") or 
        request.url.path.startswith("/api/v1/events") or
        request.url.path.startswith("/api/v1/alerts/submit-from-agent")):
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
                "tables": db_status.get('table_counts', {}),
                "server": config['database']['server'],
                "database_name": config['database']['database']
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
        logger.error(f"❌ Health check failed: {e}")
        return JSONResponse(
            content={
                "status": "unhealthy",
                "error": "Health check failed",
                "timestamp": time.time()
            },
            status_code=503
        )

# Include API routers
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(events.router, prefix="/api/v1/events", tags=["events"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
app.include_router(detection.router, prefix="/api/v1/detection", tags=["detection"])
app.include_router(agent_response.router, prefix="/api/v1/agent-response", tags=["agent-response"])
app.include_router(v1_router, prefix="/api/v1")

# Global exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"❌ Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Value error handler"""
    return JSONResponse(
        status_code=400,
        content={"error": "Bad request", "detail": str(exc)}
    )

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Development server runner
if __name__ == "__main__":
    server_config = config['server']
    print(f"""
🚀 EDR Agent Communication Server
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
    
    try:
        uvicorn.run(
            "app.main:app",
            host=server_config['bind_host'],
            port=server_config['bind_port'],
            reload=server_config['reload'],
            log_level="info",
            loop="asyncio"
        )
    except KeyboardInterrupt:
        print("\n👋 Server shutdown requested")
    except Exception as e:
        print(f"❌ Server error: {e}")

@app.get("/favicon.ico")
async def favicon():
    return FileResponse("static/favicon.ico")

def agent_cleanup_job():
    logger = logging.getLogger(__name__)
    while True:
        try:
            with SessionLocal() as session:
                count, agents = agent_service.cleanup_stale_agents(session, hours=0.1)  # 6 phút không heartbeat thì offline
                if count > 0:
                    logger.info(f"[AgentCleanup] Marked {count} agents offline: {agents}")
        except Exception as e:
            logger.error(f"[AgentCleanup] Error: {e}")
        pytime.sleep(60)  # chạy mỗi 1 phút

@app.websocket("/ws/agent/{agent_id}")
async def agent_ws(websocket: WebSocket, agent_id: str):
    await websocket.accept()
    db = SessionLocal()
    try:
        # Khi agent kết nối, cập nhật trạng thái online
        agent = db.query(Agent).filter(Agent.AgentID == agent_id).first()
        if agent:
            agent.Status = "Active"
            agent.LastHeartbeat = datetime.now()
            db.commit()
        active_ws_connections[agent_id] = websocket
        while True:
            # Đợi tin nhắn từ agent (có thể là heartbeat hoặc dữ liệu khác)
            data = await websocket.receive_text()
            # Có thể xử lý thêm nếu muốn
    except WebSocketDisconnect:
        # Khi agent disconnect, cập nhật trạng thái offline NGAY LẬP TỨC
        agent = db.query(Agent).filter(Agent.AgentID == agent_id).first()
        if agent:
            agent.Status = "Offline"
            db.commit()
        active_ws_connections.pop(agent_id, None)
    except Exception as e:
        logger.error(f"WebSocket error for agent {agent_id}: {e}")
    finally:
        try:
            db.close()
        except:
            pass

@app.websocket("/ws/dashboard")
async def dashboard_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await asyncio.sleep(60)  # giữ kết nối, có thể gửi dữ liệu sau
    except WebSocketDisconnect:
        pass

@app.get("/status")
def status():
    return {"status": "ok"}