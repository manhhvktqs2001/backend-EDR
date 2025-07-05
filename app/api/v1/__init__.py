"""
API Version 1 Package
"""

import time

# This makes the v1 directory a Python package
from . import agents, events, alerts, dashboard, threats, detection, agent_response
from fastapi import APIRouter

router = APIRouter()

@router.get("/health/check")
async def health_check():
    return {"status": "ok"}

@router.get("/status")
async def status():
    """API v1 status endpoint"""
    return {
        "status": "ok",
        "version": "1.0",
        "timestamp": time.time()
    }