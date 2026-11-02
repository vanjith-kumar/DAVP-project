from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.logs import router as logs_router
from app.api.alerts import router as alerts_router
from app.api.detection import router as detection_router
from app.api.ai import router as ai_router
from app.api.anomaly import router as anomaly_router
from app.api.threat_intel import router as ti_router
from app.api.dashboard import router as dashboard_router
from app.api.incidents import router as incidents_router
from app.api.reports import router as reports_router
from app.api.packets import router as packets_router

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Phase 3 Intelligence for SecureLog AI",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health_router, prefix="/api/health", tags=["health"])
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(logs_router, prefix="/api/logs", tags=["logs"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["alerts"])
app.include_router(detection_router, prefix="/api/detection", tags=["detection"])
app.include_router(ai_router, prefix="/api/ai", tags=["ai"])
app.include_router(anomaly_router, prefix="/api/anomaly", tags=["anomaly"])
app.include_router(ti_router, prefix="/api/threat-intelligence", tags=["threat-intel"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(incidents_router, prefix="/api/incidents", tags=["incidents"])
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
app.include_router(packets_router, prefix="/api/packets", tags=["packets"])

from app.realtime.websocket import router as ws_router
app.include_router(ws_router, tags=["realtime"])

@app.get("/")
def root():
    return {"message": "Welcome to SecureLog AI API"}
