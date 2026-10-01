from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.health import router as health_router
from app.api.auth import router as auth_router
# Future routers
# from app.api.logs import router as logs_router

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Phase 1 Foundation for SecureLog AI",
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

# Placeholders for future phases
# app.include_router(logs_router, prefix="/api/logs", tags=["logs"])

@app.get("/")
def root():
    return {"message": "Welcome to SecureLog AI API"}
