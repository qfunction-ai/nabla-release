"""Nabla web server — FastAPI application for the web UI.

Run with: uvicorn nabla.server:app
Or via CLI: nabla web
Or via Docker: NABLA_WEB_ENABLED=1
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from nabla.api.auth import router as auth_router
from nabla.api.pipeline import router as pipeline_router
from nabla.api.dashboard import router as dashboard_router
from nabla.api.entities import router as entities_router
from nabla.api.incidents import router as incidents_router
from nabla.api.chat import router as chat_router
from nabla.api.config import router as config_router
from nabla.api.system import router as system_router
from nabla.api.upload import router as upload_router
from nabla.api.timeline import router as timeline_router
from nabla.log import get_logger
from nabla.rate_limit import limiter

logger = get_logger("server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown."""
    logger.info("Nabla web server starting up")
    yield
    logger.info("Nabla web server shutting down")


app = FastAPI(
    title="Nabla API",
    description="UEBA multi-agent system — API for the web UI",
    version="0.2.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Include routers
app.include_router(auth_router)
app.include_router(pipeline_router)
app.include_router(dashboard_router)
app.include_router(entities_router)
app.include_router(incidents_router)
app.include_router(chat_router)
app.include_router(config_router)
app.include_router(system_router)
app.include_router(upload_router)
app.include_router(timeline_router)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


def main():
    """Entry point for the nabla-web script."""
    import uvicorn
    from nabla.config import get_settings

    settings = get_settings()
    uvicorn.run(
        "nabla.server:app",
        host=settings.web_host,
        port=settings.web_port,
        reload=False,
    )
