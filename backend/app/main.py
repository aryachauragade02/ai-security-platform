import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import llm
from .config import settings
from .routes_agents import router as agents_router
from .routes_agents import seed_default_policies
from .routes_gateway import router as gateway_router
from .routes_scanner import router as scanner_router
from .store import get_store

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        seed_default_policies()
    except Exception as exc:  # e.g. Supabase tables not created yet
        log.warning("Could not seed default policies: %s", exc)
    yield


app = FastAPI(
    title="AI Security Platform",
    description="LLM gateway, red-team scanner and agent permission layer",
    version="1.0.0",
    lifespan=lifespan,
)

origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(gateway_router)
app.include_router(scanner_router)
app.include_router(agents_router)


@app.get("/")
def root():
    return {"name": "AI Security Platform", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "llm": "mock" if llm.is_mock() else settings.gemini_model,
        "store": get_store().name,
        "gateway_key_required": bool(settings.gateway_api_key),
        "admin_key_required": bool(settings.admin_api_key),
    }
