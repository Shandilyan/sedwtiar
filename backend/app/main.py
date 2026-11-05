from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine, SessionLocal
import app.models
from app.routers.api import api_router
from app.services import scheduling as scheduling_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tables exist and default scheduling resources are seeded
    try:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            scheduling_service.ensure_default_resources(db)
    except Exception as exc:
        print(f"[Startup Warning] Database initialization: {exc}")
    yield


app = FastAPI(
    title="SEDWTIAR Local Backend",
    version="0.1.0",
    description="Local backend for secure IT asset sanitization and lifecycle management.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Confirms that the local backend is running."""
    return {
        "status": "ok",
        "service": "sedwtiar-backend",
    }


# Static Files & Frontend SPA serving for Desktop & Web runtime
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if FRONTEND_DIST.exists():
    if (FRONTEND_DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        file_path = FRONTEND_DIST / full_path
        if full_path and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIST / "index.html"))
