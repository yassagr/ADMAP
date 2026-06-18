import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .routers import status, m1, m2, m3, m4, m5, pipeline
from .ws import jobs

logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ADMAP Gateway")
    yield
    logger.info("Shutting down ADMAP Gateway")

app = FastAPI(
    title="ADMAP Gateway",
    description="Backend For Frontend Gateway orchestrating M1-M5 ADMAP Microservices",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(status.router, prefix="/api", tags=["Status"])
app.include_router(m1.router, prefix="/api/m1", tags=["M1 - IOC Extractor"])
app.include_router(m2.router, prefix="/api/m2", tags=["M2 - C2 Detector"])
app.include_router(m3.router, prefix="/api/m3", tags=["M3 - YARA Generator"])
app.include_router(m4.router, prefix="/api/m4", tags=["M4 - APT Mapper"])
app.include_router(m5.router, prefix="/api/m5", tags=["M5 - Attribution"])
app.include_router(pipeline.router, prefix="/api/pipeline", tags=["Pipeline Execution"])
app.include_router(jobs.router, prefix="/ws", tags=["WebSockets"])

@app.get("/")
async def root():
    return {"message": "ADMAP Gateway is running."}
