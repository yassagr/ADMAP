from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field
from admap_m5.models.output import AttributionReport


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AttributionJob(BaseModel):
    model_config = ConfigDict(frozen=True)
    job_id: str
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    result: AttributionReport | None = None
    progress: int = Field(default=0, ge=0, le=100)
