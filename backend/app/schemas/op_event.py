"""OperationalEvent — wire schema for the G1 operational notification system."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class OperationalEvent(BaseModel):
    event_id:   str      = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:  datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version:    str      = "1"
    event_type: str
    severity:   str      = "info"   # "info" | "warning" | "error"
    source:     str                 # "storage" | "upload" | "task" | "system" | "security"
    data:       dict[str, Any] = Field(default_factory=dict)
    server_id:  str | None = None
