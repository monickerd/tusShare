"""Canonical SecurityEvent schema — shared by the event bus and all SIEM output paths.

Every security event emitted by the application is represented as a SecurityEvent.
The event_bus persists these to the security_events table and fans them out to
live subscribers (SSE audit stream, syslog, webhook) that will be wired in E7.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class EventActor(BaseModel):
    user_id: str | None = None
    username: str | None = None
    ip: str | None = None
    session_id: str | None = None


class EventTarget(BaseModel):
    type: str         # file / folder / team / user / share / system
    id: str | None = None
    name: str | None = None


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str                     # dot-namespaced, e.g. "admin.emergency_revocation"
    severity: str = "info"              # info | warning | critical
    actor: EventActor = Field(default_factory=EventActor)
    target: EventTarget | None = None
    outcome: str | None = None          # success | failure | blocked
    detail: dict[str, Any] = Field(default_factory=dict)
    org_id: str | None = None           # reserved for future multi-tenant use

    # Populated for admin-on-user actions so both sides are recorded.
    admin_actor_id: str | None = None
