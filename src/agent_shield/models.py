"""Shared data models for detectors, the engine and the HTTP API."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class Finding(BaseModel):
    """One thing a detector noticed. `start`/`end` index the original text when known."""

    detector: str
    rule: str
    severity: Severity
    weight: float = Field(ge=0.0, le=1.0, description="Contribution to the risk score")
    detail: str = ""
    start: int | None = None
    end: int | None = None


class ScanRequest(BaseModel):
    agent_id: str = Field(default="anonymous", max_length=128)
    text: str = Field(max_length=100_000)
    source: str = Field(
        default="user",
        pattern="^(user|tool_output|document)$",
        description="Where the text came from. Tool output and documents are untrusted by default.",
    )


class ScanResult(BaseModel):
    action: Action
    risk_score: float
    findings: list[Finding]
    sanitized_text: str | None = None


class ToolCallRequest(BaseModel):
    agent_id: str = Field(default="anonymous", max_length=128)
    tool: str = Field(max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class ToolDecision(BaseModel):
    verdict: ToolVerdict
    reasons: list[str]
