"""FastAPI gateway exposing the scanners, the tool-call policy and the audit log."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, generate_latest

from . import __version__
from .audit import AuditLog, fingerprint
from .config import Settings
from .engine import ShieldEngine
from .models import ScanRequest, ScanResult, ToolCallRequest, ToolDecision
from .ratelimit import RateLimiter
from .tool_policy import ToolPolicy


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    engine = ShieldEngine(block_threshold=settings.block_threshold)
    policy = ToolPolicy.from_file(settings.policy_path)
    audit = AuditLog(settings.audit_path)
    limiter = RateLimiter(settings.rate_limit_capacity, settings.rate_limit_per_second)

    registry = CollectorRegistry()
    scans = Counter("agent_shield_scans_total", "Scans performed", ["kind", "action"], registry=registry)
    tool_calls = Counter("agent_shield_tool_calls_total", "Tool-call decisions", ["verdict"], registry=registry)
    rate_limited = Counter("agent_shield_rate_limited_total", "Requests rejected by rate limiting", registry=registry)

    app = FastAPI(
        title="Agent-Shield",
        version=__version__,
        description="Security gateway for AI agents: prompt-injection defence, data-leak prevention, "
        "least-privilege tool authorisation and a tamper-evident audit trail.",
    )

    app.state.audit = audit

    def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if settings.api_key and not (x_api_key and hmac.compare_digest(x_api_key, settings.api_key)):
            raise HTTPException(status_code=401, detail="missing or invalid API key")

    def throttle(agent_id: str) -> None:
        if not limiter.allow(agent_id):
            rate_limited.inc()
            raise HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": "1"})

    def record(kind: str, agent_id: str, **event: Any) -> None:
        audit.append({"kind": kind, "agent_id": agent_id, **event})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/scan/input", response_model=ScanResult, dependencies=[Depends(require_api_key)])
    def scan_input(request: ScanRequest) -> ScanResult:
        """Scan text headed *to* the model: a prompt, retrieved document or tool output."""
        throttle(request.agent_id)
        result = engine.scan_input(request.text, request.source)
        scans.labels("input", result.action.value).inc()
        record(
            "scan_input", request.agent_id, source=request.source, action=result.action.value,
            risk=result.risk_score, rules=sorted({f.rule for f in result.findings}),
            text_sha=fingerprint(request.text), length=len(request.text),
        )
        return result

    @app.post("/v1/scan/output", response_model=ScanResult, dependencies=[Depends(require_api_key)])
    def scan_output(request: ScanRequest) -> ScanResult:
        """Scan text coming *from* the model before it reaches the user or another system."""
        throttle(request.agent_id)
        result = engine.scan_output(request.text)
        scans.labels("output", result.action.value).inc()
        record(
            "scan_output", request.agent_id, action=result.action.value, risk=result.risk_score,
            rules=sorted({f.rule for f in result.findings}),
            text_sha=fingerprint(request.text), length=len(request.text),
        )
        return result

    @app.post("/v1/authorize/tool-call", response_model=ToolDecision, dependencies=[Depends(require_api_key)])
    def authorize_tool_call(request: ToolCallRequest) -> ToolDecision:
        """Decide whether an agent may run a tool with the given arguments."""
        throttle(request.agent_id)
        decision = policy.evaluate(request.tool, request.arguments)
        tool_calls.labels(decision.verdict.value).inc()
        record(
            "tool_call", request.agent_id, tool=request.tool, verdict=decision.verdict.value,
            reasons=decision.reasons, arg_names=sorted(request.arguments),
        )
        return decision

    @app.get("/v1/audit", dependencies=[Depends(require_api_key)])
    def get_audit(limit: int = Query(default=50, ge=1, le=1000)) -> dict[str, Any]:
        return {"count": len(audit), "entries": audit.entries(limit)}

    @app.get("/v1/audit/verify", dependencies=[Depends(require_api_key)])
    def verify_audit() -> dict[str, Any]:
        ok, broken_at = audit.verify()
        return {"valid": ok, "entries": len(audit), "first_broken_seq": broken_at}

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    return app
