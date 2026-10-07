"""Combines the detectors into a single allow / redact / block decision."""

from __future__ import annotations

from .injection import detect_injection
from .models import Action, Finding, ScanResult, Severity
from .pii import SECRET_RULES, detect_sensitive, redact

# Text that did not come directly from the user is more likely to carry an indirect injection,
# so the same findings are weighted higher.
_UNTRUSTED_BOOST = {"user": 1.0, "tool_output": 1.25, "document": 1.25}


def risk_score(findings: list[Finding], boost: float = 1.0) -> float:
    """Noisy-OR: independent signals compound but the score never exceeds 1.0."""
    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - min(1.0, finding.weight * boost)
    return round(1.0 - remaining, 4)


class ShieldEngine:
    def __init__(self, block_threshold: float = 0.7) -> None:
        self.block_threshold = block_threshold

    def scan_input(self, text: str, source: str = "user") -> ScanResult:
        """Scan text going *into* the model (user prompt, retrieved document, tool output)."""
        injection = detect_injection(text)
        sensitive = detect_sensitive(text)
        findings = injection + sensitive

        injection_score = risk_score(injection, _UNTRUSTED_BOOST.get(source, 1.0))
        has_critical = any(f.severity is Severity.CRITICAL for f in findings)

        if injection_score >= self.block_threshold or has_critical:
            return ScanResult(
                action=Action.BLOCK,
                risk_score=max(injection_score, risk_score(findings)),
                findings=findings,
            )
        if sensitive:
            return ScanResult(
                action=Action.REDACT,
                risk_score=risk_score(findings),
                findings=findings,
                sanitized_text=redact(text, sensitive),
            )
        return ScanResult(action=Action.ALLOW, risk_score=injection_score, findings=findings)

    def scan_output(self, text: str) -> ScanResult:
        """Scan text coming *out of* the model for leaked secrets, PII and exfiltration links."""
        sensitive = detect_sensitive(text)
        exfil = [f for f in detect_injection(text) if f.rule == "markdown_exfiltration"]
        findings = exfil + sensitive
        if exfil:
            return ScanResult(action=Action.BLOCK, risk_score=risk_score(findings), findings=findings)
        if sensitive:
            leaked_secret = any(f.rule in SECRET_RULES for f in sensitive)
            return ScanResult(
                action=Action.BLOCK if leaked_secret else Action.REDACT,
                risk_score=risk_score(findings),
                findings=findings,
                sanitized_text=None if leaked_secret else redact(text, sensitive),
            )
        return ScanResult(action=Action.ALLOW, risk_score=0.0, findings=[])
