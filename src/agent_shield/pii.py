"""Sensitive-data detection and redaction (PII and credentials)."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .models import Finding, Severity


def luhn_valid(number: str) -> bool:
    """Luhn checksum, used to avoid flagging arbitrary digit runs as card numbers."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _valid_ssn(value: str) -> bool:
    area, group, serial = value.replace(" ", "-").split("-")
    return area not in {"000", "666"} and not area.startswith("9") and group != "00" and serial != "0000"


@dataclass(frozen=True)
class Detector:
    name: str
    severity: Severity
    weight: float
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


DETECTORS: tuple[Detector, ...] = (
    Detector("private_key", Severity.CRITICAL, 1.0,
             re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    Detector("aws_access_key", Severity.CRITICAL, 0.95, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("github_token", Severity.CRITICAL, 0.95, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    Detector("slack_token", Severity.CRITICAL, 0.95, re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Detector("jwt", Severity.HIGH, 0.8,
             re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Detector("generic_secret", Severity.HIGH, 0.7,
             re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}")),
    Detector("credit_card", Severity.HIGH, 0.8,
             re.compile(r"\b(?:\d[ -]?){13,19}\b"), luhn_valid),
    Detector("us_ssn", Severity.HIGH, 0.7,
             re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"), _valid_ssn),
    Detector("email", Severity.LOW, 0.2,
             re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("phone", Severity.LOW, 0.2,
             re.compile(r"(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\d)")),
)

SECRET_RULES = frozenset(
    {"private_key", "aws_access_key", "github_token", "slack_token", "jwt", "generic_secret"}
)


def detect_sensitive(text: str) -> list[Finding]:
    """Find PII and credentials. Overlapping matches keep the first (most severe) detector."""
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            start, end = match.span()
            if detector.validator and not detector.validator(match.group()):
                continue
            if any(start < t_end and end > t_start for t_start, t_end in taken):
                continue
            taken.append((start, end))
            findings.append(
                Finding(
                    detector="sensitive_data",
                    rule=detector.name,
                    severity=detector.severity,
                    weight=detector.weight,
                    detail=f"{detector.name.replace('_', ' ')} detected",
                    start=start,
                    end=end,
                )
            )
    return sorted(findings, key=lambda f: f.start or 0)


def redact(text: str, findings: list[Finding]) -> str:
    """Replace each located finding with a `[REDACTED:<rule>]` marker."""
    located = sorted((f for f in findings if f.start is not None and f.end is not None),
                     key=lambda f: f.start or 0, reverse=True)
    for finding in located:
        text = f"{text[: finding.start]}[REDACTED:{finding.rule.upper()}]{text[finding.end:]}"
    return text
