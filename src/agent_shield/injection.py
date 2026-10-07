"""Prompt-injection detection.

Heuristic and rule based on purpose: it is fast, deterministic, explainable and has no model
dependency. Text is normalised first (Unicode NFKC, invisible characters removed) so that simple
obfuscation does not slip past the patterns, and base64 blobs are decoded and re-scanned.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

from .models import Finding, Severity

# Zero-width / bidi control characters commonly used to hide instructions from human reviewers.
_INVISIBLE = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")
# Unicode "tag" block: invisible characters that can smuggle ASCII text past a reader.
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass(frozen=True)
class Rule:
    name: str
    severity: Severity
    weight: float
    pattern: re.Pattern[str]
    description: str


def _rule(name: str, severity: Severity, weight: float, regex: str, description: str) -> Rule:
    return Rule(name, severity, weight, re.compile(regex, re.IGNORECASE | re.DOTALL), description)


RULES: tuple[Rule, ...] = (
    _rule(
        "instruction_override",
        Severity.HIGH,
        0.8,
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b"
        r".{0,30}\b(instructions?|prompts?|rules?|directions?|guidelines?|constraints?|context)\b",
        "Tries to cancel earlier instructions",
    ),
    _rule(
        "system_prompt_exfiltration",
        Severity.HIGH,
        0.75,
        r"\b(reveal|show|print|repeat|output|leak|display|tell me|what (is|are))\b.{0,40}"
        r"\b(system|hidden|initial|original|secret)\b.{0,20}\b(prompt|instructions?|message)\b",
        "Asks the model to disclose its system prompt",
    ),
    _rule(
        "role_hijack",
        Severity.HIGH,
        0.75,
        r"\b(you are now|from now on,? you are|act as|pretend (to be|you are)|roleplay as|enter)\b.{0,60}"
        r"\b(dan|developer mode|jailbroken|unrestricted|no restrictions|without (any )?restrictions|evil)\b",
        "Tries to switch the model into an unrestricted persona",
    ),
    _rule(
        "jailbreak_keyword",
        Severity.MEDIUM,
        0.5,
        r"\b(jailbreak|do anything now|developer mode (enabled|on))\b",
        "Well-known jailbreak vocabulary",
    ),
    _rule(
        "delimiter_spoofing",
        Severity.HIGH,
        0.7,
        r"(<\|?\s*(im_start|im_end|system|endoftext)\s*\|?>|\[/?INST\]|<<\s*/?sys\s*>>|^\s*#{2,}\s*system\b)",
        "Fakes chat-template or system-message delimiters",
    ),
    _rule(
        "markdown_exfiltration",
        Severity.HIGH,
        0.8,
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=",
        "Markdown image with a query string, a known channel for leaking data to a remote host",
    ),
    _rule(
        "concealment",
        Severity.MEDIUM,
        0.5,
        r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|notify|alert|mention|show)\b.{0,20}\b(the )?(user|human|operator)\b",
        "Tells the agent to hide actions from the user",
    ),
    _rule(
        "tool_coercion",
        Severity.MEDIUM,
        0.55,
        r"\b(call|invoke|execute|run|use)\b.{0,30}\b(tool|function|command|shell|script)\b.{0,60}"
        r"\b(without|do not|don't|no need to)\b.{0,20}\b(ask|asking|confirm|confirmation|approval|permission)\b",
        "Tries to push a tool call past human approval",
    ),
    _rule(
        "credential_request",
        Severity.MEDIUM,
        0.5,
        r"\b(send|post|forward|email|upload|exfiltrate)\b.{0,50}\b(api[ _-]?keys?|passwords?|credentials?|tokens?|secrets?|ssh keys?)\b",
        "Asks for credentials to be sent somewhere",
    ),
)


def normalize(text: str) -> str:
    """NFKC-normalise and strip invisible characters so obfuscated payloads match the rules."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = _TAG_CHARS.sub("", text)
    return re.sub(r"[ \t]+", " ", text)


def _match_rules(text: str, prefix: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        match = rule.pattern.search(text)
        if match:
            findings.append(
                Finding(
                    detector="injection",
                    rule=f"{prefix}{rule.name}",
                    severity=rule.severity,
                    weight=rule.weight,
                    detail=rule.description,
                )
            )
    return findings


def _decode_base64_candidates(text: str) -> list[str]:
    decoded: list[str] = []
    for blob in _BASE64_BLOB.findall(text)[:10]:
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if candidate.isprintable() or "\n" in candidate:
            decoded.append(candidate)
    return decoded


def detect_injection(text: str) -> list[Finding]:
    """Return injection findings for `text` (empty list when nothing suspicious is found)."""
    findings: list[Finding] = []

    if _TAG_CHARS.search(text):
        findings.append(
            Finding(
                detector="injection",
                rule="unicode_tag_smuggling",
                severity=Severity.HIGH,
                weight=0.8,
                detail="Contains invisible Unicode tag characters that can hide instructions",
            )
        )
    invisible = len(_INVISIBLE.findall(text))
    if invisible >= 3:
        findings.append(
            Finding(
                detector="injection",
                rule="invisible_characters",
                severity=Severity.MEDIUM,
                weight=0.4,
                detail=f"Contains {invisible} zero-width or bidi control characters",
            )
        )

    clean = normalize(text)
    findings.extend(_match_rules(clean))

    for decoded in _decode_base64_candidates(clean):
        for inner in _match_rules(normalize(decoded), prefix="encoded_"):
            findings.append(inner.model_copy(update={"weight": min(1.0, inner.weight + 0.1)}))
    return findings
