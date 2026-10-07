"""Least-privilege authorisation for agent tool calls.

A YAML policy declares which tools an agent may call and how each argument is constrained. The
default is deny: a tool that is not listed is refused. Checks are purely syntactic (no DNS or
filesystem access) so they are fast, deterministic and safe to run on untrusted input.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from .models import ToolDecision, ToolVerdict

_SHELL_META = re.compile(r"[;&|`$<>\n\r]|\$\(|\$\{")
_PRIVATE_HOST_SUFFIXES = (".internal", ".local", ".localhost", ".lan", ".corp")


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


class ToolPolicy:
    def __init__(self, config: dict[str, Any]) -> None:
        self.default = str(config.get("default", "deny")).lower()
        if self.default not in {"deny", "allow"}:
            raise PolicyError("'default' must be 'deny' or 'allow'")
        tools = config.get("tools") or {}
        if not isinstance(tools, dict):
            raise PolicyError("'tools' must be a mapping")
        self.tools: dict[str, dict[str, Any]] = tools

    @classmethod
    def from_file(cls, path: str | Path) -> ToolPolicy:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise PolicyError("policy file must contain a mapping")
        return cls(data)

    def evaluate(self, tool: str, arguments: dict[str, Any]) -> ToolDecision:
        spec = self.tools.get(tool)
        if spec is None:
            if self.default == "allow":
                return ToolDecision(verdict=ToolVerdict.ALLOW, reasons=["no rule; default allow"])
            return ToolDecision(verdict=ToolVerdict.DENY, reasons=[f"tool '{tool}' is not in the allowlist"])
        if not spec.get("allow", True):
            return ToolDecision(verdict=ToolVerdict.DENY, reasons=[f"tool '{tool}' is disabled by policy"])

        reasons: list[str] = []
        arg_rules: dict[str, dict[str, Any]] = spec.get("args") or {}

        unexpected = sorted(set(arguments) - set(arg_rules))
        if arg_rules and unexpected and spec.get("strict", True):
            reasons.append(f"unexpected argument(s): {', '.join(unexpected)}")

        for name, rules in arg_rules.items():
            if name not in arguments:
                if rules.get("required", False):
                    reasons.append(f"missing required argument '{name}'")
                continue
            reasons.extend(_check_argument(name, arguments[name], rules))

        if reasons:
            return ToolDecision(verdict=ToolVerdict.DENY, reasons=reasons)

        threshold = spec.get("require_approval_above")
        if threshold:
            field, limit = threshold["arg"], threshold["value"]
            value = arguments.get(field)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value > limit:
                return ToolDecision(
                    verdict=ToolVerdict.NEEDS_APPROVAL,
                    reasons=[f"'{field}'={value} exceeds auto-approval limit {limit}"],
                )
        if spec.get("require_approval", False):
            return ToolDecision(verdict=ToolVerdict.NEEDS_APPROVAL, reasons=["tool requires human approval"])
        return ToolDecision(verdict=ToolVerdict.ALLOW, reasons=["all constraints satisfied"])


def _check_argument(name: str, value: Any, rules: dict[str, Any]) -> list[str]:
    problems: list[str] = []

    expected = rules.get("type")
    type_map = {"string": str, "number": (int, float), "integer": int, "boolean": bool}
    if expected:
        python_type = type_map.get(expected)
        is_bool_as_number = isinstance(value, bool) and expected in {"number", "integer"}
        if python_type is None or not isinstance(value, python_type) or is_bool_as_number:
            return [f"'{name}' must be of type {expected}"]

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "max" in rules and value > rules["max"]:
            problems.append(f"'{name}'={value} exceeds maximum {rules['max']}")
        if "min" in rules and value < rules["min"]:
            problems.append(f"'{name}'={value} is below minimum {rules['min']}")

    if "enum" in rules and value not in rules["enum"]:
        problems.append(f"'{name}' must be one of {rules['enum']}")

    if isinstance(value, str):
        problems.extend(_check_string(name, value, rules))
    return problems


def _check_string(name: str, value: str, rules: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if "max_length" in rules and len(value) > rules["max_length"]:
        problems.append(f"'{name}' longer than {rules['max_length']} characters")
    if "\x00" in value:
        problems.append(f"'{name}' contains a null byte")
    if rules.get("deny_shell_metacharacters") and _SHELL_META.search(value):
        problems.append(f"'{name}' contains shell metacharacters")
    for pattern in rules.get("deny_patterns", []):
        if re.search(pattern, value):
            problems.append(f"'{name}' matches denied pattern {pattern!r}")
    if "allow_pattern" in rules and not re.fullmatch(rules["allow_pattern"], value):
        problems.append(f"'{name}' does not match the required format")
    if "path_prefixes" in rules or rules.get("deny_traversal"):
        problems.extend(_check_path(name, value, rules))
    if "schemes" in rules or "allowed_hosts" in rules or rules.get("block_private_ips"):
        problems.extend(_check_url(name, value, rules))
    return problems


def _check_path(name: str, value: str, rules: dict[str, Any]) -> list[str]:
    decoded = unquote(unquote(value)).replace("\\", "/")
    if rules.get("deny_traversal", True) and ".." in decoded.split("/"):
        return [f"'{name}' contains path traversal"]
    prefixes = rules.get("path_prefixes")
    if prefixes:
        normalized = posixpath.normpath(decoded)
        if not any(normalized == p.rstrip("/") or normalized.startswith(p.rstrip("/") + "/") for p in prefixes):
            return [f"'{name}' is outside the allowed directories {prefixes}"]
    return []


def _is_private_host(host: str) -> bool:
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(_PRIVATE_HOST_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        # Catch decimal/hex/octal integer encodings of an IPv4 address, e.g. http://2130706433/
        if re.fullmatch(r"(0x[0-9a-f]+|\d+)", lowered):
            try:
                address = ipaddress.ip_address(int(lowered, 0))
            except ValueError:
                return True
        else:
            return False
    mapped = getattr(address, "ipv4_mapped", None)
    address = mapped or address
    return (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_reserved or address.is_multicast or address.is_unspecified
    )


def _check_url(name: str, value: str, rules: dict[str, Any]) -> list[str]:
    try:
        parsed = urlparse(value)
        host = parsed.hostname
    except ValueError:
        return [f"'{name}' is not a valid URL"]
    schemes = rules.get("schemes")
    if schemes and parsed.scheme.lower() not in schemes:
        return [f"'{name}' scheme '{parsed.scheme}' is not allowed (allowed: {schemes})"]
    if not host:
        return [f"'{name}' has no host"]
    if parsed.username or parsed.password:
        return [f"'{name}' must not embed credentials"]
    if rules.get("block_private_ips") and _is_private_host(host):
        return [f"'{name}' targets a private or internal address ({host})"]
    allowed = rules.get("allowed_hosts")
    if allowed and not any(fnmatch.fnmatch(host.lower(), pattern.lower()) for pattern in allowed):
        return [f"'{name}' host '{host}' is not in the allowed hosts {allowed}"]
    return []
