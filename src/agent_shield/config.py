"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_POLICY = Path(__file__).with_name("default_policy.yaml")


@dataclass(frozen=True)
class Settings:
    policy_path: Path = DEFAULT_POLICY
    audit_path: Path | None = None
    block_threshold: float = 0.7
    rate_limit_capacity: float = 60.0
    rate_limit_per_second: float = 30.0
    api_key: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ
        audit = env.get("AUDIT_LOG_PATH")
        return cls(
            policy_path=Path(env.get("POLICY_PATH", str(DEFAULT_POLICY))),
            audit_path=Path(audit) if audit else None,
            block_threshold=float(env.get("BLOCK_THRESHOLD", "0.7")),
            rate_limit_capacity=float(env.get("RATE_LIMIT_CAPACITY", "60")),
            rate_limit_per_second=float(env.get("RATE_LIMIT_PER_SECOND", "30")),
            api_key=env.get("API_KEY") or None,
        )
