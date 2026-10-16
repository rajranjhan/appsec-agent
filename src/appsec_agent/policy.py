"""Operator-controlled capabilities. No policy values originate in model output."""

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import Field

from appsec_agent.models import Profile, Risk, Schema


class PolicyError(RuntimeError):
    """Authorization or resource limits prevent continued execution."""


class Policy(Schema):
    owner: str = Field(min_length=1, max_length=100)
    agent_id: str = Field(default_factory=lambda: str(uuid4()))
    root: Path
    profiles: frozenset[Profile] = frozenset({"system", "agent", "mcp"})
    classes: frozenset[Risk] = frozenset(Risk)
    allow_llm: bool = False
    max_files: int = Field(default=300, ge=1, le=10000)
    max_file_bytes: int = Field(default=100_000, ge=1, le=1_000_000)
    max_total_bytes: int = Field(default=2_000_000, ge=1, le=20_000_000)
    max_entries: int = Field(default=10000, ge=1, le=100000)
    max_candidates: int = Field(default=40, ge=1, le=100)
    max_tool_calls: int = Field(default=4, ge=1, le=20)
    max_requests: int = Field(default=6, ge=1, le=20)
    max_tokens: int = Field(default=60000, ge=1000, le=200000)
    timeout_seconds: float = Field(default=120, gt=0, le=600)
    kill_file: Path | None = None


def redact(text: str) -> str:
    """Best-effort minimization, not a comprehensive DLP classifier."""
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        text,
        flags=re.S,
    )
    text = re.sub(
        r"""(?im)((?:api[_-]?key|secret|password|token|authorization)[\w-]*["']?\s*[:=]\s*)([^\n,}]+)""",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b", "[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED JWT]", text)
    text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[REDACTED EMAIL]", text)
    return re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED SSN]", text)


def private_write(path: Path, data: str) -> None:
    """Create only: never follow symlinks or overwrite an existing operator file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(data)


class Audit:
    """One private JSONL file per session; hash chain requires external anchoring."""

    def __init__(self, path: Path, run_id: str, policy: Policy):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._file = os.fdopen(fd, "w", encoding="utf-8")
        self.run_id, self.policy = run_id, policy
        self.previous = "0" * 64

    def emit(self, action: str, **metadata: Any) -> None:
        event = {
            "time": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "agent_id": self.policy.agent_id,
            "owner": self.policy.owner,
            "action": action,
            "previous": self.previous,
            **metadata,
        }
        body = json.dumps(event, sort_keys=True, separators=(",", ":"))
        self.previous = hashlib.sha256(body.encode()).hexdigest()
        self._file.write(json.dumps({**event, "hash": self.previous}) + "\n")
        self._file.flush()  # Fail closed if audit storage fails.

    def close(self) -> None:
        self._file.close()


@dataclass
class Session:
    policy: Policy
    audit: Audit
    started: float = field(default_factory=time.monotonic)
    calls: int = 0
    revoked: bool = False

    def check(self) -> None:
        if self.revoked or (self.policy.kill_file and self.policy.kill_file.exists()):
            raise PolicyError("Session revoked by kill switch")
        if time.monotonic() - self.started >= self.policy.timeout_seconds:
            raise PolicyError("Session deadline exceeded")

    def authorize(self, profile: Profile) -> None:
        self.check()
        if profile not in self.policy.profiles:
            self.audit.emit("tool_denied", profile=profile)
            self.revoked = True
            raise PolicyError("Tool is outside the authorized capability manifest")
        if self.calls >= self.policy.max_tool_calls:
            self.revoked = True
            raise PolicyError("Tool-call budget exceeded")
        self.calls += 1
        self.audit.emit("tool_authorized", profile=profile, call=self.calls)


def read_beneath(root_fd: int, relative: Path, limit: int) -> bytes:
    """Descriptor-relative traversal closes parent-directory symlink races (POSIX)."""
    if relative.is_absolute() or any(p in {"..", "."} for p in relative.parts):
        raise PolicyError("Invalid source path")
    fd = os.dup(root_fd)
    try:
        for part in relative.parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        source_fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source_fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PolicyError("Only regular, non-hardlinked source files may be read")
            if info.st_size > limit:
                raise PolicyError("File exceeds read budget")
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise PolicyError("File grew beyond read budget")
            return data
    finally:
        os.close(fd)
