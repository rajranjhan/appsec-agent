"""Strict, versioned input and report contracts."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Risk(StrEnum):
    LLM01 = "LLM01:2025"
    LLM02 = "LLM02:2025"
    LLM03 = "LLM03:2025"
    LLM04 = "LLM04:2025"
    LLM05 = "LLM05:2025"
    LLM06 = "LLM06:2025"
    LLM07 = "LLM07:2025"
    LLM08 = "LLM08:2025"
    LLM09 = "LLM09:2025"
    LLM10 = "LLM10:2025"


RISK_NAMES = dict(
    zip(
        Risk,
        (
            "Prompt Injection",
            "Sensitive Information Disclosure",
            "Supply Chain",
            "Data and Model Poisoning",
            "Improper Output Handling",
            "Excessive Agency",
            "System Prompt Leakage",
            "Vector and Embedding Weaknesses",
            "Misinformation",
            "Unbounded Consumption",
        ),
        strict=True,
    )
)

Profile = Literal["system", "agent", "mcp"]


class Evidence(Schema):
    path: str
    line: int = Field(ge=1)
    start_line: int = Field(ge=1)
    excerpt: str = Field(max_length=5000)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Candidate(Schema):
    id: str
    rule: str
    risk: Risk
    title: str
    evidence: Evidence
    review_question: str
    remediation: str
    status: Literal["needs_review"] = "needs_review"


class Coverage(Schema):
    risk: Risk
    candidate_count: int
    status: Literal["candidates_found", "no_pattern_match", "not_assessed"]
    manual_review: str


class ScanResult(Schema):
    profile: Profile
    files_read: int
    bytes_read: int
    candidates: list[Candidate]
    coverage: list[Coverage]
    limitations: list[str]


class Assessment(Schema):
    candidate_id: str
    disposition: Literal["supported", "needs_review", "dismissed"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    rationale: str = Field(min_length=1, max_length=3000)
    source: str = Field(min_length=1, max_length=1000)
    sink: str = Field(min_length=1, max_length=1000)
    trust_boundary: str = Field(min_length=1, max_length=1000)
    guards: str = Field(min_length=1, max_length=1000)
    remediation: str = Field(min_length=1, max_length=3000)
    verification: str = Field(min_length=1, max_length=2000)


class Review(Schema):
    threat_model: str = Field(min_length=1, max_length=5000)
    assessments: list[Assessment] = Field(max_length=100)
    looks_good: list[str] = Field(max_length=20)
    limitations: list[str] = Field(max_length=20)


class Report(Schema):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    agent_id: str
    owner: str
    autonomy: Literal["intern"] = "intern"
    scan: ScanResult
    review: Review | None = None
    model: str | None = None
    assurance: str = "Static assessment; no exploit execution or compliance certification."
