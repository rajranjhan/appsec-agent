"""Bounded local source review; no imports, subprocesses, or target network requests."""

import hashlib
import os
from pathlib import Path

from appsec_agent.models import Candidate, Coverage, Evidence, Profile, Risk, ScanResult
from appsec_agent.policy import PolicyError, Session, read_beneath, redact
from appsec_agent.rules import MANUAL_REVIEW, RULES

EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".md", ".txt"}
SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "__pycache__", "reports"}
SECRET_NAMES = {
    "credentials",
    "id_rsa",
    "id_ed25519",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
}


def scan(session: Session, profile: Profile) -> ScanResult:
    session.authorize(profile)
    policy = session.policy
    root = policy.root.resolve(strict=True)
    if not root.is_dir():
        raise PolicyError("Scan root must be a directory")
    candidates: list[Candidate] = []
    files = total = entries = 0
    limitations = [
        "Heuristic candidates require contextual human validation; absence of matches is not proof of safety.",
        "Local source/configuration only: no live model, MCP handshake, runtime, CVE, or exploit testing.",
        "Hidden paths, dependencies, secret files, links, binary/unsupported files are excluded. Gitignore is not interpreted.",
        "Only bounded evidence windows are available to the LLM; cross-file dataflow is not resolved.",
    ]
    rules = [r for r in RULES if r.risk in policy.classes and profile in r.profiles]
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stopped = False
    try:
        for directory, dirs, names in os.walk(root, followlinks=False):
            session.check()
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS)
            entries += len(dirs) + len(names)
            if entries > policy.max_entries:
                limitations.append("Directory-entry budget reached; scan incomplete.")
                break
            for name in sorted(names):
                session.check()
                path = Path(directory) / name
                relative = path.relative_to(root)
                if (
                    name.startswith(".")
                    or name.lower() in SECRET_NAMES
                    or path.suffix.lower() not in EXTENSIONS
                ):
                    continue
                if files >= policy.max_files or total >= policy.max_total_bytes:
                    limitations.append("File/byte budget reached; scan incomplete.")
                    stopped = True
                    break
                try:
                    data = read_beneath(
                        root_fd,
                        relative,
                        min(policy.max_file_bytes, policy.max_total_bytes - total),
                    )
                    total += len(data)
                    if b"\x00" in data:
                        continue
                    content = data.decode("utf-8")
                except (OSError, UnicodeError, PolicyError):
                    limitations.append(
                        f"Skipped unreadable, linked, oversized, or non-UTF8 file: {redact(relative.as_posix())}"
                    )
                    continue
                files += 1
                lines = content.splitlines()
                for index, line in enumerate(lines):
                    for rule in rules:
                        if not rule.matches(line):
                            continue
                        start = max(0, index - 4)
                        excerpt = redact("\n".join(lines[start : index + 5]))[:5000]
                        evidence = Evidence(
                            path=redact(relative.as_posix()),
                            line=index + 1,
                            start_line=start + 1,
                            excerpt=excerpt,
                            sha256=hashlib.sha256(data).hexdigest(),
                        )
                        candidate_id = hashlib.sha256(
                            f"{relative}:{index + 1}:{rule.id}:{evidence.sha256}".encode()
                        ).hexdigest()[:20]
                        candidates.append(
                            Candidate(
                                id=candidate_id,
                                rule=rule.id,
                                risk=rule.risk,
                                title=rule.title,
                                evidence=evidence,
                                review_question=rule.question,
                                remediation=rule.fix,
                            )
                        )
                        if len(candidates) >= policy.max_candidates:
                            limitations.append("Candidate budget reached; scan incomplete.")
                            stopped = True
                            break
                    if stopped:
                        break
                if stopped:
                    break
            if stopped:
                break
    finally:
        os.close(root_fd)
    coverage = []
    for risk in Risk:
        count = sum(c.risk == risk for c in candidates)
        status = (
            "not_assessed"
            if risk not in policy.classes or not files
            else ("candidates_found" if count else "no_pattern_match")
        )
        coverage.append(
            Coverage(
                risk=risk,
                candidate_count=count,
                status=status,  # type: ignore[arg-type]
                manual_review=MANUAL_REVIEW[risk],
            )
        )
    result = ScanResult(
        profile=profile,
        files_read=files,
        bytes_read=total,
        candidates=candidates,
        coverage=coverage,
        limitations=list(dict.fromkeys(limitations))[:100],
    )
    session.audit.emit(
        "scan_completed", profile=profile, files=files, bytes=total, candidates=len(candidates)
    )
    return result


def scan_ai_system(session: Session) -> ScanResult:
    """Review AI application source, ingestion, retrieval, output, and model dependencies."""
    return scan(session, "system")


def scan_ai_agent(session: Session) -> ScanResult:
    """Review agent instructions, tool permissions, output sinks, and execution budgets."""
    return scan(session, "agent")


def scan_ai_mcp(session: Session) -> ScanResult:
    """Review local MCP server/client code and exported manifests without launching servers."""
    return scan(session, "mcp")
