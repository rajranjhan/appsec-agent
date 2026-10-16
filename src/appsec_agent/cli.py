"""Local operator interface. API keys are accepted only through environment settings."""

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path
from uuid import uuid4

from appsec_agent.config import Settings
from appsec_agent.harness import run
from appsec_agent.models import RISK_NAMES, Risk
from appsec_agent.policy import Audit, Policy, Session, private_write


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only AI security source assessment")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("classes", help="List OWASP LLM 2025 risk classes")
    command = sub.add_parser("scan", help="Scan local AI source/configuration")
    command.add_argument("root", type=Path)
    command.add_argument("--profile", choices=["system", "agent", "mcp"], default="system")
    command.add_argument(
        "--classes", nargs="+", choices=[r.name for r in Risk], default=[r.name for r in Risk]
    )
    command.add_argument("--owner", default=getpass.getuser())
    command.add_argument(
        "--llm", action="store_true", help="Authorize sending redacted evidence to configured LLM"
    )
    command.add_argument("--output", type=Path, help="New JSON report file (will not overwrite)")
    command.add_argument("--audit-dir", type=Path, default=Path(".appsec/audit"))
    command.add_argument("--kill-file", type=Path, default=Path(".appsec/STOP"))
    command.add_argument("--max-files", type=int, default=300)
    command.add_argument("--max-candidates", type=int, default=40)
    command.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.command == "classes":
        print(json.dumps({r.value: name for r, name in RISK_NAMES.items()}, indent=2))
        return 0
    audit = None
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Root must be a directory")
        policy = Policy(
            root=root,
            owner=args.owner,
            profiles=frozenset({args.profile}),
            classes=frozenset(Risk[name] for name in args.classes),
            allow_llm=args.llm,
            kill_file=args.kill_file.absolute(),
            max_files=args.max_files,
            max_candidates=args.max_candidates,
            timeout_seconds=args.timeout,
        )
        settings = Settings() if args.llm else None  # type: ignore[call-arg]
        args.audit_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        run_id = str(uuid4())
        audit = Audit(args.audit_dir / f"{run_id}.jsonl", run_id, policy)
        audit.emit(
            "run_started",
            profile=args.profile,
            classes=sorted(policy.classes),
            allow_llm=policy.allow_llm,
            autonomy="intern",
        )
        report = asyncio.run(run(Session(policy, audit), args.profile, settings=settings))
        rendered = report.model_dump_json(indent=2)
        if args.output:
            private_write(args.output, rendered + "\n")
        else:
            print(rendered)
        return 0
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        # Provider exceptions and validation errors can include credentials or request bodies.
        print(
            f"Scan failed ({type(exc).__name__}). Check scope, settings, limits, and audit events; no report was completed.",
            file=sys.stderr,
        )
        return 2
    finally:
        if audit:
            audit.close()


if __name__ == "__main__":
    sys.exit(main())
