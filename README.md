# AppSec Agent

A Pydantic AI agent for reviewing AI systems, agents, and MCP integrations against the
[OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/).
It combines local candidate discovery with optional API-key-authenticated LLM review.
The initial implementation reviews **local source and configuration**, not live endpoints.

## Quick start

Requires Python 3.11–3.14 and a POSIX host (Linux/macOS).

```sh
uv sync --locked
uv run appsec-agent classes
uv run appsec-agent scan examples/target --profile agent
uv run appsec-agent scan examples/target --profile mcp --classes LLM01 LLM03 LLM06
```

Offline scans need no API key and make no model calls. They return `needs_review`
candidates, file/line evidence, content hashes, class coverage and scope limitations.
Exit codes: 0 = completed assessment (not a security pass), 2 = failure, 130 = interrupted.
Reports are JSON; treat model text as untrusted when rendering it into another application.

## LLM review

Set `APPSEC_PROVIDER` to `openai` or `anthropic`, `APPSEC_MODEL` to a tool-capable model
available to your account, and `APPSEC_API_KEY` through your shell or secret manager.
For example, in Bash:

```sh
export APPSEC_PROVIDER=openai
export APPSEC_MODEL='your-model-id'
read -rsp 'Provider API key: ' APPSEC_API_KEY; export APPSEC_API_KEY; echo
uv run appsec-agent scan /path/to/authorized/source --profile system --llm --output report.json
unset APPSEC_API_KEY
```

`--llm` authorizes sending **redacted evidence excerpts and relative file names** to the
provider. Redaction is best effort, not comprehensive DLP: use a sanitized checkout for
sensitive repositories. Target source is untrusted data, never harness instructions.
No repository `.env` is loaded. Keys are not CLI arguments, tool parameters, or audit fields.

An OpenAI-compatible gateway can be configured with `APPSEC_BASE_URL` and an explicit
JSON `APPSEC_ALLOWED_HOSTS='["llm.example.com"]'`. HTTPS/443 is required; redirects and
environment proxies are disabled. The operator controls endpoint configuration; use an
egress firewall/proxy for network-level isolation and DNS controls.

## Tools and workflow

| Tool | Intended scope |
| --- | --- |
| `scan_ai_system` | Application prompts, data ingestion, model loading, RAG and output sinks |
| `scan_ai_agent` | Agent instructions, tool authority, execution sinks and loop limits |
| `scan_ai_mcp` | MCP client/server source and exported JSON/configuration, packages, transport and tool metadata |

Each tool is available as a Python function in `appsec_agent.scanner` and as a registered
Pydantic AI tool. The CLI grants one profile per session. Tool arguments cannot select a
different root, provider, policy, or risk taxonomy. The model receives the same immutable
scan snapshot used in the report. A disallowed tool call revokes the session.

The workflow is: identify candidate patterns → construct a threat model → inspect sources,
sinks, guards and trust boundaries → assess every candidate → recommend fixes and tests.
The model must call the selected tool and assess every real evidence ID exactly once.
Uncertain results remain `needs_review`; even `supported` is an LLM judgment requiring
human validation, not an executed exploit. Dismissals stay in the report for review.

All ten classes have heuristics and manual review questions. Heuristics are deliberately
limited: ordinary LLM input, vector queries and output delivery are review leads, not
vulnerabilities by themselves. Profiles share common rules and MCP adds specific rules.
See [coverage](docs/coverage.md) for detection limits.

## Harness controls

- Read-only target access; no shell, target execution, live MCP connection or remediation tools.
- Descriptor-relative reads reject symlinks, hardlinks, special files and parent traversal.
- Allowlisted text extensions; hidden/credential paths and dependency directories excluded.
- File, byte, candidate, request, token, tool-call and wall-clock budgets.
- Typed inputs/outputs; candidate provenance preserved independently of model judgments.
- Private per-run JSONL audit with session/agent/owner attribution and a hash chain.
- Create `.appsec/STOP` (or the configured `--kill-file`) to revoke a running session.
  The model call is cancelled when the watcher detects it; remote processing already
  accepted by a provider may continue. Remove the file only after incident review.
- Fail closed on policy/audit errors; provider bodies and credentials are not printed.
- Reports are created with mode 0600 and never overwrite an existing file.

The trusted operator controls the target, output/audit directories, environment and policy.
Run under a dedicated least-privileged OS identity against a stable read-only checkout.
Do not expose this CLI directly as an unauthenticated service.

## Agentic Trust Framework

The harness is an **Intern / observe-and-report implementation**, designed to support
the five areas in the [CSA ATF article](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents).
It does not claim ATF certification or full conformance. Local identity attribution is not
cryptographic workload authentication. [The control matrix](docs/atf-controls.md) documents
implemented safeguards, deployment gaps, evidence and requirements before promotion.

## Development

```sh
uv sync --locked
uv run pytest
uv run ruff check src tests
uv run mypy src
```

Tests use deterministic Pydantic AI models; no API credentials or paid calls are required.
The lockfile records the tested dependency versions. CI checks style, types and tests.

## Design sources

- [dymchenkko/appsec-skill](https://github.com/dymchenkko/appsec-skill): threat model first,
  secure defaults and concrete remediation. Adapted conceptually for AI workloads.
- [zavanryder/vuln-finder](https://github.com/zavanryder/vuln-finder): class-driven candidate
  discovery, contextual source-to-sink review and evidence-based reporting. Its Python
  entry point is a placeholder; this repository implements the runtime independently.
- [Pydantic AI](https://ai.pydantic.dev/agents/): typed agent, dependency injection, tools,
  output validation and usage limits.

No upstream source or skill text is vendored. Original rules and prompts implement these
workflow ideas. Prompt injection remains a first-class review category for AI trust-boundary
breaches; we do not inherit a blanket exclusion for prompt injection from the upstream skill.
