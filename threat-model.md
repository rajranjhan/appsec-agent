# Harness threat model

The operator is trusted to choose an authorized, stable repository snapshot and approved
model provider. Source files, tool descriptions and model responses are attacker-controlled.
The initial deployment is a local single-operator CLI, not a multi-tenant network service.

Assets: provider credentials, repository contents, assessment integrity, host filesystem,
audit records and provider budget. Boundaries: operator → policy; repository → scanner;
redacted snapshot → provider; model output → validated report; report → human decisions.

| Threat | Architectural control | Residual risk |
| --- | --- | --- |
| Source text tells the reviewer to execute code or read secrets | No execution tools, no model-controlled paths, fixed immutable evidence snapshot | Model can still be misled in its judgments; humans review assessments |
| Symlink, hardlink or FIFO tricks cause unintended reads | Descriptor-relative O_NOFOLLOW, regular-file/link checks, byte bounds | Trusted operator supplies root; use stable read-only mount against concurrent filesystem mutation |
| Credentials enter provider context | Skip secret paths; redact entire window before truncation | Unknown formats, PII and proprietary code can remain; sanitized input and DLP required |
| Model invents file evidence or dismisses a flaw | Bind all assessments to real IDs; require every ID exactly once | Rationale may be wrong; no semantic proof or dynamic exploit verification |
| Endless model/tool activity | Usage limits, policy counters, deadline watcher, cancellation | One response can exceed reported token budget; remote requests may outlive cancellation |
| Malicious provider endpoint/redirect steals key | Operator-only HTTPS allowlist; redirects and env proxies disabled | DNS/network isolation and provider trust remain deployment responsibilities |
| Log/report clobbering or forged audit | Exclusive creation, mode 0600, hash-linked per-session audit | Parent directories must be operator-controlled; external audit anchoring required |

Never run target code, resolve target dependencies, fetch target URLs, or launch an MCP
server merely to inspect it. Do not load policy or credentials from the scanned repository.
Tests target these trust boundaries and must run whenever the harness controls change.
