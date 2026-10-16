# ATF control mapping and deployment responsibilities

Reference: [CSA, 2 February 2026](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents).
This matrix describes this implementation's controls. It is not a certification checklist.

| Area | Implemented | Required deployment work |
| --- | --- | --- |
| Identity | Agent/session UUIDs, owner attribution, explicit purpose and per-session capability manifest | Bind the identity to authenticated workload credentials; verify issuer/audience/expiry using an IdP; establish accountable ownership and credential rotation |
| Behavior | Structured action/result/denial events, budgets, model usage, rationale and evidence IDs | Forward audit to durable access-controlled storage; baseline usage; alert on policy denials and anomalous patterns; evaluate model accuracy |
| Data governance | Strict schemas, excluded credential files, redacted evidence, content hashes, output-to-evidence binding | Apply organization-specific PII/PHI DLP, retention and residency policy, repository authorization and provider data-processing controls |
| Segmentation | One authorized root/profile, no executable tools, bounded reads, provider host allowlist | Dedicated OS identity/container, read-only mounted target, filesystem/network sandbox, egress firewall and tenant isolation |
| Incident response | Kill-file polling, cancellation, deadlines, revoked sessions and failure events | External revocation, SOC alert routing, evidence preservation, credential rotation and tested recovery runbook |

The local owner field is attribution, not authentication. The local hash chain detects edits
only when checked against a trusted external anchor; a party that can rewrite the whole
file can recompute it. Audit storage is not WORM, signed or remotely anchored by this project.
Request/token limits are resource controls, not a hard dollar-spend cap: provider reporting
can arrive after a response. Apply provider account spend limits as well.

## Autonomy and promotion

This release exposes only observe-and-report capabilities (Intern). No setting can enable
target mutation or shell execution. Recommendations require human validation and execution.
Junior, Senior and Principal workflows are not implemented. Promotion is an organizational
decision requiring measured quality, security testing, incident history and governance
sign-off; an LLM cannot promote itself. Add authenticated, action-specific approvals and
new policy enforcement before adding any write-capable tool.

## Incident runbook

1. Create the configured kill file; stop the process if immediate OS-level termination is needed.
2. Revoke provider credentials if compromise is suspected. Cancellation cannot recall already sent data.
3. Preserve the private report and audit file in approved incident storage, with a trusted digest.
4. Review evidence access, policy denials and provider account usage; assess potential disclosure.
5. Correct policy or code, run regression tests, and have the responsible owner approve restart.

## Validation evidence

`tests/test_security.py` exercises secret minimization, file confinement, hostile links,
special files, budgets, kill switches, policy denials, report creation and audit integrity.
`tests/test_harness.py` exercises real Pydantic AI orchestration with an in-process model,
including malformed evidence IDs and cancellation. These are regression tests, not
proof of complete prompt-injection resistance or production identity assurance.
