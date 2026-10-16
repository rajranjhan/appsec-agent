"""Original candidate heuristics. A match is a review lead, never proof of a flaw."""

import re
from dataclasses import dataclass

from appsec_agent.models import Profile, Risk


@dataclass(frozen=True)
class Rule:
    id: str
    risk: Risk
    title: str
    pattern: str
    question: str
    fix: str
    profiles: frozenset[Profile] = frozenset({"system", "agent", "mcp"})

    def matches(self, line: str) -> bool:
        return re.search(self.pattern, line, re.I) is not None


RULES = (
    Rule(
        "prompt-composition",
        Risk.LLM01,
        "Dynamic privileged prompt composition",
        r"(?:system_prompt|system_message|instructions)\s*=\s*(?:f[\x22\x27]|.*\+)",
        "Can attacker-controlled data become privileged instructions or change tool authorization? Ordinary user prompts alone are not a vulnerability.",
        "Separate untrusted content from instructions and enforce tool authorization outside the model.",
    ),
    Rule(
        "credential-literal",
        Risk.LLM02,
        "Credential-like literal",
        r"""(?:api_key|secret|password|access_token)\s*["']?\s*[:=]\s*["'][^"']{6,}["']""",
        "Is the literal a real credential reachable through model context, logs, or tool output, rather than an example?",
        "Use a secret manager and redact credentials before model calls and logging; rotate exposed credentials.",
    ),
    Rule(
        "remote-model-code",
        Risk.LLM03,
        "Remote model code enabled",
        r"trust_remote_code\s*[:=]\s*(?:True|true)",
        "Can an untrusted or mutable model artifact execute code under this process identity?",
        "Disable remote code; pin and verify reviewed artifacts and isolate model loading.",
    ),
    Rule(
        "unsafe-model-load",
        Risk.LLM04,
        "Executable model deserialization",
        r"(?:pickle\.loads?|joblib\.load|torch\.load)\s*\(",
        "Can an attacker replace the artifact and is safe deserialization or integrity verification enforced?",
        "Prefer non-executable model formats and verify artifact provenance before ingestion.",
    ),
    Rule(
        "output-execution",
        Risk.LLM05,
        "Potential model output execution sink",
        r"\b(?:eval|exec)\s*\(|innerHTML\s*=|dangerouslySetInnerHTML",
        "Trace model output to this sink; identify any validation or context-specific escaping.",
        "Use a typed allowlisted interpreter or context-specific output encoding; never execute model text.",
    ),
    Rule(
        "agent-shell",
        Risk.LLM06,
        "Shell-capable tool or unrestricted permission",
        r"shell\s*[:=]\s*(?:True|true)|(?:allowed_tools|permissions)\s*[:=]\s*\[?\s*[\x22\x27]\*|(?:subprocess\.(?:run|Popen)|os\.system)\s*\(",
        "Can model or tool input choose commands without per-action authorization and human approval?",
        "Replace shell tools with scoped functions, validate arguments, and gate consequential actions.",
    ),
    Rule(
        "prompt-disclosure",
        Risk.LLM07,
        "System prompt returned or logged",
        r"(?:return|print\s*\(|logger\.\w+\s*\().*\b(?:system_prompt|system_message)\b",
        "Does the prompt contain sensitive policy or data and can an unauthorized actor observe this output?",
        "Remove secrets from prompts and keep authorization in code; suppress privileged prompt logs.",
    ),
    Rule(
        "vector-query",
        Risk.LLM08,
        "Vector retrieval boundary requires review",
        r"\b(?:similarity_search|similarity_search_with_score|query_points)\s*\(",
        "Does retrieval enforce tenant and document ACLs before returning context, including metadata filters?",
        "Apply identity-bound tenant filters and document authorization before retrieval results reach the model.",
    ),
    Rule(
        "unchecked-answer",
        Risk.LLM09,
        "Model answer delivered directly",
        r"return\s+(?:response|completion|result)\.(?:text|content|output|choices)",
        "Is this a high-impact decision requiring grounded evidence, uncertainty disclosure, or human review?",
        "Validate cited evidence and output schemas, disclose uncertainty, and require review for high-impact decisions.",
    ),
    Rule(
        "unbounded-loop",
        Risk.LLM10,
        "Potential unbounded agent loop",
        r"while\s+True\s*:|(?:max_iterations|max_tokens|max_retries|request_limit)\s*[:=]\s*None",
        "Does an external deadline, token budget, or iteration bound reliably terminate this model/tool loop?",
        "Enforce independent request, token, tool-call and wall-clock limits with cancellation.",
    ),
    Rule(
        "mcp-unpinned-command",
        Risk.LLM03,
        "MCP package launched without review",
        r"[\x22\x27](?:npx|uvx)[\x22\x27]|@latest",
        "Does the MCP launcher fetch mutable third-party code with access to agent credentials?",
        "Pin and verify MCP packages; run servers in isolated identities with minimal secrets.",
        frozenset({"system", "mcp"}),
    ),
    Rule(
        "mcp-transport",
        Risk.LLM02,
        "Plaintext MCP endpoint",
        r"http://[^\s\x22\x27]*",
        "For HTTP endpoints, is transport local and isolated, or can credentials and tool data cross an untrusted network? HTTPS alone does not establish authorization.",
        "Use authenticated TLS for remote MCP, validate token audience, and restrict server egress.",
        frozenset({"mcp"}),
    ),
    Rule(
        "mcp-description-injection",
        Risk.LLM01,
        "Instruction-like text in tool metadata",
        r"ignore (?:all |previous |prior )*instructions|(?:reveal|send|exfiltrate).{0,40}(?:secret|token|password)",
        "Can tool metadata or results override agent instructions or induce unauthorized data transfer?",
        "Treat MCP descriptions and results as untrusted data; pin manifests and authorize every capability outside the model.",
        frozenset({"system", "agent", "mcp"}),
    ),
)

MANUAL_REVIEW = {risk: next(rule.question for rule in RULES if rule.risk == risk) for risk in Risk}
