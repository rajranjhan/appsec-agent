# Detection coverage

Taxonomy: [OWASP LLM Top 10, 2025 edition](https://genai.owasp.org/llm-top-10/).
Class IDs are versioned to prevent confusion with older lists and the separate Agentic Top 10.

| ID | Candidate signals | Evidence still required |
| --- | --- | --- |
| LLM01 | Dynamic privileged prompt composition, instruction-like MCP metadata | Attacker-controlled input and an actual authority/trust boundary breach |
| LLM02 | Credential-like literals, MCP URLs | Real sensitive value, disclosure path, authorization and transport context |
| LLM03 | Remote model code, mutable MCP launchers | Artifact provenance, pinning, verification and executable reachability |
| LLM04 | Pickle/joblib/torch loading | Untrusted artifact control and missing effective integrity/safe-load defenses |
| LLM05 | eval/exec and HTML sinks | Model output reaching the sink without appropriate validation/encoding |
| LLM06 | Shell-capable calls, wildcard permissions | Model influence over actions, runtime authority and approval checks |
| LLM07 | Returning/logging system prompts | Sensitive prompt contents and an unauthorized observer |
| LLM08 | Vector search calls | Tenant/document authorization and ingestion provenance |
| LLM09 | Direct model answer return | Decision impact, grounding and validation requirements |
| LLM10 | Infinite loops or explicitly unset limits | Effective runtime bounds, cancellation, provider and infrastructure limits |

The rules are line-based first-pass heuristics, not an AST/dataflow analyzer. They miss
multiline constructs, aliases, framework abstractions and unsupported languages. They can
match comments, examples and safe code; source context and humans decide whether the lead
is real. `no_pattern_match` never means a class passed. A scan with budget/skip limitations
is partial even if other files were scanned successfully. Every selected class retains a
manual review question. Unselected classes are `not_assessed`.

Supported input extensions: Python, JS/TS/JSX/TSX, JSON, YAML, TOML, Markdown and text.
These are text inspection formats, not a claim of full semantic support. Hidden directories
(including common editor MCP configuration locations) are excluded. Export only the
intended MCP configuration into a sanitized scan directory when reviewing such settings.
MCP manifests and endpoints are not fetched or executed. No claim is made to cover every
MCP authorization, OAuth, session-hijacking, tool-poisoning or protocol vulnerability.

The LLM sees up to four lines before and after each hit, capped at 5,000 characters after
redaction. Candidate count defaults to 40; the first 300 readable files and at most 2 MB
are examined by default, with 100 KB per file. Coverage is deliberately explicit about
these limits. Split large repositories into authorized scopes for deeper review.
