import asyncio
import json

import pytest
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from appsec_agent.harness import run
from appsec_agent.policy import PolicyError


def fake_model(*, fabricated=False, wrong_tool=False):
    def respond(messages, info):
        returns = [
            p for message in messages for p in message.parts if isinstance(p, ToolReturnPart)
        ]
        if not returns:
            return ModelResponse(
                parts=[ToolCallPart("scan_ai_mcp" if wrong_tool else "scan_ai_system", {})]
            )
        snapshot = returns[-1].content
        if hasattr(snapshot, "model_dump"):
            snapshot = snapshot.model_dump(mode="json")
        if isinstance(snapshot, str):
            snapshot = json.loads(snapshot)
        output = {
            "threat_model": "Untrusted model output reaches an execution sink.",
            "assessments": [
                {
                    "candidate_id": "invented" if fabricated else candidate["id"],
                    "disposition": "needs_review",
                    "severity": "medium",
                    "confidence": "low",
                    "rationale": "Verify the source of output.",
                    "source": "output variable",
                    "sink": "eval",
                    "trust_boundary": "Model text to host execution",
                    "guards": "Not visible in supplied evidence",
                    "remediation": "Use typed dispatch",
                    "verification": "Pass an unsupported action and assert rejection",
                }
                for candidate in snapshot["candidates"]
            ],
            "looks_good": [],
            "limitations": ["Only a local excerpt was assessed."],
        }
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, output)])

    return FunctionModel(respond)


async def test_real_pydantic_tool_loop(session_factory):
    session = session_factory(allow_llm=True, profiles=frozenset({"system"}))
    (session.policy.root / "app.py").write_text("eval(output)")
    report = await run(session, "system", model=fake_model())
    assert report.review is not None
    assert report.review.assessments[0].candidate_id == report.scan.candidates[0].id
    assert report.scan.candidates[0].evidence.path == "app.py"


async def test_hallucinated_evidence_rejected(session_factory):
    session = session_factory(allow_llm=True, profiles=frozenset({"system"}))
    (session.policy.root / "app.py").write_text("eval(output)")
    with pytest.raises(UnexpectedModelBehavior):
        await run(session, "system", model=fake_model(fabricated=True))
    assert session.revoked


async def test_model_cannot_expand_capabilities(session_factory):
    session = session_factory(allow_llm=True, profiles=frozenset({"system"}))
    with pytest.raises(PolicyError):
        await run(session, "system", model=fake_model(wrong_tool=True))
    assert session.revoked


async def test_egress_needs_explicit_authorization(session_factory):
    session = session_factory()
    with pytest.raises(PolicyError, match="egress"):
        await run(session, "system", model=fake_model())


async def test_cancel_inflight_model(session_factory, tmp_path):
    kill = tmp_path / "STOP"
    session = session_factory(allow_llm=True, kill_file=kill)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def slow_model(messages, info):
        started.set()
        try:
            await asyncio.sleep(20)
        finally:
            cancelled.set()
        return ModelResponse(parts=[])

    task = asyncio.create_task(run(session, "system", model=FunctionModel(slow_model)))
    await asyncio.wait_for(started.wait(), 2)
    kill.touch()
    with pytest.raises(PolicyError, match="revoked"):
        await asyncio.wait_for(task, 2)
    assert cancelled.is_set()


async def test_offline_report(session_factory):
    report = await run(session_factory(), "system")
    assert report.review is None
    assert report.model is None
    assert report.autonomy == "intern"


async def test_model_request_budget(session_factory):
    session = session_factory(allow_llm=True, max_requests=1)
    with pytest.raises(UsageLimitExceeded):
        await run(session, "system", model=fake_model())
    assert session.revoked


async def test_model_cannot_skip_evidence_tool(session_factory):
    def premature(messages, info):
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {
                        "threat_model": "Unsupported assessment",
                        "assessments": [],
                        "looks_good": [],
                        "limitations": [],
                    },
                )
            ]
        )

    session = session_factory(allow_llm=True)
    with pytest.raises(UnexpectedModelBehavior):
        await run(session, "system", model=FunctionModel(premature))


async def test_audit_failure_stops_before_model(session_factory, monkeypatch):
    session = session_factory(allow_llm=True)

    def broken_audit(*args, **kwargs):
        raise OSError("Audit storage unavailable")

    monkeypatch.setattr(session.audit, "emit", broken_audit)
    with pytest.raises(OSError):
        await run(session, "system", model=fake_model())
    assert session.revoked
