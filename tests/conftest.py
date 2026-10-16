from uuid import uuid4

import pytest
from pydantic_ai import models

from appsec_agent.policy import Audit, Policy, Session


@pytest.fixture(autouse=True)
def no_model_network(monkeypatch):
    monkeypatch.setattr(models, "ALLOW_MODEL_REQUESTS", False)


@pytest.fixture
def session_factory(tmp_path):
    audits = []

    def make(**overrides):
        root = tmp_path / "target"
        root.mkdir(exist_ok=True)
        policy = Policy(**{"root": root, "owner": "test-operator", **overrides})
        run_id = str(uuid4())
        audit = Audit(tmp_path / f"{run_id}.jsonl", run_id, policy)
        audits.append(audit)
        return Session(policy, audit)

    yield make
    for audit in audits:
        audit.close()
