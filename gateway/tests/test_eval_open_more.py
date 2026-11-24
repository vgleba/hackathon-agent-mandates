"""make eval_open, in-process, for questions 6, 8, 9, 12, 13, 15 and 16."""

from pathlib import Path

import pytest

from gateway import eval_open, eval_open_more
from mcp_server.api import routes_mcp


@pytest.fixture
def post(world, tmp_path, monkeypatch):
    monkeypatch.setattr(routes_mcp, "WRITES_PATH", tmp_path / "writes" / "corrections.jsonl")

    def send(path, body):
        r = world.client.post(path, json=body)
        return r.status_code, r.json()

    return send


def test_open_evals_pass(world, post):
    results = eval_open_more.run_more(world.state, post)
    assert {line.split()[0] for _, line in results} == {f"Q{q}" for q in eval_open_more.MORE_QUESTIONS}
    assert [line for ok, line in results if not ok] == []


def test_every_open_question_has_an_eval():
    pages = Path(__file__).resolve().parents[2] / "questions"
    asked = {int(p.name[:2]) for p in pages.glob("[0-9][0-9]-*.md")}
    assert {q for q in asked if q >= 6} == eval_open.OPEN_QUESTIONS.keys() | eval_open_more.MORE_QUESTIONS.keys()
