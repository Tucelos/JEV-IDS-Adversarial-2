"""The Agno runtime of a participant: the model of a provider, the question before round 1, failures and the SQLite memory."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx2
import pytest
from agno.models.anthropic import Claude
from agno.models.openai.like import OpenAILike
from agno.run.base import RunStatus

from jev_ids.agent_runtime import (
    HYDROGEN_KEY_VARS,
    AgentBundle,
    AgentMemory,
    AgentUnavailableError,
    check_agent_model,
    make_agent_model,
)
from jev_ids.agents import AttackerDecision, RetiredNote
from tests.adversarial_helpers import ScriptedAgnoModel, attacker_says


def open_memory(memory_dir: Path, model: ScriptedAgnoModel) -> AgentMemory:
    """A participant's memory on `memory_dir`, as the attacker opens it."""
    return AgentMemory(AgentBundle("attacker", model, "Answer in JSON.", AttackerDecision, {}, memory_dir))


class StubAgent:
    """An Agno agent reduced to `run`: it answers with a fixed content, or raises as code outside the model call would."""

    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    def run(self, _prompt: str, **_options: Any) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return SimpleNamespace(status=RunStatus.completed, content=self.outcome)


def test_claude_is_built_without_sampling_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    model = make_agent_model("claude")
    request_params: dict[str, Any] = model.get_request_params()
    assert isinstance(model, Claude)
    assert model.id == "claude-sonnet-5-5"
    # The Messages API version the SDK sends rejects `temperature`, so it must not reach the request at all.
    assert model.temperature is None
    assert {"temperature", "top_p", "top_k"}.isdisjoint(request_params)
    assert make_agent_model("anthropic", "claude-other").id == "claude-other"


def test_hydrogen_takes_its_key_from_the_environment_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in HYDROGEN_KEY_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-g-key")
    assert make_agent_model("hydrogen").api_key == "test-g-key"
    monkeypatch.setenv("HYDROGEN_API_KEY", "test-h-key")
    model = make_agent_model("hydrogen")
    assert isinstance(model, OpenAILike)
    assert (model.id, model.api_key) == ("gemini-4-hydrogen", "test-h-key")


def test_hydrogen_without_a_key_names_the_variables_instead_of_sending_a_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in HYDROGEN_KEY_VARS:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="HYDROGEN_API_KEY, GEMINI_API_KEY, GOOGLE_API_KEY"):
        make_agent_model("hydrogen")
    with pytest.raises(ValueError, match="unsupported agent provider"):
        make_agent_model("unknown_vendor")


def test_check_agent_model_asks_one_question_and_reports_a_failing_model() -> None:
    healthy = ScriptedAgnoModel("scripted", ["OK", "not a decision", "unused"])
    check_agent_model(healthy, "attacker")
    # Asked with the schema, only a failed call counts: an answer that is no decision still passes.
    check_agent_model(healthy, "attacker", AttackerDecision)
    assert healthy.responses == ["unused"]
    broken = ScriptedAgnoModel("scripted", [RuntimeError("401 invalid x-api-key")])
    with pytest.raises(AgentUnavailableError, match="defender: .*401 invalid x-api-key") as failure:
        check_agent_model(broken, "defender")
    assert failure.value.role == "defender"


def test_check_agent_model_sends_claude_the_request_a_decision_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    # Running the real Anthropic client over a mock transport, so what is read is the request body it would send.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    bodies: list[dict[str, Any]] = []

    def answer(request: httpx2.Request) -> httpx2.Response:
        bodies.append(json.loads(request.content))
        message = {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-5",
            "content": [{"type": "text", "text": attacker_says("keep")}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        return httpx2.Response(200, json=message, request=request)

    model = make_agent_model("claude")
    model.http_client = httpx2.Client(transport=httpx2.MockTransport(answer))
    check_agent_model(model, "attacker", AttackerDecision)
    (body,) = bodies
    assert body["model"] == "claude-sonnet-5-5"
    assert body["output_config"]["format"]["schema"]["title"] == "AttackerDecision"
    assert {"temperature", "top_p", "top_k"}.isdisjoint(body)


def test_ask_turns_a_provider_error_and_an_answer_outside_the_schema_into_agent_unavailable(tmp_path: Path) -> None:
    model = ScriptedAgnoModel("scripted", [attacker_says("remove"), RuntimeError("503 overloaded"), "no JSON here"])
    memory = open_memory(tmp_path, model)
    assert memory.ask("first", AttackerDecision).action == "remove"
    with pytest.raises(AgentUnavailableError, match="503 overloaded"):
        memory.ask("second", AttackerDecision)
    with pytest.raises(AgentUnavailableError, match="outside the AttackerDecision schema") as failure:
        memory.ask("third", AttackerDecision)
    assert failure.value.role == "attacker"
    memory.close()


def test_memory_is_shown_to_the_model_but_no_memory_tool_is_offered(tmp_path: Path) -> None:
    model = ScriptedAgnoModel("scripted", [attacker_says("keep")])
    memory = open_memory(tmp_path, model)
    memory.remember("Round 1: two of three records alerted")
    memory.log("tested_note:'x'", "what was tried", outcome="2/3 alerted")
    memory.ask("first", AttackerDecision)
    # Agno would hand the tools of an AGENTIC store to the model, and a tool call is a model call the loop never asked for.
    assert model.tools_offered == [0]
    assert "Round 1: two of three records alerted" in model.seen_prompts[0]
    assert "tested_note:'x'" in model.seen_prompts[0]
    assert "update_user_memory" not in model.seen_prompts[0]
    memory.close()


def test_ask_reads_a_dict_and_reports_whatever_escapes_agno(tmp_path: Path) -> None:
    memory = open_memory(tmp_path, ScriptedAgnoModel("scripted", []))
    memory.agent = StubAgent({"action": "keep", "note": "", "rationale": "as a dict"})
    assert memory.ask("first", AttackerDecision).rationale == "as a dict"
    memory.agent = StubAgent(ConnectionError("socket closed"))
    with pytest.raises(AgentUnavailableError, match="attacker: ConnectionError: socket closed"):
        memory.ask("second", AttackerDecision)
    memory.agent = StubAgent(42)
    with pytest.raises(AgentUnavailableError, match="outside the AttackerDecision schema: 42"):
        memory.ask("third", AttackerDecision)
    memory.close()


def test_ledger_records_outlive_the_process_only_through_the_memory_folder(tmp_path: Path) -> None:
    first = open_memory(tmp_path / "kept", ScriptedAgnoModel("scripted", []))
    first.save_record("retired_note", RetiredNote(wording="ticket-1", note="Ticket-1"))
    first.close()
    again = open_memory(tmp_path / "kept", ScriptedAgnoModel("scripted", []))
    elsewhere = open_memory(tmp_path / "other", ScriptedAgnoModel("scripted", []))
    assert again.load_records("retired_note", RetiredNote) == [RetiredNote(wording="ticket-1", note="Ticket-1")]
    assert elsewhere.load_records("retired_note", RetiredNote) == []
    assert again.load_records("instruction_cost", RetiredNote) == []
    assert (tmp_path / "kept" / "attacker.db").is_file()
    again.close()
    elsewhere.close()
