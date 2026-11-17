"""Going on with an adversarial run that stopped before its end: it picks up the round it stopped in and ends as if it never stopped.

Each test plays the canonical cycle twice, under two folders: once straight, once stopped, by a failure or by its process going down,
and resumed by new agents on the same memory folder, as a new process would. The resumed run must leave the same records, rows and
agent states as the straight one.
"""

import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from jev_ids.adversarial import ROUND_IN_PLAY, RoundRecord, failure_of, read_resumable, read_rounds
from jev_ids.dataset import Flow
from tests.adversarial_helpers import (
    ATTACKER_SCRIPT,
    DEFENDER_SCRIPT,
    STUDY_FLOWS,
    AgentFactory,
    Loop,
    MockDecisionDetector,
    agent_factory,
    make_spec,
    read_jsonl,
)

# What TokenLab answered while its model service was down, raised by a scripted model as the provider raised it.
OUTAGE = RuntimeError("503 The model service is temporarily unavailable. Please retry shortly.")


class Killed(BaseException):
    """The process going down: nothing in the loop catches it, as nothing catches a power cut."""


class DyingDetector(MockDecisionDetector):
    """The mock detector, whose process goes down at its `die_at`-th call, before answering it."""

    def __init__(self, die_at: int) -> None:
        super().__init__()
        self.die_at = die_at

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        if self.calls + 1 == self.die_at:
            raise Killed
        return super().predict(flow, examples)


def run_dir_of(agents: AgentFactory) -> Path:
    """The run folder of a factory's loops."""
    return agents.root / "run_adv"


def play(loop: Loop, agents: AgentFactory) -> list[RoundRecord]:
    """Run `loop` from round 1 into the factory's run folder."""
    return loop.orchestrator.run_loop(STUDY_FLOWS, [], make_spec(agents.root), out_dir=run_dir_of(agents))


def resume(loop: Loop, agents: AgentFactory) -> list[RoundRecord]:
    """Go on with the run in the factory's run folder."""
    return loop.orchestrator.resume_loop(STUDY_FLOWS, [], make_spec(agents.root), run_dir_of(agents))


def resumptions(run_dir: Path) -> list[tuple[Any, Any]]:
    """The round and the failure of each resumption `config.json` records."""
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    return [(entry["round"], entry["after"]) for entry in config["resumed"]]


@pytest.fixture
def straight(tmp_path: Path) -> Iterator[AgentFactory]:
    """Agents for the cycle played without a stop."""
    yield from agent_factory(tmp_path / "straight")


@pytest.fixture
def broken(tmp_path: Path) -> Iterator[AgentFactory]:
    """Agents for the same cycle stopped by a failure and resumed, under a folder of their own."""
    yield from agent_factory(tmp_path / "broken")


@dataclass
class Resumed:
    """The cycle played straight, and the same cycle stopped by the attacker's outage and resumed."""

    straight: Loop
    expected: list[RoundRecord]
    stopped: list[RoundRecord]
    session_before: str
    resumed: Loop
    history: list[RoundRecord]
    run_dir: Path


@pytest.fixture
def after_outage(straight: AgentFactory, broken: AgentFactory) -> Resumed:
    """The canonical cycle, and the same cycle whose attacker is down the first time its turn comes, resumed by a new process."""
    straight_loop = straight.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT)
    expected = play(straight_loop, straight)
    # The defender reinforces after round 1; after round 2 the attacker is given the turn and its model is down.
    down = broken.loop([OUTAGE], DEFENDER_SCRIPT[:1])
    stopped = play(down, broken)
    session_before = down.attacker.memory.session_id
    broken.restart()
    # The new process is given the attacker's decisions it never gave, and the defender's one it never reached.
    resumed = broken.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT[1:], reopen=True)
    return Resumed(straight_loop, expected, stopped, session_before, resumed, resume(resumed, broken), run_dir_of(broken))


def test_an_outage_stops_the_run_in_the_round_whose_turn_failed(after_outage: Resumed) -> None:
    assert [record.round for record in after_outage.stopped] == [1, 2]
    assert failure_of(after_outage.stopped) == "agent_unavailable:attacker"


def test_the_resumed_run_ends_as_if_it_never_stopped(after_outage: Resumed) -> None:
    assert after_outage.history == after_outage.expected
    assert read_rounds(after_outage.run_dir) == after_outage.expected


def test_the_stopped_round_is_read_back_and_never_judged_again(after_outage: Resumed) -> None:
    rows = read_jsonl(after_outage.run_dir / "predictions.jsonl")
    assert [row["round"] for row in rows] == [record.round for record in after_outage.expected for _ in STUDY_FLOWS]
    assert not (after_outage.run_dir / "interrupted.jsonl").exists()


def test_each_agent_goes_on_with_its_session_and_the_state_it_held(after_outage: Resumed) -> None:
    resumed, straight = after_outage.resumed, after_outage.straight
    assert resumed.attacker.memory.session_id == after_outage.session_before
    assert resumed.attacker.memory.state == straight.attacker.memory.state
    assert resumed.defender.memory.state == straight.defender.memory.state


def test_the_resumption_is_recorded_in_the_config(after_outage: Resumed) -> None:
    assert resumptions(after_outage.run_dir) == [(2, "agent_unavailable:attacker")]


def test_an_outage_that_outlasts_one_resumption_is_resumed_again(straight: AgentFactory, broken: AgentFactory) -> None:
    expected = play(straight.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT), straight)
    play(broken.loop([OUTAGE], DEFENDER_SCRIPT[:1]), broken)
    broken.restart()
    again = resume(broken.loop([OUTAGE], [], reopen=True), broken)
    assert ([record.round for record in again], failure_of(again)) == ([1, 2], "agent_unavailable:attacker")
    broken.restart()
    assert resume(broken.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT[1:], reopen=True), broken) == expected
    assert resumptions(run_dir_of(broken)) == [(2, "agent_unavailable:attacker"), (2, "agent_unavailable:attacker")]


def test_a_round_the_detector_cut_short_is_set_aside_and_judged_again(straight: AgentFactory, broken: AgentFactory) -> None:
    expected = play(straight.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT), straight)
    stopped = play(broken.loop([], [], MockDecisionDetector(failing=[flow.row_id for flow in STUDY_FLOWS])), broken)
    assert failure_of(stopped) == "detector_stopped"
    broken.restart()
    assert resume(broken.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT, reopen=True), broken) == expected
    run_dir = run_dir_of(broken)
    assert [row["error"] for row in read_jsonl(run_dir / "interrupted.jsonl")] == ["HTTP 503: unavailable"] * len(STUDY_FLOWS)
    assert len(read_jsonl(run_dir / "predictions.jsonl")) == len(STUDY_FLOWS) * len(expected)
    assert resumptions(run_dir) == [(1, "detector_stopped")]


@pytest.mark.parametrize("saved_start", [True, False])
def test_a_run_cut_off_while_the_detector_judged_judges_that_round_again(
    straight: AgentFactory, broken: AgentFactory, saved_start: bool
) -> None:
    expected = play(straight.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT), straight)
    # Rounds 1 and 2 make ten calls; the process goes down on the fourth call of round 3, after two benign rows and one attack row.
    with pytest.raises(Killed):
        play(broken.loop(ATTACKER_SCRIPT[:1], DEFENDER_SCRIPT[:1], DyingDetector(die_at=14)), broken)
    run_dir = run_dir_of(broken)
    if not saved_start:
        # A run started before the start of each round was saved goes on from the cut round's own attack row.
        (run_dir / ROUND_IN_PLAY).unlink()
    broken.restart()
    assert resume(broken.loop(ATTACKER_SCRIPT[1:], DEFENDER_SCRIPT[1:], reopen=True), broken) == expected
    assert [row["round"] for row in read_jsonl(run_dir / "interrupted.jsonl")] == [3, 3, 3]
    assert len(read_jsonl(run_dir / "predictions.jsonl")) == len(STUDY_FLOWS) * len(expected)
    assert resumptions(run_dir) == [(3, "cut_off")]


def test_a_run_cut_off_while_a_side_was_deciding_asks_that_side_again(
    straight: AgentFactory, broken: AgentFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = play(straight.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT), straight)
    loop = broken.loop([], DEFENDER_SCRIPT[:1])
    # Reading the method by name, as `monkeypatch` replaces it by name.
    adapt = getattr(loop.orchestrator, "_adapt")  # noqa: B009

    def adapt_until_round_two(turn: Any, feedback: Any, state: Any) -> Any:
        if state.round_index == 2:
            raise Killed
        return adapt(turn, feedback, state)

    monkeypatch.setattr(loop.orchestrator, "_adapt", adapt_until_round_two)
    with pytest.raises(Killed):
        play(loop, broken)
    broken.restart()
    assert resume(broken.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT[1:], reopen=True), broken) == expected
    run_dir = run_dir_of(broken)
    # Round 2 was judged in full and told to both sides, so nothing is set aside and no call is made twice.
    assert not (run_dir / "interrupted.jsonl").exists()
    assert len(read_jsonl(run_dir / "predictions.jsonl")) == len(STUDY_FLOWS) * len(expected)
    assert resumptions(run_dir) == [(2, "cut_off")]


def test_a_run_that_ended_in_order_is_not_resumed(straight: AgentFactory) -> None:
    play(straight.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT), straight)
    with pytest.raises(ValueError, match="ended in order"):
        read_resumable(run_dir_of(straight))
