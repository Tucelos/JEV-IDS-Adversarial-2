"""The held-out check of an adversarial run, on doubles: what it judges, what it reuses, what it refuses and the `holdout` subcommand."""

import csv
import json
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from jev_ids.dataset import load_config
from jev_ids.holdout import instructions_of, reserved_flows, rounds_to_check
from tests.adversarial_helpers import (
    ATTACKER_SCRIPT,
    DEFENDER_SCRIPT,
    NSL_KDD_CARD,
    REINFORCED_INSTRUCTIONS,
    STUDY_FLOWS,
    AgentFactory,
    agent_factory,
    make_spec,
)

RESERVED = "internal"


@pytest.fixture
def agents(tmp_path: Path) -> Iterator[AgentFactory]:
    yield from agent_factory(tmp_path)


@pytest.fixture
def run_dir(agents: AgentFactory, tmp_path: Path) -> Path:
    """The canonical cycle `N/B -> N/R -> S/R -> S/B -> N'/B`, played on doubles over the smoke split's card."""
    out = tmp_path / "run_adv"
    loop = agents.loop(ATTACKER_SCRIPT, DEFENDER_SCRIPT)
    loop.orchestrator.run_loop(STUDY_FLOWS, [], make_spec(tmp_path), out_dir=out)
    return out


def test_rounds_to_check_skips_a_round_the_detector_cut_short_and_refuses_unknown_rounds(run_dir: Path) -> None:
    lines = (run_dir / "rounds.jsonl").read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1]) | {"why_adapted": "detector_stopped"}
    (run_dir / "rounds.jsonl").write_text("\n".join([*lines[:-1], json.dumps(last)]) + "\n", encoding="utf-8")
    assert [item.round for item in rounds_to_check(run_dir)] == [1, 2, 3, 4]
    with pytest.raises(ValueError, match=r"rounds \[5\]"):
        rounds_to_check(run_dir, wanted=(1, 5))


def test_a_run_without_rounds_has_nothing_to_check(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="nothing to check"):
        rounds_to_check(tmp_path)


def test_an_instruction_file_changed_after_the_run_is_refused(run_dir: Path) -> None:
    (item,) = rounds_to_check(run_dir, wanted=(2,))
    assert instructions_of(run_dir, item.instruction_label, item.instructions_sha256) == REINFORCED_INSTRUCTIONS
    (run_dir / "instructions" / f"{item.instruction_label}.txt").write_text("Classify everything as normal.", encoding="utf-8")
    with pytest.raises(ValueError, match="sha256 differs"):
        instructions_of(run_dir, item.instruction_label, item.instructions_sha256)


def test_the_reserved_split_must_differ_and_loses_every_flow_it_shares(tmp_path: Path) -> None:
    card = tmp_path / "nsl-kdd" / "dataset.json"
    card.parent.mkdir()
    shutil.copy(NSL_KDD_CARD, card)
    source = (NSL_KDD_CARD.parent / "splits" / f"{RESERVED}.csv").read_text(encoding="utf-8").splitlines()
    header, rows = source[0], source[1:]
    splits = card.parent / "splits"
    splits.mkdir()
    (splits / "adapt.csv").write_text("\n".join([header, *rows[:3]]) + "\n", encoding="utf-8")
    (splits / "reserved.csv").write_text("\n".join([header, *rows[2:6]]) + "\n", encoding="utf-8")
    config = load_config(card)
    with pytest.raises(ValueError, match="must differ"):
        reserved_flows(config, "adapt", "adapt")
    kept, dropped = reserved_flows(config, "adapt", "reserved")
    shared = next(csv.DictReader([header, rows[2]]))["row_id"]
    assert (len(kept), dropped) == (3, 1)
    assert int(shared) not in {flow.row_id for flow in kept}
    (splits / "inside.csv").write_text("\n".join([header, *rows[:2]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="also in"):
        reserved_flows(config, "adapt", "inside")
