"""The held-out check of an adversarial run: does what each round settled on still hold on Flows no agent ever saw?

Every round of `adversarial.py` judges and adapts on the same split, so a defense that works there may only fit those 50 Flows, and a note
that passes there may only fool the detector on them. This module takes a finished run and judges a second split, kept apart, under the
note and the instructions each round had in force. Nothing it measures goes back to the agents: it never opens their memories and runs
after the loop, so the reserved split cannot shape any decision (interface I7 of the Trabalho 1, "dados do conjunto final reservado").

In reading order:

- `HeldRound` and `rounds_to_check`: the rounds of a run that judged every Flow, with their note and their instructions.
- `instructions_of`: the text of one instruction version, checked against the sha256 the rows carry.
- `reserved_flows`: the held-out split without any Flow the run adapted on.

The judgement of the reserved split comes next; this part only reads what a finished run left and what the reserved split holds.
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path

from jev_ids.adversarial import DETECTOR_STOPPED, read_rounds
from jev_ids.dataset import Config, Flow, load_split


@dataclass(frozen=True)
class HeldRound:
    """One round of the run, as the held-out check reads it from `rounds.jsonl`.

    Attributes:
        round: the round, from 1.
        state_code: the compact code of the round (`N/B`, `S/R`, ...).
        note: the attacker's note in force, empty for none.
        instruction_label: the label of the instructions in force.
        instructions_sha256: the sha256 of their text.
        detection_rate: detected attacks over answered attacks on the split the run adapted on.
        false_alarm_rate: the false-alarm rate on that split.
        f1: the F1 on that split.
    """

    round: int
    state_code: str
    note: str
    instruction_label: str
    instructions_sha256: str
    detection_rate: float | None
    false_alarm_rate: float
    f1: float


def detection_rate(detected: int, total: int, errors: int) -> float | None:
    """Detected attacks over the answered ones; None when no attack was answered."""
    answered = total - errors
    return None if answered <= 0 else round(detected / answered, 4)


def rounds_to_check(run_dir: Path, wanted: Collection[int] | None = None) -> list[HeldRound]:
    """The rounds of the run that judged every Flow, or only those in `wanted`.

    A round the detector cut short (`detector_stopped`) is left out: its instructions and note were never measured on the whole split.

    Raises:
        ValueError: when the run recorded no round, or a round in `wanted` is not among those it can check.
    """
    held: list[HeldRound] = []
    for record in read_rounds(run_dir):
        if record.why_adapted == DETECTOR_STOPPED:
            continue
        rate = detection_rate(record.attacks_detected, record.total_attacks, record.attack_errors)
        held.append(
            HeldRound(
                record.round,
                record.state_code,
                record.note,
                record.instruction_label,
                record.instructions_sha256,
                rate,
                record.false_alarm_rate,
                record.f1,
            )
        )
    if not held:
        raise ValueError(f"{run_dir}: no round judged every Flow, so there is nothing to check")
    if wanted is None:
        return held
    missing = sorted(set(wanted) - {item.round for item in held})
    if missing:
        raise ValueError(f"{run_dir}: rounds {missing} are not among the rounds that judged every Flow")
    return [item for item in held if item.round in wanted]


def instructions_of(run_dir: Path, label: str, sha256: str) -> str:
    """The text of one instruction version, from `instructions/<label>.txt`, refused when its bytes no longer hash to `sha256`."""
    path = run_dir / "instructions" / f"{label}.txt"
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != sha256:
        raise ValueError(f"{path}: its sha256 differs from the one the rounds recorded; the file changed after the run")
    return payload.decode("utf-8")


def reserved_flows(config: Config, adapted_on: str, held_out: str) -> tuple[list[Flow], int]:
    """The held-out split without any Flow of the split the run adapted on, and how many were dropped.

    Raises:
        ValueError: when the two splits are the same, or nothing is left once the shared Flows are dropped.
    """
    if adapted_on == held_out:
        raise ValueError(f"the held-out split must differ from the split the run adapted on ({adapted_on!r})")
    splits = config["dir"] / "splits"
    seen = {flow.row_id for flow in load_split(splits / f"{adapted_on}.csv", config)}
    candidates = load_split(splits / f"{held_out}.csv", config)
    kept = [flow for flow in candidates if flow.row_id not in seen]
    if not kept:
        raise ValueError(f"every Flow of {held_out!r} is also in {adapted_on!r}")
    return kept, len(candidates) - len(kept)
