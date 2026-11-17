"""Draw the long adversarial runs from their `rounds.jsonl`: how attack and defense change over the rounds of one run each.

Run from the repository root. matplotlib is not a project dependency, so bring it in for the run only:

    uv run --with matplotlib python -m scripts.plot_long_run results/<gemini decision run> results/<clef run>

For every run given, it reads `config.json` and `rounds.jsonl` and writes, in `results/comparison/`:

- `laco_longo.csv`: one row per run and round, with the detection rate taken over the attacks the detector answered.
- `laco_longo_<detector>.png`: the run read round by round: detection, its moving mean and false alarm, with the side the
  orchestrator chose to adapt after each round underneath (green defender, red attacker, grey end).
- `laco_longo_melhora.png`: the mean detection, false alarm and F1 of the first and the last rounds of each run, side by side.

It prints, per run, how many rounds were judged, how the loop ended, how many new wordings the attacker spent and how many
instruction versions the defender put in force. Each run is one non-deterministic trajectory, not an average.
"""

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.plotting import WHO_COLORS, patches, plt

OUT_DIR = Path("results/comparison")
LABELS = {"gemini_decision": "Gemini Decision", "systemone": "Clef"}
WHO_NAMES = {"defender": "defensor adapta", "attacker": "atacante adapta", "": "fim ou estável"}
# Smoothing the detection line over this many rounds, so the trend shows through the noise of a single run.
MOVING_WINDOW = 5
# Comparing the mean of the first and the last this many rounds of a run.
PHASE_ROUNDS = 10
METRICS = (("detection_rate", "Detecção"), ("false_alarm_rate", "Falso alarme"), ("f1", "F1"))
CSV_FIELDS: tuple[str, ...] = (
    "detector",
    "run",
    "round",
    "state_code",
    "instruction_label",
    "attacks_detected",
    "attacks_passed",
    "attack_errors",
    "detection_rate",
    "false_alarms",
    "false_alarm_rate",
    "f1",
    "attempts_left",
    "who_adapts",
    "why_adapted",
)


@dataclass(frozen=True)
class Run:
    """One adversarial run: its detector, its folder, the attacker's budget and one row per judged round."""

    detector: str
    label: str
    folder: str
    max_attempts: int
    rows: list[dict[str, Any]]


def detection_rate(row: dict[str, Any]) -> float:
    """The share of the answered attacks that alerted; 0 when the detector answered none."""
    answered = row["attacks_detected"] + row["attacks_passed"]
    return row["attacks_detected"] / answered if answered else 0.0


def load_run(run_dir: Path) -> Run:
    """Read a run's detector and budget from `config.json` and its rounds from `rounds.jsonl`, with each round's detection rate."""
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    lines = (run_dir / "rounds.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines if line.strip()]
    for row in rows:
        row["detection_rate"] = detection_rate(row)
    detector: str = config["detector"]
    return Run(detector, LABELS.get(detector, detector), run_dir.name, config["max_attempts"], rows)


def moving_mean(values: list[float], window: int) -> list[float]:
    """The mean of each value and of the ones before it, up to `window` values in all."""
    means: list[float] = []
    for index in range(len(values)):
        span = values[max(0, index - window + 1) : index + 1]
        means.append(sum(span) / len(span))
    return means


def write_csv(runs: list[Run], path: Path) -> None:
    """One row per run and round, in the columns the figures and the README read."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for run in runs:
            for row in run.rows:
                rates = {column: round(float(row[column]), 4) for column, _ in METRICS}
                writer.writerow({**row, **rates, "detector": run.label, "run": run.folder, "who_adapts": row["who_adapts"] or ""})


def draw_strip(axis: Any, rows: list[dict[str, Any]]) -> None:
    """A coloured cell per round for the side that adapted after it, named by a legend, since a cell per round cannot hold a word."""
    for row in rows:
        colour = WHO_COLORS.get(row["who_adapts"] or "", WHO_COLORS[""])
        axis.add_patch(patches.Rectangle((row["round"] - 0.5, 0.0), 1.0, 1.0, color=colour, linewidth=0))
    axis.set_ylim(0.0, 1.0)
    axis.set_yticks([])
    axis.set_ylabel("quem\nadapta", rotation=0, ha="right", va="center", fontsize=8)
    handles = [patches.Patch(color=WHO_COLORS[who], label=name) for who, name in WHO_NAMES.items()]
    axis.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -1.4), ncol=len(handles), fontsize=8, frameon=False)


def plot_trajectory(run: Run, path: Path) -> None:
    """Detection, its moving mean and false alarm over the rounds of `run`, with the side that adapted underneath."""
    rounds = [row["round"] for row in run.rows]
    detection = [row["detection_rate"] for row in run.rows]
    figure, (top, strip) = plt.subplots(2, 1, figsize=(12, 6.4), height_ratios=[6, 0.7], sharex=True)
    top.plot(rounds, detection, color="#0072B2", alpha=0.35, linewidth=1.2, marker="o", markersize=3, label="Detecção na rodada")
    smoothed = moving_mean(detection, MOVING_WINDOW)
    top.plot(rounds, smoothed, color="#0072B2", linewidth=2.6, label=f"Detecção, média de {MOVING_WINDOW} rodadas")
    top.plot(rounds, [row["false_alarm_rate"] for row in run.rows], color="#555555", linestyle="--", linewidth=1.6, label="Falso alarme")
    top.set_xlim(0.5, max(rounds) + 0.5)
    top.set_ylim(-0.05, 1.05)
    top.set_ylabel("proporção")
    top.grid(visible=True, alpha=0.3)
    top.legend(loc="lower right", fontsize=9)
    top.set_title(f"O laço adversarial em {len(rounds)} rodadas — detector {run.label}", fontsize=12)
    draw_strip(strip, run.rows)
    strip.set_xticks([1, *range(5, max(rounds) + 1, 5)])
    strip.set_xlabel("rodada")
    figure.tight_layout()
    figure.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def phase_size(run: Run) -> int:
    """How many rounds each phase holds: PHASE_ROUNDS, fewer when the run is too short for two phases that never overlap."""
    return max(1, min(PHASE_ROUNDS, len(run.rows) // 2))


def phase_mean(rows: list[dict[str, Any]], column: str) -> float:
    """The mean of `column` over `rows`."""
    return sum(float(row[column]) for row in rows) / len(rows)


def draw_phase_bars(axis: Any, run: Run) -> None:
    """Two bars per metric, the first and the last rounds of `run`, each labelled with its value."""
    size = phase_size(run)
    first, last = run.rows[:size], run.rows[-size:]
    positions = list(range(len(METRICS)))
    width = 0.38
    early_values = [phase_mean(first, column) for column, _ in METRICS]
    late_values = [phase_mean(last, column) for column, _ in METRICS]
    early = axis.bar([p - width / 2 for p in positions], early_values, width, color="#9ecae1", label=f"rodadas 1 a {size}")
    late = axis.bar([p + width / 2 for p in positions], late_values, width, color="#08519c", label=f"últimas {size} rodadas")
    axis.bar_label(early, fmt="%.2f", fontsize=8)
    axis.bar_label(late, fmt="%.2f", fontsize=8)
    axis.set_xticks(positions)
    axis.set_xticklabels([title for _, title in METRICS])
    axis.set_ylim(0, 1.12)
    axis.set_title(run.label, fontsize=11)
    axis.grid(visible=True, axis="y", alpha=0.3)
    axis.legend(fontsize=8, loc="upper right")


def plot_improvement(runs: list[Run], path: Path) -> None:
    """Per run, each metric's mean over the first and the last rounds, as two bars side by side."""
    figure, axes = plt.subplots(1, len(runs), figsize=(6 * len(runs), 4.6), squeeze=False)
    for axis, run in zip(axes[0], runs, strict=True):
        draw_phase_bars(axis, run)
    axes[0][0].set_ylabel("média na fase")
    figure.suptitle("Começo e fim de cada execução: detecção e F1 devem subir, falso alarme cair", fontsize=12)
    figure.tight_layout()
    figure.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def describe(run: Run) -> str:
    """One line on how the run went: rounds judged, how it ended, attempts spent, instruction versions and unanswered records."""
    last = run.rows[-1]
    versions = len({row["instruction_label"] for row in run.rows})
    unanswered = sum(row["attack_errors"] + row["benign_errors"] for row in run.rows)
    spent = run.max_attempts - last["attempts_left"]
    return (
        f"{run.label}: {len(run.rows)} rounds, ended by {last['why_adapted']}, {spent} of {run.max_attempts} new wordings spent, "
        f"{versions} instruction versions, {unanswered} unanswered records"
    )


def parse_args() -> argparse.Namespace:
    """The command line: the run folders, one per detector, and where to write."""
    parser = argparse.ArgumentParser(description="draw the long adversarial runs")
    parser.add_argument("run_dirs", nargs="+", type=Path, help="results/adv_* folders, one per detector")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR, help="where the CSV and the figures are written")
    return parser.parse_args()


def main() -> None:
    """Read every run, then write the CSV, one trajectory per run and the first-against-last figure."""
    args = parse_args()
    runs = [load_run(run_dir) for run_dir in args.run_dirs]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(runs, args.out_dir / "laco_longo.csv")
    for run in runs:
        plot_trajectory(run, args.out_dir / f"laco_longo_{run.detector}.png")
        print(describe(run))
    plot_improvement(runs, args.out_dir / "laco_longo_melhora.png")


if __name__ == "__main__":
    main()
