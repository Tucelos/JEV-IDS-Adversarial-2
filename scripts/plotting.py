"""What the plotting scripts share: matplotlib, loaded for the run only, and the colours of the side that adapts.

matplotlib is not a project dependency (the benchmark never plots): a script that draws runs under `uv run --with matplotlib`.
So matplotlib is loaded here by name and typed as `Any`, after the Agg backend is chosen, and the type checker never needs it
installed.
"""

import importlib
from typing import Any

matplotlib: Any = importlib.import_module("matplotlib")
# Choosing the file-only backend before pyplot is loaded, so the scripts draw without a display.
matplotlib.use("Agg")
plt: Any = importlib.import_module("matplotlib.pyplot")
patches: Any = importlib.import_module("matplotlib.patches")

# Who the orchestrator chose to adapt after a round, in the colours the loop diagrams use: green defender, red attacker, grey end.
WHO_COLORS: dict[str, str] = {"defender": "#2ca02c", "attacker": "#d62728", "": "#9e9e9e"}
