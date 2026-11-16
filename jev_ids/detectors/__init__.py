"""Detectors: Jev, Gemini Decision, the LLM baselines, Random Forest, Isolation Forest, and KNN.

Each detector is a class with `name`, `model`, `prompt_hash` and `predict(flow, examples) -> dict` returning what it measured for that
one Flow (`p_attack`, `category_pred`, `latency_ms`, ...) or an `error`. Decision detectors also expose `instructions` and
`set_instructions(...)` behind the `DecisionDetector` protocol so the adversarial orchestrator can swap defenders' instructions
without coupling to a specific backend.
"""

import json
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol, runtime_checkable

from jev_ids.dataset import Flow, record_text

# Shared retry policy for HTTP decision APIs (Jev / Gemini Decisions).
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 60
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 529})


@runtime_checkable
class DecisionDetector(Protocol):
    """Common interface for IDS detectors that evaluate flows under configurable instructions."""

    name: str
    model: str
    prompt_hash: str | None

    @property
    def instructions(self) -> str:
        """Current defense instructions applied to each judged Flow."""
        ...

    def set_instructions(self, instructions: str) -> None:
        """Update the detector instructions for subsequent `predict` calls."""
        ...

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """Predict attack probability and category for a single Flow."""
        ...


def template_instructions(template: str) -> str:
    """Return `state.instructions` from a JSON decision prompt template."""
    body: dict[str, Any] = json.loads(template)
    return str(body["state"]["instructions"])


def with_template_instructions(template: str, new_instructions: str) -> str:
    """Return a copy of a JSON decision template with `state.instructions` updated."""
    body: dict[str, Any] = json.loads(template)
    body["state"]["instructions"] = new_instructions
    return json.dumps(body)


def build_decision_body(template: str, flow: Flow, examples: Sequence[Flow], record: str = "compact") -> dict[str, Any]:
    """Fill a decision template with the Flow under test, optional Examples, and Category criteria."""
    body: dict[str, Any] = json.loads(template)
    body["state"]["flows"] = {"under_test": record_text(flow, record)}
    if examples:
        body["state"]["examples"] = [
            {
                "record": record_text(example, record),
                "category": example.category,
            }
            for example in examples
        ]
    body["questions"]["category"]["criteria"] = body["state"]["categories"]
    return body


def retry_request(
    call: Callable[[], dict[str, Any]],
    max_attempts: int = MAX_ATTEMPTS,
    backoff_seconds: float = BACKOFF_SECONDS,
) -> dict[str, Any]:
    """Execute `call` up to `max_attempts` times with exponential backoff on retryable errors."""
    result = call()
    retries = 0
    while result.get("retryable") and retries < max_attempts - 1:
        time.sleep(backoff_seconds * 2**retries)
        result = call()
        retries += 1
    result.pop("retryable", None)
    return {
        **result,
        "retries": retries,
    }
