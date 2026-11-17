"""Keep the calls to TokenLab under its ceiling: at most 20 a minute on the key the `qwen` agent and the Clef detector share.

The detectors' retries (`retry_request`) recover from a 429 after the gateway has refused a call; the spacer here keeps the refusal
from happening. Every request to a spaced host waits until a fixed interval has passed since the previous request to that host
started, and every client of the host shares one spacer, so the attacker's calls and the detector's calls add up under one ceiling.
The interval is set for `QWEN_CALLS_PER_MINUTE` calls a minute, 18 unless the variable says otherwise, which leaves a margin under
the 20 for the jitter between the moment a request leaves and the moment the gateway counts it.

In reading order:

- `CallSpacer`: the interval of one host and the moment its next request may start.
- `calls_per_minute`: the rate to space for, from the environment, refused above the ceiling.
- `spacer_for`: the one spacer of a host, created on first use.
- `spacing_hooks`: the httpx event hooks under which every request of a client, retries included, waits for its host's spacer.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

CEILING_PER_MINUTE = 20.0
DEFAULT_CALLS_PER_MINUTE = 18.0
# Sharing the QWEN_ prefix of the key and the endpoint the spaced clients read.
CALLS_PER_MINUTE_VAR = "QWEN_CALLS_PER_MINUTE"
SECONDS_PER_MINUTE = 60.0


class CallSpacer:
    """Spaces the starts of requests so that no more than `calls_per_minute` start in any minute.

    Attributes:
        interval: the seconds between the starts of two consecutive requests.
    """

    def __init__(
        self,
        calls_per_minute: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Set the interval for `calls_per_minute`, on a clock and a sleep that a test can replace."""
        if calls_per_minute <= 0:
            raise ValueError(f"calls per minute must be positive, got {calls_per_minute}")
        self.interval = SECONDS_PER_MINUTE / calls_per_minute
        self._clock = clock
        self._sleep = sleep
        self._next_start = float("-inf")
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Block until the next request may start, and book the slot that follows it.

        Returns:
            The seconds waited: 0 when the interval had already passed.
        """
        with self._lock:
            now = self._clock()
            start = max(now, self._next_start)
            self._next_start = start + self.interval
        delay = start - now
        if delay > 0:
            self._sleep(delay)
        return delay


_SPACERS: dict[str, CallSpacer] = {}
_SPACERS_LOCK = threading.Lock()


def calls_per_minute() -> float:
    """The rate to space for: `QWEN_CALLS_PER_MINUTE`, or 18 when it is unset.

    Raises:
        ValueError: when the variable is not a number above 0 and at most 20, the most the gateway admits.
    """
    raw = os.environ.get(CALLS_PER_MINUTE_VAR)
    if not raw:
        return DEFAULT_CALLS_PER_MINUTE
    try:
        rate = float(raw)
    except ValueError as exc:
        raise ValueError(f"{CALLS_PER_MINUTE_VAR} must be a number, got {raw!r}") from exc
    if not 0 < rate <= CEILING_PER_MINUTE:
        raise ValueError(f"{CALLS_PER_MINUTE_VAR} must be above 0 and at most {CEILING_PER_MINUTE:g}, got {raw}")
    return rate


def spacer_for(base_url: str) -> CallSpacer:
    """The one spacer of the host of `base_url`, created on first use, so every client of that host shares it."""
    host = urlsplit(base_url).netloc.lower()
    with _SPACERS_LOCK:
        spacer = _SPACERS.get(host)
        if spacer is None:
            spacer = CallSpacer(calls_per_minute())
            _SPACERS[host] = spacer
        return spacer


def spacing_hooks(base_url: str) -> dict[str, list[Callable[..., Any]]]:
    """The httpx event hooks under which every request of a client, a retry included, first waits for the spacer of its host.

    Typed as httpx types its `EventHook`, so the mapping is accepted by `httpx.Client(event_hooks=...)` as it is.
    """
    spacer = spacer_for(base_url)

    def wait_turn(_request: httpx.Request) -> None:
        spacer.wait()

    return {"request": [wait_turn]}
