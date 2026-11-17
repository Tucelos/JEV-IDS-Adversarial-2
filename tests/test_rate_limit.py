"""The spacer that keeps TokenLab's calls under its ceiling: the interval, the rate from the environment, one spacer per host."""

import httpx
import pytest

from jev_ids import rate_limit
from jev_ids.rate_limit import CallSpacer, calls_per_minute, spacer_for, spacing_hooks
from tests.helpers import TOKENLAB, FakeClock, fake_tokenlab_spacer


def test_the_first_call_goes_at_once_and_the_next_waits_out_the_interval() -> None:
    clock = FakeClock()
    spacer = CallSpacer(20, clock=clock.time, sleep=clock.sleep)
    assert spacer.interval == 3.0
    assert spacer.wait() == 0
    assert spacer.wait() == 3.0
    clock.now = 10.0
    # The interval has passed since the last booked start, so nothing is waited.
    assert spacer.wait() == 0
    assert clock.slept == [3.0]


def test_no_minute_holds_more_calls_than_the_rate() -> None:
    clock = FakeClock()
    spacer = CallSpacer(20, clock=clock.time, sleep=clock.sleep)
    starts: list[float] = []
    for _ in range(100):
        spacer.wait()
        starts.append(clock.now)
    # Counting the starts of every minute that opens on a start: the busiest of them all.
    busiest = max(sum(1 for other in starts if start <= other < start + 60) for start in starts)
    assert busiest == 20


def test_the_rate_comes_from_the_environment_and_never_passes_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(rate_limit.CALLS_PER_MINUTE_VAR, raising=False)
    assert calls_per_minute() == 18.0
    monkeypatch.setenv(rate_limit.CALLS_PER_MINUTE_VAR, "12")
    assert calls_per_minute() == 12.0
    for refused in ("21", "0", "-3", "many"):
        monkeypatch.setenv(rate_limit.CALLS_PER_MINUTE_VAR, refused)
        with pytest.raises(ValueError, match=rate_limit.CALLS_PER_MINUTE_VAR):
            calls_per_minute()
    with pytest.raises(ValueError, match="positive"):
        CallSpacer(0)


def test_every_client_of_a_host_shares_its_spacer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rate_limit, "_SPACERS", {})
    monkeypatch.delenv(rate_limit.CALLS_PER_MINUTE_VAR, raising=False)
    agent_side = spacer_for(TOKENLAB)
    assert spacer_for("https://API.tokenlab.amd.com/v1/systemone") is agent_side
    assert spacer_for("https://generativelanguage.googleapis.com/v1beta/openai/") is not agent_side
    assert agent_side.interval == pytest.approx(60 / 18)


def test_every_request_of_a_spaced_client_waits_its_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = fake_tokenlab_spacer(monkeypatch)
    statuses = iter([429, 200, 200])

    def gateway(request: httpx.Request) -> httpx.Response:
        return httpx.Response(next(statuses), json={}, request=request)

    # A refused request is spaced like any other, so a retry that follows it waits its turn too.
    with httpx.Client(transport=httpx.MockTransport(gateway), event_hooks=spacing_hooks(TOKENLAB)) as client:
        codes = [client.post(f"{TOKENLAB}/systemone", json={}).status_code for _ in range(3)]
    assert codes == [429, 200, 200]
    assert clock.slept == [3.0, 3.0]
