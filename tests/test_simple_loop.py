"""Tests for SimpleLoopOrchestrator."""

from __future__ import annotations

from threading import Event
from unittest.mock import MagicMock

from sentinel.core.engine import SentinelConfig
from sentinel.plugins.orchestrators.simple_loop import SimpleLoopOrchestrator


def make_cfg() -> SentinelConfig:
    """Return a minimal mock config for loop tests."""
    return SentinelConfig(
        detector=MagicMock(),
        remediator=MagicMock(),
        verifier=MagicMock(),
        enforcer=MagicMock(),
        notifier=MagicMock(),
        issue_tracker=MagicMock(),
        state_store=MagicMock(),
        trust=MagicMock(),
        audit=MagicMock(),
    )


def test_run_once_is_called(mocker) -> None:
    """schedule should invoke run_once at least once."""
    cfg = make_cfg()
    cfg.detector.detect.return_value = []
    run_once_mock = mocker.patch("sentinel.plugins.orchestrators.simple_loop.run_once")
    loop = SimpleLoopOrchestrator(interval=0.01)
    loop.schedule(cfg)
    run_once_mock.assert_called_once_with(cfg)
    loop.stop()


def test_stop_works(mocker) -> None:
    """stop should prevent further scheduled ticks."""
    cfg = make_cfg()
    cfg.detector.detect.return_value = []
    run_once_mock = mocker.patch("sentinel.plugins.orchestrators.simple_loop.run_once")
    loop = SimpleLoopOrchestrator(interval=0.01)
    loop.schedule(cfg)
    loop.stop()
    calls_before = run_once_mock.call_count
    import time

    time.sleep(0.05)
    assert run_once_mock.call_count == calls_before


def test_retry_backoff_on_exception(mocker) -> None:
    """retry should sleep according to exponential backoff after a failure."""
    cfg = make_cfg()
    loop = SimpleLoopOrchestrator(
        interval=60.0,
        initial_backoff=0.02,
        max_backoff=0.08,
        backoff_factor=2.0,
    )
    done = Event()
    sleep_durations: list[float] = []
    schedule_calls: list[object] = []

    def fake_wait(delay: float) -> None:
        sleep_durations.append(delay)

    def fake_schedule(config: SentinelConfig) -> None:
        schedule_calls.append(config)
        done.set()

    mocker.patch.object(loop, "_wait", side_effect=fake_wait)
    mocker.patch.object(loop, "schedule", side_effect=fake_schedule)
    loop.retry(cfg)
    done.wait(timeout=1.0)
    assert sleep_durations == [0.02]
    assert loop._backoff == 0.04
    assert schedule_calls == [cfg]
