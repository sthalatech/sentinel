"""Tests for the default-wiring warning in sentinel.config."""

from __future__ import annotations

import logging

from sentinel.config import build_default_config


def test_default_config_warns_stdout_notifier_active(caplog) -> None:
    """build_default_config() logs a loud warning that the default StdoutNotifier
    only prints escalations to process logs, so a real deployment is not
    proactively delivering them. Mirrors NoopEnforcer's construction warning."""
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        build_default_config(db_path=":memory:")
    messages = [r.getMessage() for r in caplog.records if r.name == "sentinel.config"]
    assert any("StdoutNotifier active" in m for m in messages), messages


def test_default_config_warning_explains_not_proactively_delivered(caplog) -> None:
    """The warning text must make the limitation explicit, not just name it."""
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        build_default_config(db_path=":memory:")
    messages = [r.getMessage() for r in caplog.records if r.name == "sentinel.config"]
    assert any("not proactively delivered" in m for m in messages), messages
