"""The collector's per-router display cap is configurable, and the default did
not move: with neither variable set, vector.yaml still caps at 3000 lines per
router per minute and excludes nothing from the throttle."""

from __future__ import annotations

from pathlib import Path

import yaml


def test_vector_default_is_unchanged_and_unlimited_is_opt_in() -> None:
    root = Path(__file__).resolve().parents[3]
    text = (root / "deploy/device-logs/vector.yaml").read_text()
    resolved = text.replace("${NETLOGS_DISPLAY_CAP_PER_MIN:-3000}", "3000").replace(
        "${NETLOGS_DISPLAY_CAP_UNLIMITED:-false}", "false"
    )
    throttle = yaml.safe_load(resolved)["transforms"]["throttle_index"]
    assert throttle["threshold"] == 3000
    assert throttle["window_secs"] == 60
    assert throttle["exclude"]["source"] == '"false" == "true"'
    assert "${NETLOGS_DISPLAY_CAP_PER_MIN:-3000}" in text
    assert "${NETLOGS_DISPLAY_CAP_UNLIMITED:-false}" in text
