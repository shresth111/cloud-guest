"""QA-029: lines whose syslog head the parser could not read (no topics)
now reach dhcp / wireless / system; EVERY other line keeps its exact
classification and summary (founder-approved additive edit).

The corpus (``fixtures/netlogs_classify_corpus.json``) was recorded with the
classifier as it was on origin/main before the edit.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from app.domains.device_logs.classifier import classify, summary_for

CORPUS = json.loads(
    (Path(__file__).parent / "fixtures" / "netlogs_classify_corpus.json").read_text()
)

#: The only lines allowed to change, and what they must become.
CHANGED = {
    "<134>Oct 24  3:54:11 QA-sim dhcp,info defconf assigned 192.168.88.6 for "
    "02:00:00:00:06:01 qa-host-6": ("dhcp", "success"),
    "<132>Oct 24  3:54:11 QA-sim wireless,warning 02:00:00:00:00:05@wlan1: "
    "disconnected, extensive data loss": ("wireless", "disconnected"),
    "<130>Oct 24  3:54:11 QA-sim system,error,critical login failure for user "
    "admin from 203.0.113.5 via ssh": ("system", "failure"),
    "<134>Oct 24  3:54:11 QA-sim script,info hello": ("system", None),
}


@pytest.mark.parametrize("row", CORPUS, ids=[r["raw"][:48] for r in CORPUS])
def test_corpus(row) -> None:
    c = classify(row["message"], topics=row["topics"])
    after = dataclasses.asdict(c)
    summary = summary_for(c.category, c.status)
    if row["raw"] in CHANGED:
        category, status = CHANGED[row["raw"]]
        assert (after["category"], after["status"]) == (category, status)
        assert row["before"]["category"] == "other"
        return
    assert after == row["before"], "an existing classification changed"
    assert summary == row["summary_before"], "an existing summary changed"


def test_every_change_is_listed_and_from_other() -> None:
    assert all(r in {x["raw"] for x in CORPUS} for r in CHANGED)


def test_firewall_and_hotspot_in_the_unparsed_shape_are_untouched() -> None:
    unparsed = [r for r in CORPUS if r["topics"] is None and "QA-sim" in r["raw"]]
    for r in unparsed:
        if r["before"]["category"] in ("firewall", "hotspot_auth"):
            again = classify(r["message"], topics=None)
            assert dataclasses.asdict(again) == r["before"]


def test_ip_lists_are_not_mistaken_for_topics() -> None:
    assert classify("<134>Oct 24  3:54:11 h 192.168.1.1,10.0.0.1 x").category == "other"
