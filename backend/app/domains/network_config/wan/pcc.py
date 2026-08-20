"""GCD-reduced PCC plan for weighted multi-WAN load balancing."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class WeightedPccPlan:
    total: int
    indices_by_wan: list[list[int]]


def _gcd(a: int, b: int) -> int:
    return math.gcd(a, b)


def build_weighted_pcc_plan(weights: list[int]) -> WeightedPccPlan | None:
    """Mirror ``buildWeightedPccPlan`` from the frontend generator.

    Returns ``None`` when the GCD-reduced denominator exceeds 20 (RouterOS
    PCC practical cap).
    """
    if not weights or any(w <= 0 for w in weights):
        return None
    g = weights[0]
    for w in weights[1:]:
        g = _gcd(g, w)
    reduced = [w // g for w in weights]
    total = sum(reduced)
    if total > 20:
        return None
    indices_by_wan: list[list[int]] = []
    cursor = 0
    for share in reduced:
        indices = list(range(cursor, cursor + share))
        cursor += share
        indices_by_wan.append(indices)
    return WeightedPccPlan(total=total, indices_by_wan=indices_by_wan)
