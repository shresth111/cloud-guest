"""Shared, format-agnostic report payload types (BE-012 Part 5).

``report_service.py`` (composition: calls the existing Parts 2-4 analytics
services, builds this tree) and ``export.py`` (rendering: turns this same
tree into JSON/CSV/Excel/PDF bytes) both depend on this module rather than
on each other -- keeps the composition layer and the rendering layer able to
change independently, and avoids a two-way import between them.

A :class:`ReportPayload` is deliberately generic: every section's ``data``
is whatever a composed analytics service's own Pydantic response
``.model_dump(mode="json")`` already produced, verbatim -- this module adds
no new metric, just a plain container plus the two small, format-agnostic
tree-walking helpers (:func:`flatten_scalar_fields`/
:func:`extract_tabular_blocks`) every tabular export format (CSV, Excel,
and the PDF's own tables) shares, so the "what counts as tabular vs.
scalar" rule is defined exactly once. See ``export.py``'s module docstring
for the full write-up of that rule (this domain's documented CSV/Excel
flattening convention).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ReportSection:
    """One labeled slice of a report -- ``data`` is a plain, JSON-shaped
    dict (almost always an existing analytics response's own
    ``model_dump(mode="json")`` output, occasionally hand-assembled for a
    report-only grouping, e.g. Part 5's own Business Insights + Operational
    Recommendations composition for ``ReportType.HEALTH``)."""

    key: str
    title: str
    data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ReportPayload:
    """The full, assembled-but-not-yet-rendered report tree --
    ``report_service.ReportGenerationService.generate``'s return value,
    and ``export.render_report``'s only input."""

    report_type: str
    title: str
    generated_at: str
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    period_start: str | None
    period_end: str | None
    sections: list[ReportSection] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """The exact shape ``report_schemas.ReportPayloadResponse``
        documents, and what ``export.py``'s own ``JSON`` format is."""
        return {
            "report_type": self.report_type,
            "title": self.title,
            "generated_at": self.generated_at,
            "organization_id": (
                str(self.organization_id) if self.organization_id is not None else None
            ),
            "location_id": (
                str(self.location_id) if self.location_id is not None else None
            ),
            "period_start": self.period_start,
            "period_end": self.period_end,
            "sections": [
                {"key": section.key, "title": section.title, "data": section.data}
                for section in self.sections
            ],
        }


@dataclass(frozen=True, slots=True)
class TabularBlock:
    """One "genuinely tabular" slice found while walking a
    :class:`ReportSection`'s ``data`` -- every JSON list-of-objects field,
    at any nesting depth, becomes exactly one of these (see module
    docstring)."""

    name: str
    columns: list[str]
    rows: list[list[Any]]


def _is_list_of_dicts(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, dict) for item in value)
    )


def flatten_scalar_fields(
    data: dict[str, Any], *, prefix: str = ""
) -> list[tuple[str, Any]]:
    """Every leaf of ``data`` that is **not** itself a list-of-objects,
    as ``(dotted.path, value)`` pairs -- nested dicts are walked
    recursively (their own dotted path prefix accumulating), and a list of
    plain scalars (e.g. ``recipient_emails``) is rendered as one single
    ``"; "``-joined string value rather than expanded into rows (it is a
    single field's *value*, not a table of records) -- this is the "Summary"
    half of this domain's documented flattening convention; see
    :func:`extract_tabular_blocks` for the other half."""
    pairs: list[tuple[str, Any]] = []
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            pairs.extend(flatten_scalar_fields(value, prefix=path))
        elif _is_list_of_dicts(value):
            continue
        elif isinstance(value, list):
            pairs.append((path, "; ".join(str(item) for item in value)))
        else:
            pairs.append((path, value))
    return pairs


def extract_tabular_blocks(
    data: dict[str, Any], *, prefix: str = ""
) -> list[TabularBlock]:
    """Every list-of-dicts field anywhere in ``data``, as its own
    :class:`TabularBlock` -- column headers are the union of every row's
    own keys (in first-seen order), so one row missing an optional key
    does not break the block; missing cells render as an empty string."""
    blocks: list[TabularBlock] = []
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            blocks.extend(extract_tabular_blocks(value, prefix=path))
        elif _is_list_of_dicts(value):
            columns: list[str] = []
            for item in value:
                for column in item:
                    if column not in columns:
                        columns.append(column)
            rows = [[item.get(column, "") for column in columns] for item in value]
            blocks.append(TabularBlock(name=path, columns=columns, rows=rows))
    return blocks


__all__ = [
    "ReportSection",
    "ReportPayload",
    "TabularBlock",
    "flatten_scalar_fields",
    "extract_tabular_blocks",
]
