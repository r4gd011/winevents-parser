"""Field-level filtering for parsed Windows Event dicts."""

from __future__ import annotations

import argparse

# Maps user-facing filter key → actual key in the parsed event dict.
# Needed where the XML field name differs from the intuitive name.
# ParentProcessId: in Event 4688 EventData the creator PID is stored as "ProcessId".
# (ProcessID with capital D is always "4" — the audit subsystem PID, unrelated.)
FIELD_ALIASES: dict[str, str] = {
    "ParentProcessId": "ProcessId",
}


def parse_filter_spec(spec: str) -> tuple[str, str, str]:
    """
    Parse a filter expression into (field, op, value).

    Accepts:
      "Field=value"  — exact match (case-insensitive)
      "Field~value"  — substring / contains match (case-insensitive)

    Splits on the first delimiter only, so values may themselves contain = or ~.
    Raises argparse.ArgumentTypeError on unrecognised syntax.
    """
    for op in ("=", "~"):
        if op in spec:
            field, value = spec.split(op, 1)
            field = field.strip()
            if not field:
                raise argparse.ArgumentTypeError(
                    f"Filter field name is empty in {spec!r}"
                )
            return field, op, value
    raise argparse.ArgumentTypeError(
        f"Invalid filter {spec!r} — use FIELD=VALUE (exact) or FIELD~VALUE (contains)"
    )


def apply_filters(
    events: list[dict],
    filters: list[tuple[str, str, str]],
) -> list[dict]:
    """
    Return the subset of events that satisfy ALL supplied filters (AND logic).

    filter tuple: (field, op, value)
      op "=" — case-insensitive exact match
      op "~" — case-insensitive substring match
    A field absent from an event never matches.
    """
    if not filters:
        return events

    def matches(event: dict) -> bool:
        for field, op, value in filters:
            actual_key = FIELD_ALIASES.get(field, field)
            raw = event.get(actual_key)
            if raw is None:
                return False
            ev_val = str(raw).lower()
            cmp_val = value.lower()
            if op == "=" and ev_val != cmp_val:
                return False
            if op == "~" and cmp_val not in ev_val:
                return False
        return True

    return [e for e in events if matches(e)]
