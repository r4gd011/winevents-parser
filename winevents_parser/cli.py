"""Command-line interface for winevents-parser."""

from __future__ import annotations

import argparse
import json
import sys

from .filters import apply_filters, parse_filter_spec
from .parser import parse_file, parse_xml


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        prog="winevents-parser",
        description="Parse Windows Security Event XML and output JSON.",
    )
    ap.add_argument(
        "input",
        nargs="?",
        metavar="FILE",
        help="XML file to parse (omit or use - to read from stdin)",
    )
    ap.add_argument(
        "--filter-id", "-f",
        metavar="IDS",
        help="Comma-separated EventIDs to include (e.g. 4624,4625)",
    )
    ap.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty-print JSON output",
    )
    ap.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    ap.add_argument(
        "--array", "-a",
        action="store_true",
        help="Always wrap output in a JSON array (default: array only for multiple events)",
    )
    ap.add_argument(
        "--ndjson", "-n",
        action="store_true",
        help="Output newline-delimited JSON (one object per line)",
    )
    ap.add_argument(
        "--filter", "-F",
        metavar="FIELD=VALUE or FIELD~VALUE",
        action="append",
        dest="filters",
        type=parse_filter_spec,
        help=(
            "Filter events by field value. "
            "Use = for exact match, ~ for substring match (both case-insensitive). "
            "Repeatable; all filters must match (AND logic). "
            "Example: --filter SubjectUserName=alice --filter CommandLine~encoded"
        ),
    )

    args = ap.parse_args(argv)

    try:
        if not args.input or args.input == "-":
            events = parse_xml(sys.stdin.read())
        else:
            events = parse_file(args.input)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.filter_id:
        ids = {eid.strip() for eid in args.filter_id.split(",")}
        events = [e for e in events if e.get("EventID") in ids]

    if args.filters:
        events = apply_filters(events, args.filters)

    indent = 2 if args.pretty else None

    if args.ndjson:
        output = "\n".join(json.dumps(e) for e in events)
        if output:
            output += "\n"
    elif len(events) == 1 and not args.array:
        output = json.dumps(events[0], indent=indent) + "\n"
    else:
        output = json.dumps(events, indent=indent) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)


if __name__ == "__main__":
    main()
