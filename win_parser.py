#!/usr/bin/env python3
"""Parse a Windows Security Event XML file and print JSON to stdout."""

import argparse
import json
import sys

from winevents_parser import parse_file
from winevents_parser.filters import apply_filters, parse_filter_spec


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Parse a Windows Security Event XML file and output JSON."
    )
    ap.add_argument("file", help="Path to the XML event file")
    ap.add_argument("--pretty", "-p", action="store_true", help="Pretty-print output")
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
    args = ap.parse_args()

    try:
        events = parse_file(args.file)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.filters:
        events = apply_filters(events, args.filters)

    indent = 2 if args.pretty else None
    output = events[0] if len(events) == 1 else events
    print(json.dumps(output, indent=indent))


if __name__ == "__main__":
    main()
