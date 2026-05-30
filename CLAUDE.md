# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Python tool that parses Windows Security Event XML (exported from Event Viewer, EVTX exports, or SIEM pipelines) and outputs structured JSON. Targets Security/Audit events (4624, 4625, 4634, 4647, 4648, 4688, 4689, 4768, 4771, 4778, 4779), PowerShell script-block events (4103, 4104), and account management / object access / privilege-use events.

## Commands

```bash
# Run tests (conftest.py adds project root to sys.path automatically)
python3 -m pytest

# Run a single test class or file
python3 -m pytest tests/test_parser.py::TestSystemFields -v

# Parse a file
python3 -m winevents_parser.cli event.xml

# Parse from stdin, filter to logon events, pretty-print
cat events.xml | python3 -m winevents_parser.cli - --filter-id 4624,4625 --pretty

# Always output an array, write to file
python3 -m winevents_parser.cli events.xml --array --output out.json

# Newline-delimited JSON (one object per line — good for piping to jq)
python3 -m winevents_parser.cli events.xml --ndjson
```

Installing in editable mode requires pip ≥ 22 (the system pip on macOS is old). Either upgrade pip first or use the `PYTHONPATH` workaround:
```bash
PYTHONPATH=. python3 -m pytest
```

## Architecture

```
winevents_parser/
  parser.py   — all XML parsing logic; the only file that touches ElementTree
  filters.py  — field-level filtering (parse_filter_spec, apply_filters, FIELD_ALIASES)
  cli.py      — argparse front-end; calls parse_xml / parse_file, writes JSON
  __init__.py — re-exports iter_events, parse_file, parse_xml

tests/
  test_parser.py      — 39 tests; inline XML plus fixture-file tests
  test_filters.py     — 42 tests covering filter parsing, matching, aliases, CLI integration
  fixtures/           — one realistic .xml per event type (4624, 4625, 4688, 4104,
                        multi_events with <Events> wrapper)
```

### Why `xml.etree.ElementTree`

`ET` is stdlib, zero dependencies, and sufficient for the structured/predictable schema of Windows Security Event XML. The namespace (`http://schemas.microsoft.com/win/2004/08/events/event`) is consistent across all event types, so no namespace stripping is needed — element lookups use the full Clark notation `{ns}Tag`. `lxml` would add no meaningful benefit given the fixed schema.

### JSON output decisions

- **Flat dict per event** — System fields and EventData fields are merged into one object; no nested `System`/`EventData` keys. Callers treat every event uniformly without knowing which sub-element a field came from.
- **Strings only** — no type coercion. EventIDs, hex PIDs, logon types, SIDs all stay as the raw string from XML. Avoids lossy int conversion (hex PIDs) and keeps output round-trippable.
- **Absent fields omitted** — fields not present in an event are not emitted as `null`. Sparse events (e.g. 4634 has far fewer fields than 4624) stay compact.
- **Single event → bare object; multiple → array** — unless `--array` is passed. This is the natural shape for piping to `jq` for single-file inspection while still being valid JSON for multi-event files.

### Parsing pipeline (`parser.py`)

1. `parse_file` — reads bytes, detects UTF-16 BOM vs UTF-8, delegates to `parse_xml`.
2. `parse_xml` — strips BOM, calls `ET.fromstring`. If that fails (multiple bare `<Event>` elements with no wrapper), wraps in a synthetic root and retries.
3. `_iter_event_elements` — handles three root shapes: single `<Event>`, `<Events>` wrapper, or any other root (uses `.iter()`).
4. `_parse_event_element` — merges `<System>`, `<EventData>`, and (rarely) `<UserData>`.

### Field name normalisation

All fields are output with their XML `Name` attribute as the key **except** these renames applied in `_EVENTDATA_RENAMES`:

| XML field name        | Output key       | Reason                                          |
|-----------------------|------------------|-------------------------------------------------|
| `SubjectDomainName`   | `SubjectDomain`  | Shorter form used in spec                       |
| `TargetDomainName`    | `TargetDomain`   | Shorter form used in spec                       |
| `TargetLinkedLogonId` | `LinkedLogonId`  | Spec calls it LinkedLogonId                     |

Fields absent from an event are omitted (not set to null). All values are strings — no type coercion is applied (EventIDs, hex PIDs, logon types, etc. stay as strings matching the raw XML).

### Filtering (`filters.py`)

`--filter FIELD=VALUE` (exact) and `--filter FIELD~VALUE` (substring), both case-insensitive. Multiple `--filter` flags are **AND** logic — an event must satisfy all filters to be included. Implemented in `filters.py`, used by both `cli.py` and `win_parser.py`.

`parse_filter_spec` is passed as `type=` to `argparse.add_argument` so syntax errors are caught and reported before any parsing runs.

`FIELD_ALIASES` maps user-facing names to actual JSON keys where the XML name is unintuitive:

| Filter key        | Resolves to  | Why                                              |
|-------------------|--------------|--------------------------------------------------|
| `ParentProcessId` | `ProcessId`  | 4688 EventData stores creator PID as `ProcessId` |

A field absent from an event never matches (the event is excluded). This means `--filter CommandLine~encoded` will only return events that *have* a `CommandLine` field containing "encoded" — 4624 logon events (which have no `CommandLine`) are silently excluded, not errored.

### Event-specific field notes

- **4688 process creation**: EventData `ProcessId` is the *parent/creator* PID; `NewProcessId` is the spawned process. System `ProcessID` (from `<Execution>`) is the audit provider process — three different PIDs.
- **4104 PowerShell**: `ScriptBlockText` may be split across multiple events (`MessageNumber`/`MessageTotal`) when the block exceeds the maximum event size. Reassembly by `ScriptBlockId` is the caller's responsibility.
- **`SubStatus`**: spec listed as `Sub-status`; the XML field is `SubStatus` — no rename needed.
- **`TargetUserSid`**: spec listed as `TargetUserSidSID` (apparent typo); XML field is `TargetUserSid` — output as-is.
