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
  cli.py      — argparse front-end; calls parse_xml / parse_file, writes JSON
  __init__.py — re-exports parse_xml, parse_file

tests/
  test_parser.py      — 39 tests; inline XML plus fixture-file tests
  fixtures/           — one realistic .xml per event type (4624, 4625, 4688, 4104,
                        multi_events with <Events> wrapper)
```

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

### Event-specific field notes

- **4688 process creation**: EventData `ProcessId` is the *parent/creator* PID; `NewProcessId` is the spawned process. System `ProcessID` (from `<Execution>`) is the audit provider process — three different PIDs.
- **4104 PowerShell**: `ScriptBlockText` may be split across multiple events (`MessageNumber`/`MessageTotal`) when the block exceeds the maximum event size. Reassembly by `ScriptBlockId` is the caller's responsibility.
- **`SubStatus`**: spec listed as `Sub-status`; the XML field is `SubStatus` — no rename needed.
- **`TargetUserSid`**: spec listed as `TargetUserSidSID` (apparent typo); XML field is `TargetUserSid` — output as-is.
