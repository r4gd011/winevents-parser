# Handoff

## What we built

A Python library and CLI tool that parses Windows Security Event XML and outputs structured JSON. The primary use case is post-processing exports from Event Viewer, EVTX-to-XML converters, or SIEM pipelines for triage and analysis.

### Scope

- **Event IDs covered**: 4624, 4625, 4634, 4647, 4648 (logon/logoff), 4688, 4689 (process), 4768, 4771 (Kerberos), 4778, 4779 (session), 4103, 4104 (PowerShell). Any event using standard `<EventData>` structure will also parse correctly.
- **Input formats**: single `<Event>`, `<Events>`-wrapped multi-event exports, bare multiple `<Event>` elements with no wrapper, UTF-8/UTF-16/BOM encodings.
- **Output**: flat JSON dict per event; System + EventData fields merged; strings only; absent fields omitted.

### Files

```
winevents_parser/
  parser.py   — XML parsing (the only file that touches ElementTree)
  filters.py  — field-level filtering logic
  cli.py      — full CLI (stdin, --array, --ndjson, --output, --filter-id, --filter)
  __init__.py — public API: iter_events, parse_file, parse_xml

win_parser.py       — standalone root-level script, no install needed
samples/            — 4 realistic XML files for manual testing
tests/
  test_parser.py    — 39 tests
  test_filters.py   — 42 tests
  fixtures/         — per-event-type XML fixtures
```

81 tests, all passing.

---

## How to use it

### CLI

```bash
# Parse a file
python3 -m winevents_parser.cli events.xml --pretty

# Read from stdin
cat events.xml | python3 -m winevents_parser.cli -

# Filter by event ID
python3 -m winevents_parser.cli events.xml --filter-id 4624,4625

# Filter by field — exact match (case-insensitive)
python3 -m winevents_parser.cli events.xml --filter SubjectUserName=alice

# Filter by substring
python3 -m winevents_parser.cli events.xml --filter CommandLine~encoded

# Multiple filters = AND logic
python3 -m winevents_parser.cli events.xml --filter LogonType=3 --filter TargetDomain=CORP

# NDJSON for jq pipelines
python3 -m winevents_parser.cli events.xml --ndjson | jq 'select(.EventID=="4688") | .CommandLine'

# Write to file, always as array
python3 -m winevents_parser.cli events.xml --array --output out.json
```

`win_parser.py` supports `--filter` and `--pretty`; use it when you don't want to install the package.

### Library

```python
from winevents_parser import parse_file, parse_xml, iter_events
from winevents_parser.filters import apply_filters

# List — fine for most files
events = parse_file("export.xml")

# Generator — use for large files
for event in iter_events("large_export.xml"):
    if event.get("EventID") == "4688":
        print(event["CommandLine"])

# Filtering
results = apply_filters(events, [
    ("LogonType", "=", "3"),
    ("CommandLine", "~", "powershell"),
])
```

### Field alias

When filtering 4688 events by parent process, use `ParentProcessId` — it resolves to the actual JSON key `ProcessId` (EventData). This alias exists because the XML name `ProcessId` is ambiguous given that `ProcessID` (capital D, System/Execution) is an unrelated field that is always `"4"`.

---

## What's left to do

### High value

- **4104 script block reassembly** — PowerShell script blocks larger than the event size limit are split across multiple events with the same `ScriptBlockId`, incrementing `MessageNumber` up to `MessageTotal`. The parser emits each fragment as a separate event. A `reassemble_script_blocks(events)` helper that groups by `ScriptBlockId` and concatenates in order would make 4104 analysis much more useful.
- **`%%NNNN` decoding gaps** — The static decode dict covers the most common codes (ImpersonationLevel, TokenElevationType, FailureReason, Yes/No). Other event types (4769, 4776, object access events) use additional resource strings not yet in the dict.
- **EVTX support** — Currently requires XML. Adding direct `.evtx` parsing via `python-evtx` or calling `wevtutil` as a subprocess would remove the export step.

### Medium value

- **OR filter logic** — Current `--filter` flags are AND-only. A `--filter-any` flag (or `|` syntax) would cover cases like "show me all failed logons OR process creations by this user".
- **Time range filtering** — `--after` / `--before` flags on `TimeCreated` would be natural for triage workflows. The field is already parsed as an ISO 8601 string.
- **Output field selection** — `--fields EventID,SubjectUserName,CommandLine` to project a subset of fields, useful when piping to CSV or tabular output.

### Low value / stretch

- `%%NNNN` decoding via live registry lookup (instead of static dict) — adds a Windows-only runtime dependency for marginal gain.
- Structured output for known event shapes (typed dataclasses per event ID) — useful for downstream type-checked code but breaks the current "flat dict, strings only" invariant.

---

## Decisions and why

### ElementTree over lxml

`xml.etree.ElementTree` is stdlib and sufficient. Windows Security Event XML has a fixed, well-known namespace (`http://schemas.microsoft.com/win/2004/08/events/event`) and a predictable structure. `lxml`'s XPath and schema validation offer nothing here that `ET` doesn't cover; adding a compiled dependency would be a net negative.

### Flat dict, strings only

All fields — System and EventData — are merged into one flat dict. No nested `{"System": {...}, "EventData": {...}}` shape. Callers never need to know which sub-element a field came from, and every event can be processed with the same code.

Values are left as strings. EventIDs, hex PIDs (`0x1a4c`), logon types (`"3"`), SIDs all stay as the raw XML string. Int conversion would be lossy for hex PIDs and would break the round-trip invariant. Callers that need ints can convert at the point of use.

### Absent fields omitted, not null

A 4634 logoff event has far fewer fields than a 4624 logon. Emitting `null` for every field the event lacks would bloat output and mislead callers into treating nulls as meaningful. Omitting absent fields keeps each event compact and makes `event.get("CommandLine")` the natural access pattern.

### Streaming via `iter_events` / `ET.iterparse`

`parse_file` originally loaded the full XML into memory. After testing with multi-event files, it was replaced with `ET.iterparse` + `elem.clear()`. The `parse_file` API is unchanged (still returns a list) but now iterates the file in a single pass. `iter_events` exposes the generator directly for callers processing large exports.

### `parse_filter_spec` as argparse `type=`

Passing the filter parser as `type=parse_filter_spec` means argparse validates filter syntax before the program does any parsing. A malformed `--filter` exits with a clean usage error immediately, not after potentially processing a large file.

### AND logic for multiple filters

Multiple `--filter` flags require all conditions to match. OR logic was considered but AND covers the primary triage workflow ("show me all events from this user that also match this command line") and is simpler to reason about. OR can always be approximated by running the tool twice and merging output.

### `win_parser.py` alongside `cli.py`

`cli.py` is the installed entry point with the full flag set (`--array`, `--ndjson`, `--output`, stdin). `win_parser.py` is a standalone script at the repo root for analysts who want to drop the file next to their XML exports and run it without installing anything. Both share the same library and filter logic.
