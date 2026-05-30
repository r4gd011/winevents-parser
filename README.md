# winevents-parser

Parse Windows Security Event XML and output structured JSON. Accepts exports from Event Viewer, EVTX-to-XML converters, and SIEM pipelines.

## Supported event IDs

| Category | Event IDs |
|---|---|
| Logon / logoff | 4624, 4625, 4634, 4647, 4648 |
| Process | 4688, 4689 |
| Kerberos | 4768, 4771 |
| Session | 4778, 4779 |
| PowerShell | 4103, 4104 |

Account management, object access, and privilege-use events are also parsed — any event that uses the standard `<EventData>` structure will produce output.

## Installation

```bash
# Run directly without installing (tests and CLI both work this way)
PYTHONPATH=. python3 -m winevents_parser.cli event.xml

# Or install in editable mode (requires pip >= 22)
pip install -e .
winevents-parser event.xml
```

## Usage

```bash
# Parse a file
python3 -m winevents_parser.cli event.xml

# Parse from stdin
cat events.xml | python3 -m winevents_parser.cli -

# Pretty-print
python3 -m winevents_parser.cli event.xml --pretty

# Filter to specific event IDs
python3 -m winevents_parser.cli events.xml --filter-id 4624,4625

# Filter by field value (exact, case-insensitive)
python3 -m winevents_parser.cli events.xml --filter SubjectUserName=alice

# Filter by substring (case-insensitive)
python3 -m winevents_parser.cli events.xml --filter CommandLine~encoded

# Combine filters (AND logic)
python3 -m winevents_parser.cli events.xml --filter LogonType=3 --filter TargetDomain=CORP

# Always output an array, write to file
python3 -m winevents_parser.cli events.xml --array --output out.json

# Newline-delimited JSON (pipe-friendly)
python3 -m winevents_parser.cli events.xml --ndjson | jq '.EventID'
```

`win_parser.py` in the repo root is a standalone script with the same `--filter`/`--pretty` flags, no installation required.

## Output

Each event is a flat JSON object. System fields (`EventID`, `Computer`, `TimeCreated`, etc.) are merged with EventData fields into a single dict. Fields absent from an event are omitted. All values are strings.

```json
{
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": "4624",
  "TimeCreated": "2024-01-15T08:23:41.123456Z",
  "Computer": "WORKSTATION01.corp.example.com",
  "Channel": "Security",
  "SubjectUserName": "WORKSTATION01$",
  "SubjectDomain": "CORP",
  "TargetUserName": "alice",
  "TargetDomain": "CORP",
  "TargetLogonId": "0x3e7",
  "LogonType": "3",
  "AuthenticationPackageName": "Kerberos",
  "IpAddress": "192.168.1.42"
}
```

### Field notes

- **4688 process creation** has three PIDs: `ProcessID` (System/Execution, always `"4"` — the audit provider), `ProcessId` (EventData — the parent/creator), `NewProcessId` (the spawned process). Filter by `ParentProcessId` as an alias for `ProcessId`.
- **`%%NNNN`** Windows message strings are decoded: `ImpersonationLevel`, `TokenElevationType`, `FailureReason`, and Yes/No values.
- **4104 PowerShell** script blocks larger than the event size limit are split across multiple events sharing a `ScriptBlockId`. Reassembly is the caller's responsibility.
- Field renames applied: `SubjectDomainName→SubjectDomain`, `TargetDomainName→TargetDomain`, `TargetLinkedLogonId→LinkedLogonId`.

## Library usage

```python
from winevents_parser import parse_file, parse_xml, iter_events

# From file (returns list)
events = parse_file("events.xml")

# Streaming (memory-efficient for large files)
for event in iter_events("large_export.xml"):
    process(event)

# From string
events = parse_xml(xml_string)
```

### Filtering

```python
from winevents_parser.filters import apply_filters

filters = [
    ("LogonType", "=", "3"),
    ("CommandLine", "~", "powershell"),
]
results = apply_filters(events, filters)
```

## Running tests

```bash
python3 -m pytest
python3 -m pytest tests/test_parser.py::TestSystemFields -v
```

## Input formats

The parser handles:
- Single `<Event>` element
- Multiple `<Event>` elements wrapped in `<Events>`
- Multiple bare `<Event>` elements with no wrapper
- UTF-8, UTF-8 BOM, and UTF-16 BOM encodings
