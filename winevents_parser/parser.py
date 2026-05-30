"""Core XML parsing for Windows Security Events."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Iterator

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = f"{{{EVENT_NS}}}"

# <System> children whose text content becomes a top-level output field
_SYSTEM_TEXT_FIELDS = (
    "EventID", "Version", "Level", "Task", "Opcode",
    "Keywords", "Channel", "Computer", "RecordID",
)

# EventData <Data Name="..."> values whose output key differs from the XML Name attribute.
# Normalises Windows doc field names to the shorter forms the spec requests, and
# collapses TargetLinkedLogonId → LinkedLogonId.
# Note: TargetUserSid stays as-is (spec listed it as "TargetUserSidSID" — apparent typo).
#       SubStatus stays as-is (spec listed it as "Sub-status" — normalised here).
_EVENTDATA_RENAMES: dict[str, str] = {
    "SubjectDomainName":   "SubjectDomain",
    "TargetDomainName":    "TargetDomain",
    "TargetLinkedLogonId": "LinkedLogonId",
}

# Windows message resource strings (%%NNNN) appear verbatim in raw XML exports.
# Event Viewer resolves them at display time via msobjs.dll / lsasrv.dll; we do
# the same here so callers see human-readable values instead of opaque codes.
_WIN_MESSAGES: dict[str, str] = {
    # ImpersonationLevel — Events 4624, 4648, etc.
    "%%1832": "Anonymous",
    "%%1833": "Impersonation",
    "%%1834": "Delegation",
    "%%1835": "Identification",
    # TokenElevationType — Event 4688
    # Default: no split token (UAC disabled, or process launched without elevation prompt)
    # Full:    elevated token (Run as Administrator)
    # Limited: non-elevated half of a split token (standard UAC user)
    "%%1936": "TokenElevationTypeDefault",
    "%%1937": "TokenElevationTypeFull",
    "%%1938": "TokenElevationTypeLimited",
    # Boolean flags — ElevatedToken, VirtualAccount (Events 4624, etc.)
    "%%1842": "Yes",
    "%%1843": "No",
    # FailureReason — Event 4625
    "%%2305": "The specified user account has expired.",
    "%%2306": "The NetLogon component is not active.",
    "%%2307": "Account locked out.",
    "%%2308": "The user has not been granted the requested logon type at this machine.",
    "%%2309": "The specified account's password has expired.",
    "%%2310": "Account currently disabled.",
    "%%2311": "Account logon time restriction violation.",
    "%%2312": "User not allowed to logon at this computer.",
    "%%2313": "Unknown user name or bad password.",
}


def _tag(name: str) -> str:
    return _NS + name


def _parse_system(system: ET.Element) -> dict:
    out: dict = {}

    provider = system.find(_tag("Provider"))
    if provider is not None:
        if (v := provider.get("Name")) is not None:
            out["ProviderName"] = v
        if (v := provider.get("Guid")) is not None:
            out["ProviderGUID"] = v

    for field in _SYSTEM_TEXT_FIELDS:
        el = system.find(_tag(field))
        if el is not None and el.text is not None:
            out[field] = el.text

    tc = system.find(_tag("TimeCreated"))
    if tc is not None and (v := tc.get("SystemTime")) is not None:
        out["TimeCreated"] = v

    corr = system.find(_tag("Correlation"))
    if corr is not None and (v := corr.get("ActivityID")) is not None:
        out["CorrelationActivityID"] = v

    exe = system.find(_tag("Execution"))
    if exe is not None:
        if (v := exe.get("ProcessID")) is not None:
            # This is the audit subsystem's own PID — always 4 for the Security channel.
            # Do not confuse with EventData ProcessId, which is event-specific (e.g. the
            # parent/creator PID in Event 4688).
            out["ProcessID"] = v
        if (v := exe.get("ThreadID")) is not None:
            out["ThreadID"] = v

    return out


def _parse_eventdata(eventdata: ET.Element) -> dict:
    out: dict = {}
    for data in eventdata.findall(_tag("Data")):
        name = data.get("Name")
        if name:
            key = _EVENTDATA_RENAMES.get(name, name)
            value = data.text
            # Resolve Windows message resource strings so callers get readable values
            # instead of raw %%NNNN codes (e.g. "%%1938" → "TokenElevationTypeLimited").
            if value in _WIN_MESSAGES:
                value = _WIN_MESSAGES[value]
            out[key] = value
    return out


def _parse_userdata(userdata: ET.Element) -> dict:
    """Flatten UserData (used by a minority of non-Security channel events)."""
    out: dict = {}
    for child in userdata:
        for sub in child:
            local = sub.tag.split("}", 1)[-1] if "}" in sub.tag else sub.tag
            out[local] = sub.text
    return out


def _parse_event_element(event: ET.Element) -> dict:
    out: dict = {}

    system = event.find(_tag("System"))
    if system is not None:
        out.update(_parse_system(system))

    eventdata = event.find(_tag("EventData"))
    if eventdata is not None:
        # Note: in Event 4688, TargetUserSid = "S-1-0-0" (null SID) and
        # TargetUserName = "-" mean the new process inherited the subject's token
        # unchanged — the normal case. Non-null values indicate a different token
        # was used (e.g. runas, scheduled task, service account).
        out.update(_parse_eventdata(eventdata))

    userdata = event.find(_tag("UserData"))
    if userdata is not None:
        out.update(_parse_userdata(userdata))

    return out


def _iter_event_elements(root: ET.Element) -> Iterator[ET.Element]:
    tag = _tag("Event")
    if root.tag == tag:
        yield root
    else:
        yield from root.iter(tag)


def parse_xml(content: str) -> list[dict]:
    """
    Parse one or more Windows Event XML strings.

    Accepts:
    - A single <Event> element
    - Multiple bare <Event> elements (no wrapper — wrapped automatically)
    - An <Events> root containing multiple <Event> children
    - UTF-8 text with or without a BOM
    """
    content = content.strip().lstrip("﻿")  # strip UTF-8 BOM if present

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Multiple bare <Event> elements — synthesise a wrapper
        try:
            root = ET.fromstring(
                f'<_W xmlns="{EVENT_NS}">{content}</_W>'
            )
        except ET.ParseError as exc:
            raise ValueError(f"Cannot parse XML: {exc}") from exc

    return [_parse_event_element(e) for e in _iter_event_elements(root)]


def iter_events(path: str) -> Iterator[dict]:
    """
    Yield parsed events one at a time without loading the full file into memory.

    Uses iterparse so memory stays proportional to a single event regardless of
    file size — important for large Security channel exports (100 MB+).
    ET.iterparse reads binary and resolves encoding (UTF-8 BOM, UTF-16 BOM) from
    the XML declaration automatically, so no manual decode step is needed.
    """
    for _, elem in ET.iterparse(path, events=("end",)):
        if elem.tag == _tag("Event"):
            yield _parse_event_element(elem)
            elem.clear()  # release the element tree node immediately after use


def parse_file(path: str) -> list[dict]:
    """Parse all events from a file into a list. See iter_events() for streaming."""
    return list(iter_events(path))
