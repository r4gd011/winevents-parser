"""Tests for the Windows Event XML parser."""

from pathlib import Path

import pytest

from winevents_parser.parser import parse_file, parse_xml

FIXTURES = Path(__file__).parent / "fixtures"

# ── Inline minimal XML ─────────────────────────────────────────────────────────

_4624 = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-15T08:30:45.1234567Z"/>
    <RecordID>12345678</RecordID>
    <Correlation ActivityID="{AABB-CCDD-EEFF}"/>
    <Execution ProcessID="4" ThreadID="200"/>
    <Channel>Security</Channel>
    <Computer>HOST01</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">HOST01$</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-5-21-111-222-333-1001</Data>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0xabcdef</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="IpPort">54321</Data>
    <Data Name="TargetLinkedLogonId">0x0</Data>
    <Data Name="ElevatedToken">%%1842</Data>
  </EventData>
</Event>"""

_4625 = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-15T09:00:00.0000000Z"/>
    <RecordID>9999</RecordID><Correlation/><Execution ProcessID="4" ThreadID="100"/>
    <Channel>Security</Channel><Computer>HOST01</Computer><Security/>
  </System>
  <EventData>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc0000064</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="TargetUserName">baduser</Data>
    <Data Name="TargetDomainName">CORP</Data>
  </EventData>
</Event>"""

_NO_CORRELATION = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Audit" Guid="{}"/>
    <EventID>4634</EventID><Version>0</Version><Level>0</Level><Task>0</Task>
    <Opcode>0</Opcode><Keywords>0x0</Keywords>
    <TimeCreated SystemTime="2024-01-15T08:00:00Z"/>
    <RecordID>1</RecordID>
    <Correlation/>
    <Execution ProcessID="4" ThreadID="1"/>
    <Channel>Security</Channel><Computer>H1</Computer><Security/>
  </System>
  <EventData/>
</Event>"""

_WRAPPED_TWO = """\
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Audit" Guid="{}"/>
      <EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>0</Task>
      <Opcode>0</Opcode><Keywords>0x0</Keywords>
      <TimeCreated SystemTime="2024-01-15T08:00:00Z"/>
      <RecordID>1</RecordID><Correlation/><Execution ProcessID="4" ThreadID="1"/>
      <Channel>Security</Channel><Computer>H1</Computer><Security/>
    </System>
    <EventData><Data Name="TargetUserName">alice</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Audit" Guid="{}"/>
      <EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>0</Task>
      <Opcode>0</Opcode><Keywords>0x0</Keywords>
      <TimeCreated SystemTime="2024-01-15T08:01:00Z"/>
      <RecordID>2</RecordID><Correlation/><Execution ProcessID="4" ThreadID="1"/>
      <Channel>Security</Channel><Computer>H1</Computer><Security/>
    </System>
    <EventData><Data Name="TargetUserName">bob</Data></EventData>
  </Event>
</Events>"""

# Same two events but without the <Events> wrapper
_BARE_TWO = "\n".join(
    line for line in _WRAPPED_TWO.splitlines()
    if line.strip() not in ("<Events>", "</Events>")
)


# ── System field extraction ────────────────────────────────────────────────────

class TestSystemFields:
    def setup_method(self):
        self.e = parse_xml(_4624)[0]

    def test_event_id(self):
        assert self.e["EventID"] == "4624"

    def test_channel(self):
        assert self.e["Channel"] == "Security"

    def test_computer(self):
        assert self.e["Computer"] == "HOST01"

    def test_time_created(self):
        assert self.e["TimeCreated"] == "2024-01-15T08:30:45.1234567Z"

    def test_record_id(self):
        assert self.e["RecordID"] == "12345678"

    def test_correlation_activity_id(self):
        assert self.e["CorrelationActivityID"] == "{AABB-CCDD-EEFF}"

    def test_process_id_from_execution(self):
        assert self.e["ProcessID"] == "4"

    def test_thread_id_from_execution(self):
        assert self.e["ThreadID"] == "200"

    def test_provider_name(self):
        assert self.e["ProviderName"] == "Microsoft-Windows-Security-Auditing"

    def test_provider_guid(self):
        assert self.e["ProviderGUID"] == "{54849625-5478-4994-A5BA-3E3B0328C30D}"

    def test_version(self):
        assert self.e["Version"] == "2"

    def test_level(self):
        assert self.e["Level"] == "0"

    def test_task(self):
        assert self.e["Task"] == "12544"

    def test_keywords(self):
        assert self.e["Keywords"] == "0x8020000000000000"


# ── EventData field renames ────────────────────────────────────────────────────

class TestEventDataRenames:
    def setup_method(self):
        self.e4624 = parse_xml(_4624)[0]
        self.e4625 = parse_xml(_4625)[0]

    def test_subject_domain_renamed(self):
        assert self.e4624["SubjectDomain"] == "CORP"
        assert "SubjectDomainName" not in self.e4624

    def test_target_domain_renamed(self):
        assert self.e4624["TargetDomain"] == "CORP"
        assert "TargetDomainName" not in self.e4624

    def test_linked_logon_id_renamed(self):
        assert self.e4624["LinkedLogonId"] == "0x0"
        assert "TargetLinkedLogonId" not in self.e4624

    def test_substatus_kept_as_substatus(self):
        # XML field is SubStatus; user spec listed it as Sub-status — normalised
        assert self.e4625["SubStatus"] == "0xc0000064"

    def test_target_user_sid_kept_as_is(self):
        # XML is TargetUserSid; user spec listed as TargetUserSidSID (typo)
        assert self.e4624["TargetUserSid"] == "S-1-5-21-111-222-333-1001"


# ── Regular EventData fields ───────────────────────────────────────────────────

class TestEventDataFields:
    def setup_method(self):
        self.e = parse_xml(_4624)[0]

    def test_subject_user_sid(self):
        assert self.e["SubjectUserSid"] == "S-1-5-18"

    def test_target_user_name(self):
        assert self.e["TargetUserName"] == "alice"

    def test_logon_type(self):
        assert self.e["LogonType"] == "3"

    def test_ip_address(self):
        assert self.e["IpAddress"] == "192.168.1.50"

    def test_ip_port(self):
        assert self.e["IpPort"] == "54321"


# ── Multiple events ────────────────────────────────────────────────────────────

class TestMultipleEvents:
    def test_wrapped_events_count(self):
        events = parse_xml(_WRAPPED_TWO)
        assert len(events) == 2

    def test_bare_events_count(self):
        events = parse_xml(_BARE_TWO)
        assert len(events) == 2

    def test_event_ids_in_order(self):
        events = parse_xml(_WRAPPED_TWO)
        assert events[0]["EventID"] == "4624"
        assert events[1]["EventID"] == "4625"

    def test_target_usernames(self):
        events = parse_xml(_WRAPPED_TWO)
        assert events[0]["TargetUserName"] == "alice"
        assert events[1]["TargetUserName"] == "bob"

    def test_returns_list_for_single_event(self):
        result = parse_xml(_4624)
        assert isinstance(result, list)
        assert len(result) == 1


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_missing_correlation_attribute_omitted(self):
        e = parse_xml(_NO_CORRELATION)[0]
        assert "CorrelationActivityID" not in e

    def test_bom_stripped(self):
        bom_xml = "﻿" + _4624
        events = parse_xml(bom_xml)
        assert events[0]["EventID"] == "4624"

    def test_leading_whitespace_ignored(self):
        events = parse_xml("   \n" + _4624)
        assert events[0]["EventID"] == "4624"

    def test_invalid_xml_raises_value_error(self):
        with pytest.raises(ValueError, match="Cannot parse XML"):
            parse_xml("not xml <<<>>>")


# ── Fixture files ──────────────────────────────────────────────────────────────

class TestFixtureFiles:
    def test_4624_system_fields(self):
        events = parse_file(str(FIXTURES / "event_4624.xml"))
        e = events[0]
        assert e["EventID"] == "4624"
        assert e["Channel"] == "Security"
        assert e["ProviderName"] == "Microsoft-Windows-Security-Auditing"
        assert e["CorrelationActivityID"] == "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

    def test_4624_eventdata_fields(self):
        e = parse_file(str(FIXTURES / "event_4624.xml"))[0]
        assert e["SubjectDomain"] == "CORP"
        assert e["TargetUserName"] == "jsmith"
        assert e["TargetDomain"] == "CORP"
        assert e["LinkedLogonId"] == "0x0"
        assert e["IpAddress"] == "192.168.1.100"

    def test_4625_failure_fields(self):
        e = parse_file(str(FIXTURES / "event_4625.xml"))[0]
        assert e["EventID"] == "4625"
        assert e["Status"] == "0xc000006d"
        assert e["SubStatus"] == "0xc0000064"
        assert e["FailureReason"] == "Unknown user name or bad password."

    def test_4688_process_fields(self):
        e = parse_file(str(FIXTURES / "event_4688.xml"))[0]
        assert e["EventID"] == "4688"
        assert e["NewProcessName"] == r"C:\Windows\System32\cmd.exe"
        assert e["CommandLine"] == "cmd.exe /c whoami"
        assert e["ParentProcessName"] == r"C:\Windows\explorer.exe"
        assert e["MandatoryLabel"] == "S-1-16-8192"
        assert e["TokenElevationType"] == "TokenElevationTypeDefault"

    def test_4104_powershell_fields(self):
        e = parse_file(str(FIXTURES / "event_4104.xml"))[0]
        assert e["EventID"] == "4104"
        assert e["Channel"] == "Microsoft-Windows-PowerShell/Operational"
        assert "Invoke-WebRequest" in e["ScriptBlockText"]
        assert e["Path"] == r"C:\Users\jsmith\Downloads\update.ps1"
        assert e["MessageNumber"] == "1"
        assert e["MessageTotal"] == "1"

    def test_multi_events_file(self):
        events = parse_file(str(FIXTURES / "multi_events.xml"))
        assert len(events) == 2
        ids = {e["EventID"] for e in events}
        assert ids == {"4624", "4625"}
        usernames = {e["TargetUserName"] for e in events}
        assert usernames == {"alice", "bob"}
