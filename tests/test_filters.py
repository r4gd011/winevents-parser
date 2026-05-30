"""Tests for winevents_parser.filters."""

import argparse
import json
import sys
from io import StringIO
from pathlib import Path

import pytest

from winevents_parser.filters import FIELD_ALIASES, apply_filters, parse_filter_spec

FIXTURES = Path(__file__).parent / "fixtures"

# ── Sample events used across tests ───────────────────────────────────────────

_EVT_ALICE = {
    "EventID": "4624",
    "SubjectUserName": "alice",
    "SubjectDomain": "CORP",
    "SubjectUserSid": "S-1-5-21-111-222-333-1001",
    "SubjectLogonId": "0x5b2f0",
    "LogonType": "3",
    "IpAddress": "192.168.1.10",
    "TargetUserName": "alice",
    "TargetDomain": "CORP",
    "TargetUserSid": "S-1-5-21-111-222-333-1001",
    "TargetLogonId": "0xabcdef",
    "WorkstationName": "LAPTOP-ALICE",
    "LogonProcessName": "NtLmSsp",
    "AuthenticationPackageName": "NTLM",
}

_EVT_BOB_FAIL = {
    "EventID": "4625",
    "SubjectUserName": "bob",
    "SubjectDomain": "CORP",
    "SubjectUserSid": "S-1-0-0",
    "TargetUserName": "bob",
    "TargetDomain": "CORP",
    "TargetUserSid": "S-1-0-0",
    "Status": "0xc000006d",
    "SubStatus": "0xc0000064",
    "LogonType": "3",
    "LogonProcessName": "NtLmSsp",
    "AuthenticationPackageName": "NTLM",
    "IpAddress": "10.0.0.99",
    "WorkstationName": "ATTACKER-PC",
}

_EVT_4688 = {
    "EventID": "4688",
    "SubjectUserName": "jsmith",
    "SubjectDomain": "CORP",
    "NewProcessId": "0x2f38",
    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
    "TokenElevationType": "TokenElevationTypeDefault",
    "ProcessId": "0x1a4c",          # parent/creator PID — aliased as ParentProcessId
    "CommandLine": "cmd.exe /c whoami",
    "ParentProcessName": "C:\\Windows\\explorer.exe",
    "MandatoryLabel": "S-1-16-8192",
}

_ALL = [_EVT_ALICE, _EVT_BOB_FAIL, _EVT_4688]


# ── parse_filter_spec ──────────────────────────────────────────────────────────

class TestParseFilterSpec:
    def test_exact_operator(self):
        assert parse_filter_spec("SubjectUserName=alice") == ("SubjectUserName", "=", "alice")

    def test_contains_operator(self):
        assert parse_filter_spec("CommandLine~whoami") == ("CommandLine", "~", "whoami")

    def test_value_containing_equals(self):
        field, op, value = parse_filter_spec("Status=0xc000=extra")
        assert op == "="
        assert value == "0xc000=extra"

    def test_value_containing_tilde(self):
        field, op, value = parse_filter_spec("CommandLine~foo~bar")
        assert op == "~"
        assert value == "foo~bar"

    def test_equals_takes_priority_over_tilde(self):
        # first delimiter wins
        field, op, value = parse_filter_spec("Field=a~b")
        assert op == "="
        assert value == "a~b"

    def test_no_delimiter_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="Invalid filter"):
            parse_filter_spec("SubjectUserNamealice")

    def test_empty_field_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="empty"):
            parse_filter_spec("=value")


# ── apply_filters — exact match ────────────────────────────────────────────────

class TestApplyFiltersExact:
    def test_match_returns_event(self):
        result = apply_filters(_ALL, [("SubjectUserName", "=", "alice")])
        assert len(result) == 1
        assert result[0]["SubjectUserName"] == "alice"

    def test_no_match_returns_empty(self):
        result = apply_filters(_ALL, [("SubjectUserName", "=", "nobody")])
        assert result == []

    def test_case_insensitive(self):
        result = apply_filters(_ALL, [("SubjectUserName", "=", "ALICE")])
        assert len(result) == 1

    def test_missing_field_excluded(self):
        # _EVT_4688 has no Status field
        result = apply_filters([_EVT_4688], [("Status", "=", "0xc000006d")])
        assert result == []

    def test_logon_type_exact(self):
        result = apply_filters(_ALL, [("LogonType", "=", "3")])
        assert all(e.get("LogonType") == "3" for e in result)

    def test_target_user_sid(self):
        result = apply_filters(_ALL, [("TargetUserSid", "=", "S-1-0-0")])
        assert len(result) == 1
        assert result[0]["EventID"] == "4625"

    def test_substatus(self):
        result = apply_filters(_ALL, [("SubStatus", "=", "0xc0000064")])
        assert len(result) == 1
        assert result[0]["SubjectUserName"] == "bob"

    def test_status(self):
        result = apply_filters(_ALL, [("Status", "=", "0xc000006d")])
        assert len(result) == 1

    def test_workstation_name(self):
        result = apply_filters(_ALL, [("WorkstationName", "=", "ATTACKER-PC")])
        assert len(result) == 1
        assert result[0]["EventID"] == "4625"

    def test_logon_process_name(self):
        result = apply_filters(_ALL, [("LogonProcessName", "=", "ntlmssp")])
        assert len(result) == 2   # alice and bob both have NtLmSsp

    def test_authentication_package(self):
        result = apply_filters(_ALL, [("AuthenticationPackageName", "=", "NTLM")])
        assert len(result) == 2

    def test_target_logon_id(self):
        result = apply_filters(_ALL, [("TargetLogonId", "=", "0xabcdef")])
        assert len(result) == 1
        assert result[0]["SubjectUserName"] == "alice"

    def test_subject_logon_id(self):
        result = apply_filters(_ALL, [("SubjectLogonId", "=", "0x5b2f0")])
        assert len(result) == 1

    def test_subject_user_sid(self):
        result = apply_filters(_ALL, [("SubjectUserSid", "=", "S-1-5-21-111-222-333-1001")])
        assert len(result) == 1

    def test_target_domain(self):
        result = apply_filters(_ALL, [("TargetDomain", "=", "CORP")])
        assert len(result) == 2   # alice and bob


# ── apply_filters — contains match ────────────────────────────────────────────

class TestApplyFiltersContains:
    def test_command_line_contains(self):
        result = apply_filters(_ALL, [("CommandLine", "~", "whoami")])
        assert len(result) == 1
        assert result[0]["EventID"] == "4688"

    def test_command_line_case_insensitive(self):
        result = apply_filters(_ALL, [("CommandLine", "~", "WHOAMI")])
        assert len(result) == 1

    def test_no_match_returns_empty(self):
        result = apply_filters(_ALL, [("CommandLine", "~", "mimikatz")])
        assert result == []

    def test_new_process_name_contains(self):
        result = apply_filters(_ALL, [("NewProcessName", "~", "cmd.exe")])
        assert len(result) == 1
        assert result[0]["EventID"] == "4688"

    def test_parent_process_name_contains(self):
        result = apply_filters(_ALL, [("ParentProcessName", "~", "explorer")])
        assert len(result) == 1

    def test_ip_address_contains(self):
        result = apply_filters(_ALL, [("IpAddress", "~", "192.168")])
        assert len(result) == 1
        assert result[0]["SubjectUserName"] == "alice"


# ── ParentProcessId alias ──────────────────────────────────────────────────────

class TestFieldAliases:
    def test_alias_defined(self):
        assert FIELD_ALIASES["ParentProcessId"] == "ProcessId"

    def test_parent_process_id_resolves_to_process_id(self):
        result = apply_filters([_EVT_4688], [("ParentProcessId", "=", "0x1a4c")])
        assert len(result) == 1

    def test_parent_process_id_no_match(self):
        result = apply_filters([_EVT_4688], [("ParentProcessId", "=", "0x9999")])
        assert result == []

    def test_parent_process_id_contains(self):
        result = apply_filters([_EVT_4688], [("ParentProcessId", "~", "1a4")])
        assert len(result) == 1


# ── AND logic ─────────────────────────────────────────────────────────────────

class TestAndLogic:
    def test_both_match(self):
        result = apply_filters(_ALL, [
            ("SubjectUserName", "=", "alice"),
            ("LogonType", "=", "3"),
        ])
        assert len(result) == 1

    def test_one_fails(self):
        result = apply_filters(_ALL, [
            ("SubjectUserName", "=", "alice"),
            ("LogonType", "=", "9"),      # alice has LogonType=3, not 9
        ])
        assert result == []

    def test_exact_and_contains(self):
        result = apply_filters(_ALL, [
            ("EventID", "=", "4688"),
            ("CommandLine", "~", "whoami"),
        ])
        assert len(result) == 1

    def test_empty_filters_returns_all(self):
        result = apply_filters(_ALL, [])
        assert result is _ALL


# ── CLI integration ────────────────────────────────────────────────────────────

class TestCLIIntegration:
    def _run(self, *argv):
        """Run cli.main() and capture stdout as parsed JSON."""
        from winevents_parser.cli import main
        buf = StringIO()
        old, sys.stdout = sys.stdout, buf
        try:
            main(list(argv))
        finally:
            sys.stdout = old
        return json.loads(buf.getvalue())

    def test_filter_exact_single_event(self):
        result = self._run(
            str(FIXTURES / "event_4624.xml"),
            "--filter", "SubjectUserName=WORKSTATION01$",
        )
        assert result["EventID"] == "4624"

    def test_filter_exact_no_match_returns_empty_array(self):
        result = self._run(
            str(FIXTURES / "event_4624.xml"),
            "--filter", "SubjectUserName=nobody",
            "--array",
        )
        assert result == []

    def test_filter_contains_command_line(self):
        result = self._run(
            str(FIXTURES / "event_4688.xml"),
            "--filter", "CommandLine~whoami",
        )
        assert result["EventID"] == "4688"

    def test_filter_contains_no_match(self):
        result = self._run(
            str(FIXTURES / "event_4688.xml"),
            "--filter", "CommandLine~mimikatz",
            "--array",
        )
        assert result == []

    def test_and_filters_on_multi_event_file(self):
        # Two filters narrow multi_events.xml (alice+bob) to 1 event → bare object
        result = self._run(
            str(FIXTURES / "multi_events.xml"),
            "--filter", "TargetUserName=alice",
            "--filter", "LogonType=2",
        )
        assert isinstance(result, dict)
        assert result["TargetUserName"] == "alice"

    def test_filter_id_and_field_filter_combine(self):
        # EventID filter + field filter both applied; 1 result → bare object
        result = self._run(
            str(FIXTURES / "multi_events.xml"),
            "--filter-id", "4624,4625",
            "--filter", "TargetUserName=bob",
        )
        assert isinstance(result, dict)
        assert result["EventID"] == "4625"
