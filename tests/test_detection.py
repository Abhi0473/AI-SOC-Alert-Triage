"""Unit tests for src/detection.py"""

import pytest
from src import detection


def _ip_lookup(verdicts):
    """Fake threat_intel_lookup for testing without touching real enrichment."""
    def _lookup(ip):
        return verdicts.get(ip, {"verdict": "unknown", "reputation": "no_data", "categories": []})
    return _lookup


def test_encoded_powershell_fires_on_dash_enc():
    event = {
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
    }
    hit = detection.rule_suspicious_encoded_powershell(event)
    assert hit is not None
    assert hit["rule_id"] == "suspicious_encoded_powershell"


def test_encoded_powershell_fires_on_full_flag_name():
    event = {
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
    }
    assert detection.rule_suspicious_encoded_powershell(event) is not None


def test_encoded_powershell_does_not_fire_on_plain_command():
    event = {
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe Get-Process",
    }
    assert detection.rule_suspicious_encoded_powershell(event) is None


def test_encoded_powershell_does_not_fire_on_non_powershell_process():
    event = {
        "event_type": "process_creation",
        "process": "cmd.exe",
        "command_line": "cmd.exe -enc whatever",
    }
    assert detection.rule_suspicious_encoded_powershell(event) is None


def test_encoded_powershell_ignores_non_process_events():
    event = {
        "event_type": "network_connection",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
    }
    assert detection.rule_suspicious_encoded_powershell(event) is None


def test_outbound_connection_fires_on_malicious_ip():
    event = {"event_type": "network_connection", "destination_ip": "1.2.3.4"}
    lookup = _ip_lookup({"1.2.3.4": {"verdict": "malicious", "reputation": "high_risk", "categories": ["c2"]}})
    hit = detection.rule_suspicious_outbound_connection(event, lookup)
    assert hit is not None
    assert hit["rule_id"] == "suspicious_outbound_connection"


def test_outbound_connection_does_not_fire_on_clean_ip():
    event = {"event_type": "network_connection", "destination_ip": "8.8.8.8"}
    lookup = _ip_lookup({"8.8.8.8": {"verdict": "benign", "reputation": "clean", "categories": []}})
    assert detection.rule_suspicious_outbound_connection(event, lookup) is None


def test_outbound_connection_does_not_fire_with_no_destination_ip():
    event = {"event_type": "network_connection", "destination_ip": None}
    lookup = _ip_lookup({})
    assert detection.rule_suspicious_outbound_connection(event, lookup) is None


def test_unconfirmed_reputation_fires_only_on_unknown_verdict():
    event = {"event_type": "network_connection", "destination_ip": "203.0.113.1"}
    lookup = _ip_lookup({})  # not in dict -> "unknown" per _ip_lookup default
    hit = detection.rule_unconfirmed_reputation_outbound(event, lookup)
    assert hit is not None
    assert hit["rule_id"] == "unconfirmed_reputation_outbound"


def test_unconfirmed_reputation_does_not_fire_on_malicious_or_benign():
    event = {"event_type": "network_connection", "destination_ip": "1.2.3.4"}
    lookup_bad = _ip_lookup({"1.2.3.4": {"verdict": "malicious", "reputation": "high_risk", "categories": []}})
    lookup_clean = _ip_lookup({"1.2.3.4": {"verdict": "benign", "reputation": "clean", "categories": []}})
    assert detection.rule_unconfirmed_reputation_outbound(event, lookup_bad) is None
    assert detection.rule_unconfirmed_reputation_outbound(event, lookup_clean) is None


def test_run_detection_can_fire_multiple_rules_at_once():
    event = {
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
        "destination_ip": "1.2.3.4",
    }
    lookup = _ip_lookup({"1.2.3.4": {"verdict": "malicious", "reputation": "high_risk", "categories": ["c2"]}})
    fired = detection.run_detection(event, lookup)
    fired_ids = {r["rule_id"] for r in fired}
    assert fired_ids == {"suspicious_encoded_powershell", "suspicious_outbound_connection"}


def test_run_detection_returns_empty_for_clean_event():
    event = {
        "event_type": "process_creation",
        "process": "chrome.exe",
        "command_line": "N/A",
        "destination_ip": "8.8.8.8",
    }
    lookup = _ip_lookup({"8.8.8.8": {"verdict": "benign", "reputation": "clean", "categories": []}})
    assert detection.run_detection(event, lookup) == []
