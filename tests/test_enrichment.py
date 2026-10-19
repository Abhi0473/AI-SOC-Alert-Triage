"""Unit tests for src/enrichment.py"""

import os
from src import enrichment


def test_known_malicious_ip_returns_malicious_from_mock_db():
    result = enrichment.get_ip_reputation("185.220.101.50")
    assert result["verdict"] == "malicious"
    assert "c2" in result["categories"] or "malware" in result["categories"]


def test_known_clean_ip_returns_benign():
    result = enrichment.get_ip_reputation("8.8.8.8")
    assert result["verdict"] == "benign"


def test_unlisted_ip_returns_unknown_not_benign():
    """This is the exact distinction reviewer feedback asked for: an IP with
    no threat-intel entry must come back 'unknown', never silently 'benign'."""
    result = enrichment.get_ip_reputation("203.0.113.250")
    assert result["verdict"] == "unknown"
    assert result["verdict"] != "benign"


def test_no_live_api_key_uses_mock_db(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = enrichment.get_ip_reputation("185.220.101.50")
    assert result["source"] == "mock_local_db"


def test_map_mitre_returns_none_for_unknown_rule():
    assert enrichment.map_mitre("nonexistent_rule_id") is None


def test_map_mitre_returns_fixed_technique_for_known_rule():
    mapping = enrichment.map_mitre("suspicious_encoded_powershell")
    assert mapping["technique_id"] == "T1059.001"


def test_enrich_alert_attaches_ip_reputation_and_mitre():
    alert = {
        "destination_ip": "185.220.101.50",
        "fired_rules": [{"rule_id": "suspicious_encoded_powershell"}],
    }
    result = enrichment.enrich_alert(alert)
    assert result["enrichment"]["ip_reputation"]["verdict"] == "malicious"
    assert result["enrichment"]["mitre"][0]["technique_id"] == "T1059.001"


def test_enrich_alert_handles_missing_destination_ip():
    alert = {"destination_ip": None, "fired_rules": []}
    result = enrichment.enrich_alert(alert)
    assert result["enrichment"]["ip_reputation"] is None
