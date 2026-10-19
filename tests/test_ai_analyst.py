"""Unit tests for src/ai_analyst.py -- mostly the schema validator, since the
live API path needs a real key and is exercised manually / in mock mode."""

import pytest
from src.ai_analyst import _validate_response, InvalidAIResponse, _mock_response


VALID = {
    "verdict": "escalate",
    "confidence": "high",
    "evidence": ["Encoded PowerShell observed."],
    "recommended_actions": ["Review the process tree."],
}


def test_valid_response_passes_and_strips_unexpected_keys():
    result = _validate_response({**VALID, "_mode": "should_be_dropped", "extra": "junk"})
    assert result["verdict"] == "escalate"
    assert "_mode" not in result
    assert "extra" not in result


def test_invalid_verdict_value_is_rejected():
    with pytest.raises(InvalidAIResponse):
        _validate_response({**VALID, "verdict": "definitely_malicious"})


def test_invalid_confidence_value_is_rejected():
    with pytest.raises(InvalidAIResponse):
        _validate_response({**VALID, "confidence": "extremely_sure"})


def test_missing_evidence_is_rejected():
    bad = {**VALID}
    del bad["evidence"]
    with pytest.raises(InvalidAIResponse):
        _validate_response(bad)


def test_empty_evidence_list_is_rejected():
    with pytest.raises(InvalidAIResponse):
        _validate_response({**VALID, "evidence": []})


def test_non_string_evidence_items_rejected():
    with pytest.raises(InvalidAIResponse):
        _validate_response({**VALID, "evidence": [{"nested": "object"}]})


def test_non_dict_top_level_is_rejected():
    with pytest.raises(InvalidAIResponse):
        _validate_response(["not", "a", "dict"])


def test_mock_response_always_passes_the_same_validator():
    """The mock path should produce output that would also satisfy the live
    schema contract -- keeps both modes honest against the same rules."""
    alert = {
        "risk": {"score": 80, "severity": "high", "breakdown": {"base_severity": 30}},
        "fired_rules": [{"rule_id": "suspicious_encoded_powershell", "rule_name": "x", "description": "encoded ps"}],
        "enrichment": {"ip_reputation": {"verdict": "malicious", "categories": ["c2"]}, "mitre": []},
        "destination_ip": "1.2.3.4",
        "critical_asset": False,
    }
    mock = _mock_response(alert)
    validated = _validate_response(mock)
    assert validated["verdict"] == "escalate"
