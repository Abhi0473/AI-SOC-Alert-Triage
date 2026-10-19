"""Integration tests for src/pipeline.py against the real dataset."""

import os
from src.pipeline import run_pipeline


def test_pipeline_generates_no_alert_for_true_negative_events():
    """EVT-1004 (clean browsing) and EVT-1005 (plain, non-encoded PowerShell)
    are true-negative controls -- no detection rule should fire on either."""
    alerts = run_pipeline()
    alerted_source_ids = {a["source_event_id"] for a in alerts}
    assert "EVT-1004" not in alerted_source_ids
    assert "EVT-1005" not in alerted_source_ids


def test_pipeline_generates_low_severity_alert_for_unknown_reputation_ip():
    """EVT-1006 has an IP with no threat-intel entry. It SHOULD generate a
    visibility alert (not silence), but at low severity, and it must not be
    scored/treated the same as a confirmed-malicious IP."""
    alerts = run_pipeline()
    evt_1006 = next((a for a in alerts if a["source_event_id"] == "EVT-1006"), None)
    assert evt_1006 is not None, "expected a low-confidence visibility alert for the unknown-reputation IP"
    assert evt_1006["risk"]["severity"] == "low"
    assert evt_1006["enrichment"]["ip_reputation"]["verdict"] == "unknown"


def test_pipeline_flags_scenario1_as_high_or_critical():
    alerts = run_pipeline()
    evt_1001 = next(a for a in alerts if a["source_event_id"] == "EVT-1001")
    assert evt_1001["risk"]["severity"] in ("high", "critical")
    assert evt_1001["ai_analysis"]["verdict"] == "escalate"


def test_every_generated_alert_has_a_valid_ai_analysis_shape():
    alerts = run_pipeline()
    for alert in alerts:
        ai = alert["ai_analysis"]
        assert ai["verdict"] in {"escalate", "monitor", "close_as_benign"}
        assert ai["confidence"] in {"low", "medium", "high"}
        assert isinstance(ai["evidence"], list) and ai["evidence"]
        assert isinstance(ai["recommended_actions"], list) and ai["recommended_actions"]


def test_pipeline_never_lets_ai_layer_override_mitre_or_score():
    """The MITRE technique and risk score on the alert object must come only
    from enrichment/risk_engine -- ai_analysis has no keys that could
    overwrite them, and this test locks that contract in place."""
    alerts = run_pipeline()
    for alert in alerts:
        assert "mitre" not in alert["ai_analysis"]
        assert "score" not in alert["ai_analysis"]
        assert "severity" not in alert["ai_analysis"]
