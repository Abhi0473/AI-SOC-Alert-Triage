"""Unit tests for src/risk_engine.py"""

from src.risk_engine import score_alert


def _base_alert(fired_rules, ip_verdict="benign", categories=None, critical_asset=False):
    return {
        "fired_rules": fired_rules,
        "critical_asset": critical_asset,
        "enrichment": {
            "ip_reputation": {
                "verdict": ip_verdict,
                "reputation": "n/a",
                "categories": categories or [],
            }
        },
    }


def test_no_rules_fired_scores_zero_low():
    alert = _base_alert([])
    result = score_alert(alert)
    assert result["risk"]["score"] == 0
    assert result["risk"]["severity"] == "low"


def test_encoded_powershell_alone():
    alert = _base_alert([{"rule_id": "suspicious_encoded_powershell"}])
    result = score_alert(alert)
    # base_severity (30) + encoded_powershell (20) = 50 -> medium
    assert result["risk"]["score"] == 50
    assert result["risk"]["severity"] == "medium"


def test_encoded_powershell_plus_malicious_c2_ip_is_critical_with_critical_asset():
    alert = _base_alert(
        [{"rule_id": "suspicious_encoded_powershell"}],
        ip_verdict="malicious",
        categories=["c2"],
        critical_asset=True,
    )
    result = score_alert(alert)
    # base(30) + malicious_ip(25) + c2(20) + encoded_ps(20) + critical_asset(15) = 110
    assert result["risk"]["score"] == 110
    assert result["risk"]["severity"] == "critical"


def test_unconfirmed_reputation_alone_does_not_trigger_base_severity():
    alert = _base_alert([{"rule_id": "unconfirmed_reputation_outbound"}], ip_verdict="unknown")
    result = score_alert(alert)
    # unconfirmed_reputation (10) only, no base_severity -> low, and specifically NOT
    # scored the same as a confirmed-malicious or confirmed-clean IP.
    assert result["risk"]["score"] == 10
    assert result["risk"]["severity"] == "low"
    assert "base_severity" not in result["risk"]["breakdown"]


def test_malicious_ip_without_c2_category_gets_no_c2_bonus():
    alert = _base_alert(
        [{"rule_id": "suspicious_outbound_connection"}],
        ip_verdict="malicious",
        categories=["phishing"],
    )
    result = score_alert(alert)
    assert "known_c2_indicator" not in result["risk"]["breakdown"]
    # base(30) + malicious_ip(25) = 55 -> medium
    assert result["risk"]["score"] == 55
    assert result["risk"]["severity"] == "medium"


def test_severity_thresholds_are_inclusive_of_boundaries():
    # exactly 30 -> low, exactly 31 -> medium, exactly 60 -> medium, exactly 61 -> high
    from src.risk_engine import _severity_from_score
    assert _severity_from_score(30) == "low"
    assert _severity_from_score(31) == "medium"
    assert _severity_from_score(60) == "medium"
    assert _severity_from_score(61) == "high"
    assert _severity_from_score(85) == "high"
    assert _severity_from_score(86) == "critical"
