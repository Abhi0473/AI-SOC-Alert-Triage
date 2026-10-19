"""
Phase 3: Deterministic Risk Scoring
------------------------------------
THE most important design decision in the project: this score is computed
BEFORE the alert ever reaches the LLM, from purely observable signals. The
LLM never independently decides whether something is malicious -- it receives
this score as fixed context.

Additive point scale (see docs/design-decisions.md, Decision 001):
    Base severity (encoded PS or malicious IP rule fired)  +30
    Malicious IP reputation          +25
    Encoded PowerShell               +20
    Known C2 indicator               +20
    Repeated activity (placeholder)  +10
    Unconfirmed IP reputation        +10  (no threat-intel history either way -- not the same as confirmed-clean)
    Critical asset involved          +15

Thresholds:
    0-30   -> Low
    31-60  -> Medium
    61-85  -> High
    86+    -> Critical
"""

SEVERITY_THRESHOLDS = [
    (30, "low"),
    (60, "medium"),
    (85, "high"),
    (float("inf"), "critical"),
]


def _severity_from_score(score: int) -> str:
    for ceiling, label in SEVERITY_THRESHOLDS:
        if score <= ceiling:
            return label
    return "critical"


#: Rules serious enough on their own to warrant the +30 base-severity point.
#: The unconfirmed-reputation rule is deliberately excluded -- "we have no
#: data on this IP" is a visibility signal, not a suspicious-activity signal,
#: and should not be scored as if it were.
BASE_SEVERITY_RULES = {"suspicious_encoded_powershell", "suspicious_outbound_connection"}


def score_alert(alert: dict) -> dict:
    breakdown = {}
    fired_rule_ids = {r["rule_id"] for r in alert["fired_rules"]}
    ip_intel = (alert.get("enrichment") or {}).get("ip_reputation") or {}

    if fired_rule_ids & BASE_SEVERITY_RULES:
        breakdown["base_severity"] = 30

    if "unconfirmed_reputation_outbound" in fired_rule_ids:
        breakdown["unconfirmed_reputation"] = 10

    if ip_intel.get("verdict") == "malicious":
        breakdown["malicious_ip_reputation"] = 25
        if "c2" in ip_intel.get("categories", []) or "botnet" in ip_intel.get("categories", []):
            breakdown["known_c2_indicator"] = 20

    if "suspicious_encoded_powershell" in fired_rule_ids:
        breakdown["encoded_powershell"] = 20

    # Placeholder for a real "repeated activity" check (e.g. same host/user
    # firing the same rule N times in a window) -- out of scope for V1's
    # single-event pipeline, kept here so the formula matches docs and V2 can
    # wire it up without changing the scoring contract.
    # breakdown["repeated_activity"] = 10

    if alert.get("critical_asset"):
        breakdown["critical_asset_involved"] = 15

    total = sum(breakdown.values())
    severity = _severity_from_score(total)

    alert["risk"] = {
        "score": total,
        "severity": severity,
        "breakdown": breakdown,
    }
    return alert
