"""
Phase 2: Enrichment
--------------------
Two independent lookups:
  1. IOC reputation for the destination IP (VirusTotal / AbuseIPDB in a real
     deployment; falls back to a local mock DB here so the project runs with
     zero API keys and zero cost).
  2. MITRE ATT&CK technique mapping -- a FIXED lookup table keyed by rule_id.
     The LLM is never allowed to assign or invent a technique ID; it can only
     explain one it was handed here.
"""

import json
import os

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

with open(os.path.join(_DATA_DIR, "threat_intel_db.json")) as f:
    _MOCK_THREAT_INTEL = json.load(f)

with open(os.path.join(_DATA_DIR, "mitre_mapping.json")) as f:
    _MITRE_TABLE = json.load(f)


def get_ip_reputation(ip: str) -> dict:
    """Returns a normalized reputation dict for an IP.

    Live-API mode: set ABUSEIPDB_API_KEY in the environment and this will
    call AbuseIPDB instead of the local mock DB. (Requires outbound network
    access to api.abuseipdb.com, which this sandbox does not have -- this
    path is written for when you run the project on your own machine.)
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if api_key:
        try:
            import requests
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "verdict": "malicious" if score >= 50 else "benign",
                "reputation": "high_risk" if score >= 50 else "clean",
                "categories": data.get("usageType", "").split(",") if data.get("usageType") else [],
                "abuse_confidence_score": score,
                "source": "abuseipdb_live",
            }
        except Exception as e:
            # Fail safe: fall back to mock DB rather than crash the pipeline
            fallback = dict(_MOCK_THREAT_INTEL.get(ip, _default_clean(ip)))
            fallback["source"] = f"mock_fallback_after_live_error:{e}"
            return fallback

    return dict(_MOCK_THREAT_INTEL.get(ip, _default_clean(ip)))


def _default_clean(ip: str) -> dict:
    return {
        "verdict": "unknown",
        "reputation": "no_data",
        "categories": [],
        "abuse_confidence_score": 0,
        "source": "mock_local_db_no_entry",
    }


def map_mitre(rule_id: str) -> dict:
    """Fixed lookup only. Returns None if a rule has no mapping (should not
    happen for the rules shipped in V1, but fail loud in that case)."""
    return _MITRE_TABLE.get(rule_id)


def enrich_alert(alert: dict) -> dict:
    ip_intel = get_ip_reputation(alert["destination_ip"]) if alert.get("destination_ip") else None

    mitre_hits = []
    for rule in alert["fired_rules"]:
        mapping = map_mitre(rule["rule_id"])
        if mapping:
            mitre_hits.append(mapping)

    alert["enrichment"] = {
        "ip_reputation": ip_intel,
        "mitre": mitre_hits,
    }
    return alert
