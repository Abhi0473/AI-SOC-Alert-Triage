"""
Normalization
-------------
Turns a raw telemetry event + the rules that fired on it into a single,
consistent Alert JSON schema that every downstream phase (enrichment, risk
engine, AI layer, dashboard) can rely on without guessing field names.
"""

from datetime import datetime, timezone


def build_alert(event: dict, fired_rules: list) -> dict:
    return {
        "alert_id": f"ALERT-{event['event_id']}",
        "source_event_id": event["event_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "original_timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "user": event.get("user"),
        "process": event.get("process"),
        "parent_process": event.get("parent_process"),
        "command_line": event.get("command_line"),
        "destination_ip": event.get("destination_ip"),
        "critical_asset": bool(event.get("critical_asset", False)),
        "fired_rules": fired_rules,          # list of {rule_id, rule_name, description}
        "ground_truth_verdict": event.get("ground_truth_verdict"),   # kept ONLY for evaluation, never shown to the LLM
        "ground_truth_notes": event.get("ground_truth_notes"),
        # populated by later phases:
        "enrichment": None,
        "risk": None,
        "ai_analysis": None,
        "analyst_verdict": "pending_review",
    }
