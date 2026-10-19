"""
Phase 1: Detection Rules
-------------------------
Small, explainable, regex/pattern-based rules. No ML, no LLM here on purpose --
this layer has to be auditable and cheap to explain in an interview.

Each rule returns either None (no match) or a dict describing what fired and why.
Multiple rules may fire on the same raw event.
"""

import re

ENCODED_PS_PATTERN = re.compile(r"-enc(odedcommand)?\b", re.IGNORECASE)


def rule_suspicious_encoded_powershell(event: dict):
    """Flags any powershell.exe process launched with -enc / -EncodedCommand.

    Deliberately simplistic: this rule does NOT try to distinguish admin
    automation from an attacker yet -- that nuance is supposed to come from
    enrichment/context and, ultimately, analyst judgment. Scenario 3 is built
    specifically to demonstrate that this rule alone produces a false positive.
    """
    if event.get("event_type") != "process_creation":
        return None
    if "powershell" not in (event.get("process") or "").lower():
        return None
    if not ENCODED_PS_PATTERN.search(event.get("command_line") or ""):
        return None

    return {
        "rule_id": "suspicious_encoded_powershell",
        "rule_name": "Suspicious Encoded PowerShell Execution",
        "description": (
            f"Process '{event.get('process')}' was launched with an encoded "
            f"command argument (-enc / -EncodedCommand)."
        ),
    }


def rule_suspicious_outbound_connection(event: dict, threat_intel_lookup):
    """Flags a network connection to a destination IP with a bad reputation.

    threat_intel_lookup: callable(ip) -> dict (see enrichment.get_ip_reputation)
    Kept dependency-injected so detection stays testable without hitting any API.
    """
    dest_ip = event.get("destination_ip")
    if not dest_ip:
        return None
    if event.get("event_type") not in ("network_connection", "process_creation"):
        return None

    intel = threat_intel_lookup(dest_ip)
    if intel.get("verdict") != "malicious":
        return None

    return {
        "rule_id": "suspicious_outbound_connection",
        "rule_name": "Suspicious Outbound Connection",
        "description": (
            f"Connection observed to {dest_ip}, which threat intelligence "
            f"rates as '{intel.get('reputation')}' "
            f"(categories: {', '.join(intel.get('categories', [])) or 'n/a'})."
        ),
    }


def rule_unconfirmed_reputation_outbound(event: dict, threat_intel_lookup):
    """Flags an outbound connection to an IP with NO threat-intel coverage at all.

    This is a deliberately separate, lower-confidence rule from
    `rule_suspicious_outbound_connection`. Reviewer feedback on V1 correctly
    pointed out that treating "unknown reputation" the same as "confirmed
    clean" (i.e. generating no alert either way) hides a real gap: an IP with
    zero threat-intel history is not the same thing as an IP that has been
    checked and found clean. This rule makes that distinction visible to the
    analyst instead of silently dropping it.
    """
    dest_ip = event.get("destination_ip")
    if not dest_ip:
        return None
    if event.get("event_type") not in ("network_connection", "process_creation"):
        return None

    intel = threat_intel_lookup(dest_ip)
    if intel.get("verdict") != "unknown":
        return None

    return {
        "rule_id": "unconfirmed_reputation_outbound",
        "rule_name": "Outbound Connection to Unconfirmed-Reputation IP",
        "description": (
            f"Connection observed to {dest_ip}, which has NO threat-intel "
            f"history (neither confirmed malicious nor confirmed clean). "
            f"Flagged for visibility, not treated as confirmed-bad."
        ),
    }


ALL_RULES = [
    rule_suspicious_encoded_powershell,
    # rule_suspicious_outbound_connection is invoked separately in pipeline.py
    # because it needs the threat_intel_lookup dependency injected.
]


def run_detection(event: dict, threat_intel_lookup) -> list:
    """Runs every detection rule against a single normalized-ish raw event.
    Returns a list of fired-rule dicts (may be empty -> event stays un-alerted).
    """
    fired = []

    hit = rule_suspicious_encoded_powershell(event)
    if hit:
        fired.append(hit)

    hit = rule_suspicious_outbound_connection(event, threat_intel_lookup)
    if hit:
        fired.append(hit)

    hit = rule_unconfirmed_reputation_outbound(event, threat_intel_lookup)
    if hit:
        fired.append(hit)

    return fired
