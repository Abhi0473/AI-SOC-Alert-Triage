# Detection Rules

## Rule: `suspicious_encoded_powershell`
- **Logic:** `powershell.exe` (or any process containing "powershell") launched
  with `-enc` or `-EncodedCommand` in the command line.
- **Catches:** Attackers commonly base64-encode PowerShell payloads to evade
  simple string-matching AV/EDR signatures and to avoid shell quoting issues
  when delivering multi-line scripts.
- **MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell.
- **Known limitation:** Legitimate admin automation (scheduled tasks, config
  management tools) also uses `-enc` for the exact same "avoid quoting
  headaches" reason. This rule alone cannot tell the two apart — see
  Scenario 3 and `investigation-notes.md`.

## Rule: `suspicious_outbound_connection`
- **Logic:** Any network connection (or process event carrying a destination
  IP) where the destination IP's threat-intel verdict is `malicious`.
- **Catches:** C2 beaconing, connections to known botnet/malware
  infrastructure.
- **MITRE:** T1071.001 — Application Layer Protocol: Web Protocols.
- **Known limitation:** Entirely dependent on threat-intel feed freshness and
  coverage. A brand-new C2 IP with no reputation history will not be flagged
  by this rule alone — this is the kind of gap a correlation engine (V2)
  or additional behavioral rules would help close.

## Rule: `unconfirmed_reputation_outbound`
- **Logic:** A network connection to a destination IP with NO threat-intel
  entry at all (neither confirmed malicious nor confirmed clean).
- **Catches:** Nothing on its own — this is a visibility signal, not a
  suspicious-activity signal. It exists so the pipeline never conflates "we
  checked this IP and it's clean" with "we have no idea about this IP,"
  which V1 originally did (see Decision 009 in `design-decisions.md`).
- **MITRE:** None assigned — there's no attack technique implied by "we lack
  data," so the fixed lookup table intentionally has no entry for this rule.
- **Risk contribution:** +10 only, and it does NOT trigger the +30
  base-severity point the other two rules do (see `risk_engine.py:BASE_SEVERITY_RULES`).
  An alert from this rule alone lands at "low" severity — enough to surface
  it to an analyst, not enough to imply confirmed malicious activity.

## Why three rules for V1
Three to five well-built, explainable rules beat fifty shallow ones for an
entry-level portfolio. Each rule here is simple enough to walk through
line-by-line in an interview, and together they cover an endpoint-based
signal, a confirmed-bad network signal, and an unconfirmed/no-data network
signal — three meaningfully different confidence levels. One rule
(`suspicious_encoded_powershell`) is also used to deliberately demonstrate a
false positive (see `investigation-notes.md`).
