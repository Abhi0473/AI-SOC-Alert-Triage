# Design Decisions Log

This file exists for interview preparation as much as documentation. Every
entry is written the moment the decision is made.

---

### Decision 001 — Deterministic risk scoring before the LLM
**Decision:** Calculate risk before sending the alert to the LLM.
**Why:** Security-critical decisions should not depend entirely on
probabilistic model output.
**Alternative considered:** Letting the LLM directly determine severity.
**Rejected because:** LLMs can hallucinate, behave inconsistently across
runs, and are difficult to audit as the sole decision-maker.
**Result:** `risk_engine.py` produces a deterministic score from observable
signals (encoded PowerShell, malicious IP, critical asset, etc). The LLM in
`ai_analyst.py` receives that score as fixed context and only explains it.

---

### Decision 002 — Constrained MITRE mapping
**Decision:** MITRE ATT&CK techniques are assigned by the enrichment layer
via a fixed lookup table (`data/mitre_mapping.json`), keyed by rule ID — not
by the LLM.
**Why:** The LLM should not invent or freely select ATT&CK technique IDs.
**Alternative considered:** Letting the LLM freely assign any technique ID it
judged fit based on the alert description.
**Rejected because:** This risks hallucinated or inconsistent technique IDs
that would be hard to trust or audit at scale.
**Result:** The LLM can explain a technique it was handed, but the mapping
itself is a static, versioned table anyone can review.

---

### Decision 003 — Streamlit over a custom React frontend
**Decision:** Use Streamlit rather than building a custom web frontend.
**Why:** The project's goal is demonstrating security investigation
functionality, not frontend engineering.
**Alternative considered:** A full custom React/Next.js frontend.
**Rejected because:** It would consume time better spent on detection,
enrichment, and scoring logic, without adding proportional resume value for
a security-analyst role.
**Result:** Development effort stayed on the security pipeline; the UI
(`app.py`) is functional, fast to build, and good enough to demo live.

---

### Decision 004 — Regex-based detection rules, not Sigma/full SIEM rules
**Decision:** Use simple Python regex/pattern rules (`src/detection.py`)
instead of a Sigma rule engine or a real SIEM's correlation language.
**Why:** V1's goal is to demonstrate the *pipeline architecture* end to end,
not to reimplement a SIEM rule engine.
**Alternative considered:** Writing rules in Sigma format and using a Sigma
converter.
**Rejected because:** Adds a dependency and translation layer without adding
proportional resume value at the entry-level stage; the underlying detection
logic (pattern match on -enc, IP reputation check) is identical either way.
**Result:** Rules are ~10 lines of readable Python each, easy to explain line
by line in an interview.

---

### Decision 005 — Deliberately keeping a known false positive in V1
**Decision:** The encoded-PowerShell rule matches on the `-enc` flag alone,
with no allowlist for known-good admin automation. Scenario 3 (a legitimate
Task-Scheduler-launched backup script) deliberately trips this rule.
**Why:** A project that only shows clean detections is less credible than
one that shows how false positives get triaged and why human review still
matters.
**Alternative considered:** Adding a script-hash allowlist so Scenario 3
comes back clean.
**Rejected because:** That would remove the single most valuable interview
talking point in the whole project — see `docs/investigation-notes.md` for
how this specific failure case is documented and explained.
**Result:** `run_evaluation.py` reports this as an honest false positive
rather than hiding it, and the dashboard exposes ground truth (evaluation
only) so the gap between AI verdict and reality is visible.

---

### Decision 006 — Mock mode for both the AI layer and threat intel
**Decision:** Both `ai_analyst.py` and `enrichment.py` fall back to
deterministic mock responses when `ANTHROPIC_API_KEY` / `ABUSEIPDB_API_KEY`
are not set, instead of failing.
**Why:** The project needs to be demoable by anyone (including an
interviewer, with zero setup) at zero cost, while still being wired for real
API calls.
**Alternative considered:** Requiring live API keys to run at all.
**Rejected because:** Adds friction to grading/demoing and couples the
portfolio project's reliability to third-party API uptime and billing.
**Result:** Same code path, same output schema, either mode. Swapping to
live APIs is a one-line environment variable change.

---

### Decision 007 — Reject malformed or out-of-vocabulary AI responses
**Decision:** Every LLM response (live mode) is passed through
`ai_analyst._validate_response()` before it's trusted: `verdict` must be one
of a fixed set, `confidence` must be one of a fixed set, `evidence` and
`recommended_actions` must be non-empty lists of strings.
**Why:** `json.loads()` succeeding only proves the text was valid JSON — not
that it matches the contract the rest of the pipeline (evaluation, dashboard)
assumes. An LLM can return valid JSON with an invented verdict string, a
missing field, or the wrong types.
**Alternative considered:** Trust the parsed JSON directly, as V1 did.
**Rejected because:** A malformed or hallucinated field would silently break
`run_evaluation.py`'s TP/FP counting or crash the dashboard mid-render.
**Result:** Any response that fails validation raises `InvalidAIResponse`,
which is caught in `analyze_alert()` and falls back to the deterministic mock
response — the same graceful-degradation pattern already used for a failed
API call (Decision 006).

---

### Decision 008 — Treat raw telemetry as untrusted data, not instructions
**Decision:** The prompt sent to the LLM separates fixed pipeline metadata
from a clearly delimited `<untrusted_telemetry>` block containing the raw
event fields (command line, process name, etc.), with an explicit system-prompt
instruction to treat that block as data to analyze, never as instructions.
**Why:** Command lines and process names are attacker-controlled input. A
sufficiently crafted command line could otherwise attempt a prompt injection
against the AI layer (e.g. text designed to make the model respond
"close_as_benign" regardless of the evidence).
**Alternative considered:** Interpolate raw fields directly into a single
prose paragraph, as V1 did.
**Rejected because:** Blending trusted context and untrusted data in the same
unstructured text makes injection easier and harder to reason about.
**Result:** Structural separation plus an explicit instruction. This does not
make injection impossible — no prompt-based defense fully does — but it is
the standard mitigation and the schema validation from Decision 007 provides
a second layer: even a successfully-injected response still has to pass
verdict/confidence/evidence-shape validation to be accepted.

---

### Decision 009 — "Unknown" IP reputation is not "confirmed clean"
**Decision:** Added a dedicated `unconfirmed_reputation_outbound` detection
rule and risk-engine signal for destination IPs with zero threat-intel
history, scored much lower (+10, no base severity) than a confirmed-malicious
IP, and reported as its own outcome category in evaluation.
**Why:** V1 let `verdict != "malicious"` cover both "checked and clean" and
"never checked" identically — both produced no alert at all. Those are very
different confidence levels and should not be visually or statistically
indistinguishable.
**Alternative considered:** Leave unknown-reputation IPs unscored, as V1 did.
**Rejected because:** It silently discards a real signal (no intel = no
information, not confirmation of safety) that a real SOC analyst would want
visibility into, especially for brand-new infrastructure a slow-moving
threat-intel feed hasn't caught up to yet.
**Result:** `EVT-1006` (unknown-reputation IP) now generates a low-severity
visibility alert instead of nothing, and `run_evaluation.py` reports it as a
distinct case rather than folding it into "benign, no rule fired."

---

### Decision 010 — Analyst verdicts persist across dashboard sessions
**Decision:** `app.py` reads/writes `data/analyst_verdicts.json` keyed by
alert ID whenever the analyst changes the verdict dropdown.
**Why:** A dashboard that discards the human decision the moment the page
refreshes doesn't actually demonstrate a human-in-the-loop workflow — it
just simulates one for a single session.
**Alternative considered:** Keep it purely in Streamlit session state (V1),
with a comment saying "a real deployment would persist this."
**Rejected because:** For a portfolio project meant to be run and re-opened
by an interviewer, a comment describing the missing feature is weaker than
actually having the feature, and a flat JSON file is a two-line
implementation — there was no good reason to defer it to a hypothetical V2.
**Result:** Verdicts survive `streamlit run app.py` restarts. Still
intentionally NOT a database — that trade-off (fine for a single-analyst demo,
not fine for concurrent multi-analyst use) is itself a good interview answer.
