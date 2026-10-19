# AI-Assisted SOC Alert Investigation & Triage Platform

A small, complete simulation of a real SOC investigation workflow: raw
telemetry is turned into an alert by a detection rule, the alert is enriched
with threat intelligence and MITRE ATT&CK context, a **deterministic** risk
engine scores it, and only then does an LLM assist by explaining the evidence
and recommending a next step. **A human analyst verdict sits at the end of
the chain — not the AI.**

> This project deliberately uses simulated/public-style datasets, not any
> real production or company data.

## Architecture

```
Telemetry -> Detection Rules -> Normalization -> Enrichment
  (IOC reputation + MITRE ATT&CK) -> Deterministic Risk Scoring
  -> AI Analyst Assistance -> Analyst Verdict -> Streamlit Dashboard
```

See `docs/architecture.md` for the full component breakdown.

## Why this project, not another port scanner

- Matches what real SOC tooling vendors (Splunk AI, Microsoft Security
  Copilot, Google Chronicle) are shipping right now.
- Demoable live in an interview — click an alert, walk through the reasoning.
- Tests every core L1 skill: alert triage, IOC enrichment, MITRE mapping, and
  escalation judgment.
- The AI is constrained and auditable, not a black box making the final call.

## Quickstart

```bash
pip install -r requirements.txt

# Run the unit + integration test suite (39 tests, no API keys needed):
python -m pytest tests/ -v

# Run the pipeline + honest evaluation report (works with zero API keys):
python run_evaluation.py

# Launch the interactive dashboard:
streamlit run app.py
```

Both AI analysis and IOC reputation lookups work out of the box in **mock
mode** — no API keys required, zero cost. To use live services, copy
`.env.example` to `.env` and set:
- `ANTHROPIC_API_KEY` — enables live Claude analysis in `src/ai_analyst.py`
- `ABUSEIPDB_API_KEY` — enables live IP reputation lookups in `src/enrichment.py`

## The six labeled scenarios

| Scenario | What it demonstrates |
|---|---|
| 1. Encoded PowerShell execution → known-bad IP | The full pipeline, endpoint + network signals combined, MITRE T1059.001 |
| 2. Suspicious outbound connection (no PowerShell) | Pure network-based detection, MITRE T1071.001 |
| 3. Benign admin PowerShell script (looks like #1) | **False-positive handling** — the system escalates it, and that failure is documented, not hidden |
| 4. Ordinary browsing to a known-clean IP | True-negative control — no rule fires |
| 5. Plain (non-encoded) interactive PowerShell | True-negative control — the encoded-command rule doesn't over-fire |
| 6. Connection to an IP with zero threat-intel history | "Unknown" is treated as its own category, not silently folded into "benign" |

Full write-up: `docs/investigation-notes.md`.

## Evaluation

No headline accuracy number. Instead, honest metrics from `run_evaluation.py`
across all 6 labeled events — true positives, false positives, false
negatives, **and true negatives** (including events that correctly generate
no alert at all) — plus a fully documented failure case explaining *why* it
happened and what a human analyst would catch that the automated pipeline
didn't.

## Testing

`tests/` has 39 unit and integration tests covering: every detection rule
(including edge cases like a non-PowerShell process using `-enc`, or an event
with no destination IP), the risk-scoring formula and its severity
boundaries, the enrichment layer's malicious/benign/**unknown** distinction,
the AI response schema validator (rejects malformed verdicts, wrong types,
missing fields), and full-pipeline integration tests (true negatives really
produce no alert; the AI layer can never override the MITRE technique or risk
score). Run with `python -m pytest tests/ -v` (the `-m pytest` form avoids
import-path issues the bare `pytest` executable can hit in some environments).

## Design decisions worth asking about in an interview

- Why is risk scored **before** the LLM ever sees the alert? → `docs/design-decisions.md` (Decision 001)
- Why can't the LLM assign its own MITRE technique ID? → Decision 002
- Why Streamlit instead of a custom React frontend? → Decision 003
- Why does the project keep a known false positive instead of "fixing" it? → Decision 005
- What stops a crafted command line from prompt-injecting the AI layer? → Decision 008
- Why does "we have no data on this IP" get its own severity tier instead of being treated as clean? → Decision 009

## Resume bullet

> Built an AI-assisted SOC investigation platform that detects suspicious
> endpoint and network activity, enriches IOCs against threat-intelligence
> sources, maps events to MITRE ATT&CK techniques, calculates deterministic
> risk scores, and generates evidence-backed analyst recommendations through
> an LLM. Evaluated the pipeline against a labeled security-event test set,
> measuring detection performance, false-positive rate, and estimated analyst
> triage-time reduction.

## Project layout

```
soc-ai-triage/
├── .gitignore                 # Keeps secrets and runtime state out of version control
├── .env.example                # Template for optional API keys (copy to .env)
├── app.py                     # Streamlit dashboard (Phase 5)
├── run_evaluation.py          # Evaluation script (Phase 6)
├── src/
│   ├── detection.py           # Phase 1: detection rules
│   ├── normalize.py           # Alert schema normalization
│   ├── enrichment.py          # Phase 2: IOC reputation + MITRE mapping
│   ├── risk_engine.py         # Phase 3: deterministic scoring
│   ├── ai_analyst.py          # Phase 4: LLM analysis (live or mock)
│   └── pipeline.py            # Orchestrates all phases
├── data/
│   ├── raw_events.json        # 6 labeled scenario events (incl. 2 true-negative controls)
│   ├── threat_intel_db.json   # Mock IOC reputation DB
│   ├── mitre_mapping.json     # Fixed rule_id -> MITRE technique table
│   ├── alerts_output.json     # Generated by the pipeline
│   ├── analyst_verdicts.json  # Created automatically by app.py at runtime -- not committed (see .gitignore); contains analyst-session state, not project logic
│   └── evaluation_results.json# Generated by run_evaluation.py
├── tests/                     # 39 pytest unit + integration tests
│   ├── test_detection.py
│   ├── test_enrichment.py
│   ├── test_risk_engine.py
│   ├── test_ai_analyst.py
│   └── test_pipeline.py
└── docs/
    ├── architecture.md
    ├── design-decisions.md    # 10 logged decisions, interview-ready
    ├── detection-rules.md
    └── investigation-notes.md
```

## V2 (future work, not built here)

A correlation engine linking related alerts into a single attack-chain
narrative (e.g. PowerShell execution → C2 communication → credential
access), plus expanded telemetry across endpoint, network, and authentication
sources together.
