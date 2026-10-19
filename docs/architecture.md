# Architecture

```
Security Telemetry / Dataset (data/raw_events.json)
        |
        v
Detection Rules (src/detection.py)
        |
        v
Alert Normalization (src/normalize.py)
        |
        v
Enrichment (src/enrichment.py)
   +-- IOC Reputation (AbuseIPDB live, or local mock DB)
   +-- MITRE ATT&CK Mapping (fixed lookup table)
        |
        v
Deterministic Risk Scoring (src/risk_engine.py)
        |
        v
AI Analysis (src/ai_analyst.py — Claude, or mock mode)
        |
        v
Analyst Verdict (human-reviewable, set in app.py)
        |
        v
Streamlit Dashboard (app.py)
```

## Component responsibilities

| Component | File | Responsibility |
|---|---|---|
| Detection | `src/detection.py` | Regex/pattern rules over raw events. Auditable, no ML/LLM. |
| Normalization | `src/normalize.py` | Converts a raw event + fired rules into one consistent Alert schema. |
| Enrichment | `src/enrichment.py` | IOC reputation lookup + fixed MITRE technique mapping. |
| Risk Engine | `src/risk_engine.py` | Additive, deterministic scoring. Runs **before** the AI layer. |
| AI Analyst | `src/ai_analyst.py` | Explains evidence + recommends next steps. Cannot change score or MITRE ID. |
| Pipeline | `src/pipeline.py` | Orchestrates the phases above in order for a single event. |
| Dashboard | `app.py` | Alert queue + full evidence-trail detail view; human sets final verdict. |
| Evaluation | `run_evaluation.py` | Runs all scenarios, reports honest TP/FP/FN metrics + failure case. |

## Why the AI sits at the end, not the start

The risk score and MITRE technique are both computed by deterministic code
before the alert ever reaches the LLM. The LLM is handed those results as
fixed context and asked only to explain the evidence and suggest next steps —
it cannot change the score, invent a technique ID, or silently become the
actual decision-maker. See `design-decisions.md` for the full rationale.
