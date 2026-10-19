"""
Phase 6: Validation
--------------------
Runs the full pipeline over all labeled scenarios and reports honest metrics:
true positives, false positives, false negatives, AND true negatives (events
that correctly generated no alert at all) -- earlier versions of this script
only looked at generated alerts, which silently excluded true negatives from
the metrics. Also reports risk-score distribution, escalation rate vs ground
truth, and rough per-alert pipeline compute time. No headline "accuracy %" --
see docs/design-decisions.md and PDF Section 8 for why.
"""

import json
import os

from src.pipeline import run_pipeline

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
MALICIOUS_VERDICTS = {"escalate"}


def main():
    with open(os.path.join(DATA_DIR, "raw_events.json")) as f:
        raw_events = {e["event_id"]: e for e in json.load(f)}

    alerts = run_pipeline()
    alerts_by_event_id = {a["source_event_id"]: a for a in alerts}

    tp, fp, fn, tn = 0, 0, 0, 0
    rows = []

    for event_id, event in raw_events.items():
        gt = event["ground_truth_verdict"]                 # "malicious" | "benign"
        actual_malicious = gt == "malicious"
        alert = alerts_by_event_id.get(event_id)

        if alert is None:
            # No rule fired at all -- system implicitly treated this as benign.
            predicted_malicious = False
            ai_verdict, severity, score, compute_ms = "no_alert_generated", "n/a", 0, 0.0
        else:
            ai_verdict = alert["ai_analysis"]["verdict"]
            predicted_malicious = ai_verdict in MALICIOUS_VERDICTS
            severity = alert["risk"]["severity"]
            score = alert["risk"]["score"]
            compute_ms = alert["_pipeline_compute_time_ms"]

        if predicted_malicious and actual_malicious:
            tp += 1
            outcome = "TP"
        elif predicted_malicious and not actual_malicious:
            fp += 1
            outcome = "FP"
        elif not predicted_malicious and actual_malicious:
            fn += 1
            outcome = "FN"
        else:
            tn += 1
            outcome = "TN"

        rows.append({
            "event_id": event_id,
            "alert_id": alert["alert_id"] if alert else "-",
            "host": event["host"],
            "ground_truth": gt,
            "risk_score": score,
            "severity": severity,
            "ai_verdict": ai_verdict,
            "outcome": outcome,
            "pipeline_compute_time_ms": compute_ms,
        })

    print("=" * 96)
    print("SOC AI-ASSISTED TRIAGE -- EVALUATION REPORT")
    print("=" * 96)
    header = f"{'Event ID':<11}{'Alert ID':<16}{'Host':<14}{'GroundTruth':<12}{'Score':<7}{'Severity':<10}{'AI Verdict':<20}{'Outcome':<8}"
    print(header)
    for r in rows:
        print(f"{r['event_id']:<11}{r['alert_id']:<16}{r['host']:<14}{r['ground_truth']:<12}"
              f"{r['risk_score']:<7}{r['severity']:<10}{r['ai_verdict']:<20}{r['outcome']:<8}")

    total = len(rows)
    alerts_generated = len(alerts)
    escalation_rate = sum(1 for r in rows if r["ai_verdict"] == "escalate") / total * 100 if total else 0
    compute_times = [r["pipeline_compute_time_ms"] for r in rows if r["alert_id"] != "-"]
    avg_ms = sum(compute_times) / len(compute_times) if compute_times else 0.0

    print("-" * 96)
    print(f"Total labeled events:        {total}")
    print(f"Alerts generated:            {alerts_generated}  (events where at least one detection rule fired)")
    print(f"True Positives:               {tp}")
    print(f"False Positives:              {fp}")
    print(f"False Negatives:              {fn}")
    print(f"True Negatives:               {tn}  (includes events where no rule fired at all)")
    print(f"Escalation rate:              {escalation_rate:.1f}%  (of all labeled events, small sample -- not a base-rate claim)")
    print(f"Avg pipeline compute time:    {avg_ms:.2f} ms/alert  (detection+enrichment+scoring+AI-layer, in-process; "
          f"near-zero in mock AI mode, includes real network latency only if ANTHROPIC_API_KEY is set)")
    print("=" * 96)

    fps = [r for r in rows if r["outcome"] == "FP"]
    if fps:
        print("\nDOCUMENTED FAILURE CASE(S):")
        for r in fps:
            event = raw_events[r["event_id"]]
            print(f"- {r['alert_id']} ({r['host']}): system marked as '{r['ai_verdict']}' "
                  f"(risk score {r['risk_score']}, severity {r['severity']}), "
                  f"but ground truth is benign.")
            print(f"  Why: {event['ground_truth_notes']}")
            print(f"  Root cause: the encoded-PowerShell rule matches on the -enc flag alone, "
                  f"with no allowlist for known admin automation (e.g. Task-Scheduler-launched "
                  f"service-account scripts). This is why analyst review remains required and "
                  f"the LLM verdict is never auto-applied.")

    fns = [r for r in rows if r["outcome"] == "FN"]
    if fns:
        print("\nDOCUMENTED MISSED DETECTION(S) (false negatives):")
        for r in fns:
            event = raw_events[r["event_id"]]
            print(f"- {r['event_id']} ({r['host']}): ground truth is malicious, but no rule fired "
                  f"or the AI recommended '{r['ai_verdict']}' instead of escalation.")
            print(f"  Notes: {event.get('ground_truth_notes', 'n/a')}")

    # write machine-readable copy for docs/README
    with open(os.path.join(DATA_DIR, "evaluation_results.json"), "w") as f:
        json.dump({"rows": rows, "summary": {
            "total_labeled_events": total,
            "alerts_generated": alerts_generated,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "escalation_rate_pct": round(escalation_rate, 1),
            "avg_pipeline_compute_time_ms": round(avg_ms, 2),
        }}, f, indent=2)


if __name__ == "__main__":
    main()
