"""
Pipeline orchestrator
----------------------
Raw event -> Detection -> Normalize -> Enrich -> Risk Score -> AI Analysis -> output

This is the single place that defines "how an event actually flows through
the code" (PDF Section 3). Every phase module stays independently testable;
this file just calls them in order.
"""

import json
import os
import time

from . import detection, normalize, enrichment, risk_engine, ai_analyst

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def process_event(raw_event: dict) -> dict:
    fired_rules = detection.run_detection(raw_event, enrichment.get_ip_reputation)

    if not fired_rules:
        # No rule fired -> no alert is generated. This matters for the
        # evaluation script: it's how we'd measure true negatives.
        return None

    alert = normalize.build_alert(raw_event, fired_rules)
    alert = enrichment.enrich_alert(alert)
    alert = risk_engine.score_alert(alert)
    alert = ai_analyst.analyze_alert(alert)
    return alert


def run_pipeline(raw_events_path=None, output_path=None) -> list:
    raw_events_path = raw_events_path or os.path.join(_DATA_DIR, "raw_events.json")
    output_path = output_path or os.path.join(_DATA_DIR, "alerts_output.json")

    with open(raw_events_path) as f:
        raw_events = json.load(f)

    alerts = []
    for event in raw_events:
        start = time.perf_counter()
        alert = process_event(event)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        if alert:
            # Named explicitly to avoid the metric being misread as end-to-end
            # latency: this is detection+enrichment+scoring+AI-layer compute
            # time for ONE event, measured in-process. In mock AI mode this is
            # near-zero; with a live ANTHROPIC_API_KEY it will include real
            # network latency to the Claude API.
            alert["_pipeline_compute_time_ms"] = elapsed_ms
            alerts.append(alert)

    with open(output_path, "w") as f:
        json.dump(alerts, f, indent=2)

    return alerts


if __name__ == "__main__":
    result = run_pipeline()
    print(f"Processed {len(result)} alert(s). Output written to data/alerts_output.json")
