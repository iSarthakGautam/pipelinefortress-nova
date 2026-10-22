# metrics.py
# Prometheus text-exposition export for R5's dashboard ("AI quality over time"). Write it to a file for the
# node_exporter textfile collector or POST it to a pushgateway; this module does neither, it only renders text.
# Counts are per CLUSTER (what the model judged), plus per-finding totals for the funnel.

PREFIX = "pipelinefortress_ai"

# TODO(R5): choose the ingestion path (textfile collector vs pushgateway) and confirm the metric names/labels you want;
#           eval/stubs/r5_metrics_push_stub.py only validates the text and records the request.


def _rej_type(msg: str) -> str:
    m = msg.lower()
    for key, name in [("cve", "cve"), ("cwe", "cwe"), ("package", "package"), ("fixed_version", "package"),
                      ("file", "location"), ("line", "location"), ("verdict", "verdict")]:
        if key in m:
            return name
    return "other"


def render(results: list, traces: list) -> str:
    out, seen = {}, set()
    cluster_rows = []
    for r in results:
        cid = r["dedupe"]["cluster_id"]
        if cid not in seen:
            seen.add(cid)
            cluster_rows.append(r)
    verdict = {}
    for r in cluster_rows:
        v = r["triage"]["verdict"]
        verdict[v] = verdict.get(v, 0) + 1
    rej = {}
    for r in cluster_rows:
        for c in r["triage"]["grounding"]["rejected_claims"]:
            if not r["triage"]["grounding"]["validated"]:
                rej[_rej_type(c)] = rej.get(_rej_type(c), 0) + 1
    outcomes = {}
    for t in traces:
        outcomes[t["outcome"]] = outcomes.get(t["outcome"], 0) + 1
    lat = [t["latency_s"] for t in traces if t.get("latency_s")]

    lines = []

    def metric(name, help_, typ, samples):
        lines.append(f"# HELP {PREFIX}_{name} {help_}")
        lines.append(f"# TYPE {PREFIX}_{name} {typ}")
        for labels, value in samples:
            lab = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}" if labels else ""
            lines.append(f"{PREFIX}_{name}{lab} {value}")

    metric("findings_total", "Findings received by the triage step", "gauge", [({}, len(results))])
    metric("clusters_total", "Clusters (model calls needed) after dedupe", "gauge", [({}, len(cluster_rows))])
    metric("verdict_total", "Clusters by final verdict (NEEDS_HUMAN_REVIEW = abstentions)", "gauge",
           [({"verdict": k}, v) for k, v in sorted(verdict.items())] or [({"verdict": "none"}, 0)])
    metric("validator_rejections_total", "Model claims dropped by the grounding validator", "gauge",
           [({"type": k}, v) for k, v in sorted(rej.items())] or [({"type": "none"}, 0)])
    metric("outcome_total", "Per-cluster pipeline outcome (ok, injection_detected, pre_egress_tripwire, llm_unavailable_or_malformed...)",
           "gauge", [({"outcome": k}, v) for k, v in sorted(outcomes.items())] or [({"outcome": "none"}, 0)])
    metric("llm_latency_seconds_sum", "Total model latency", "gauge", [({}, round(sum(lat), 3))])
    metric("llm_calls_total", "Model calls made", "gauge", [({}, len(lat))])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render([], []))
