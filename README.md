# Monitoring configuration

This configuration is a starting point for a local demo. It uses R4's existing metric names. The source metrics are snapshot gauges; therefore do not use `rate()`, counter semantics, p95 latency, or claim long-term trends from a single metrics file. For trends, repeated timestamped scrapes of an exporter are required.

## Run (from this folder)
1. Install Docker + Docker Compose.
2. Copy the actual `artifacts/demo/out/metrics.prom` into this folder as `metrics.prom` or generate a new file using R4's pipeline.
3. Run `docker compose up -d` inside `r5/monitoring/`.
4. Push the metrics file to the local Pushgateway:
   `python3 push_metrics.py metrics.prom http://localhost:9091/metrics/job/pipelinefortress_ai`
5. Open Prometheus at `http://localhost:9090` and Grafana at `http://localhost:3000` (admin/admin for this local demo only; change for any shared environment).
6. In Prometheus, confirm metrics appear; in Grafana, open the provisioned PipelineFortress dashboard.
7. Capture evidence using `r5/evidence/SCREENSHOT_STANDARD.md`.

Do not report the integration as working until these steps have been run and evidence saved. The included Compose setup is local-only.
