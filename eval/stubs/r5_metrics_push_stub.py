import os
import re
import sys

# r5_metrics_push_stub.py
# STAND-IN for R5's metrics ingestion. It validates metrics.prom as Prometheus text and writes the request a
# pushgateway push would make. It never opens a network connection.
# RESOLVED(R5): Pushgateway path selected (eval/metrics/push_metrics.py); metric catalogue confirmed.
#              This stub remains for offline local validation of Prometheus text without network connections.
#   python3 eval/stubs/r5_metrics_push_stub.py <metrics.prom> <out_dir>

LINE = re.compile(r'^(#.*|[a-z_]+(\{[a-z_]+="[^"]*"(,[a-z_]+="[^"]*")*\})? -?[0-9.]+)$')
JOB_URL = "http://localhost:9091/metrics/job/pipelinefortress_ai"


def main():
    src, out_dir = sys.argv[1], sys.argv[2]
    text = open(src, encoding="utf-8").read()
    bad = [ln for ln in text.splitlines() if ln.strip() and not LINE.match(ln)]
    if bad:
        print(f"[R5 stub] INVALID Prometheus line: {bad[0]!r}", file=sys.stderr)
        sys.exit(1)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "pushgateway_request_stub.txt"), "w", encoding="utf-8") as f:
        f.write(f"WOULD POST {JOB_URL}\n\n{text}")
    print(f"[R5 stub] {sum(1 for l in text.splitlines() if l and not l.startswith('#'))} samples validated")


if __name__ == "__main__":
    main()
