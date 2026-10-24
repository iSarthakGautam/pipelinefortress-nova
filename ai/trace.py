import hashlib
import json
import os
import time

# trace.py
# Append-only, hash-chained replay log (PLAN rule 6: everything replayable).
# One line per LLM call: prompt sha256, model + digest, raw response, validator verdict.
# Each line carries the sha256 of the previous line, so deleting or editing history is detectable.
# Off unless a trace dir is given (arg or LLM_TRACE_DIR); `make triage` turns it on.

TRACE_FILE = "trace.jsonl"
REJECTION_FILE = "rejections.jsonl"
_GENESIS = "0" * 64


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _append(path: str, record: dict) -> None:
    prev = _GENESIS
    if os.path.exists(path):
        with open(path, "rb") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        if lines:
            prev = hashlib.sha256(lines[-1]).hexdigest()
    record = dict(record, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), prev_hash=prev)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def trace_dir(explicit=None):
    return explicit or os.getenv("LLM_TRACE_DIR") or None


def write_trace(record: dict, directory=None) -> None:
    d = trace_dir(directory)
    if not d:
        return
    os.makedirs(d, exist_ok=True)
    _append(os.path.join(d, TRACE_FILE), record)


def write_rejection(record: dict, directory=None) -> None:
    d = trace_dir(directory)
    if not d:
        return
    os.makedirs(d, exist_ok=True)
    _append(os.path.join(d, REJECTION_FILE), record)


def verify_chain(path: str) -> bool:
    """True if every line's prev_hash matches the sha256 of the line before it."""
    prev = _GENESIS
    with open(path, "rb") as f:
        for raw in f.read().splitlines():
            if not raw.strip():
                continue
            if json.loads(raw).get("prev_hash") != prev:
                return False
            prev = hashlib.sha256(raw).hexdigest()
    return True


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        write_trace({"n": 1}, d)
        write_trace({"n": 2}, d)
        print("chain valid:", verify_chain(os.path.join(d, TRACE_FILE)))
