import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from redaction.redactor import egress_guard_check

# llm_client.py
# Local-only Ollama client (stdlib urllib, native /api/chat). temperature=0, seed=42.
#   format_mode "schema": Ollama grammar-constrained decoding against ai/schemas/triage_output.schema.json
#   format_mode "json"  : JSON mode (valid JSON, no schema)
#   format_mode "none"  : unconstrained (used as the ablation baseline)
# Safety: every call passes the egress guard; the opener ignores HTTP(S)_PROXY so traffic cannot be rerouted;
# any failure comes back as ok=False so the caller degrades to NEEDS_HUMAN_REVIEW (hard rule 2).
# Error text is returned for the trace only. Callers must not put it in human-facing fields.

# RESOLVED(R1/R4): Model execution in CI runs via local Ollama service (qwen2.5-coder:1.5b on loopback)
#                 with fail-open degradation if offline. OLLAMA_BASE_URL remains loopback.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "ollama")  # unused by Ollama; kept for OpenAI-compatible setups
DEFAULT_MODEL = os.getenv("LLM_MODEL", "llama3.1:8b")
TIMEOUT_S = float(os.getenv("LLM_TIMEOUT", "180"))

AI_DIR = os.path.dirname(os.path.abspath(__file__))
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def native_root(base_url: str = None) -> str:
    """http://host:port/v1  ->  http://host:port"""
    base = (base_url or OLLAMA_BASE_URL).rstrip("/")
    return base[:-3] if base.endswith("/v1") else base


def load_schema() -> dict:
    with open(os.path.join(AI_DIR, "schemas", "triage_output.schema.json"), encoding="utf-8") as f:
        return json.load(f)


def load_lock() -> list:
    """Tiny parser for models.lock.yaml (flat list of scalar maps), so no PyYAML dependency."""
    entries, cur = [], None
    with open(os.path.join(AI_DIR, "models.lock.yaml"), encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith("#") or line.startswith("models:"):
                continue
            stripped = line.strip()
            if stripped.startswith("- "):
                cur = {}
                entries.append(cur)
                stripped = stripped[2:]
            key, _, val = stripped.partition(":")
            val = val.strip().strip('"')
            cur[key.strip()] = {"true": True, "false": False}.get(val, val)
    return entries


def locked_digest(model: str) -> str:
    return next((e.get("digest", "unlocked") for e in load_lock() if e.get("tag") == model), "unlocked")


_live_cache = {}


def live_digest(model: str, base_url: str = None) -> str:
    root = native_root(base_url)
    if (root, model) in _live_cache:
        return _live_cache[(root, model)]
    digest = "unknown"
    try:
        if egress_guard_check(root):
            with _NO_PROXY_OPENER.open(root + "/api/tags", timeout=10) as r:
                for m in json.load(r).get("models", []):
                    if m.get("name") == model:
                        digest = "sha256:" + m.get("digest", "")
    except Exception:
        pass
    _live_cache[(root, model)] = digest
    return digest


def chat(system_prompt: str, user_prompt: str, model: str = None, format_mode: str = "schema",
         expect_json: bool = True, base_url: str = None) -> dict:
    """One model call. Returns {ok, parsed, raw, latency_s, error, model, digest, lock_digest, request_sha256}."""
    model = model or DEFAULT_MODEL
    root = native_root(base_url)
    body = {
        "model": model,
        "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        "stream": False,
        "options": {"temperature": 0, "seed": 42},
    }
    if expect_json and format_mode == "schema":
        body["format"] = load_schema()
    elif expect_json and format_mode == "json":
        body["format"] = "json"
    data = json.dumps(body, sort_keys=True).encode("utf-8")
    result = {"ok": False, "parsed": None, "raw": "", "latency_s": 0.0, "error": None, "model": model,
              "digest": "unknown", "lock_digest": locked_digest(model),
              "request_sha256": hashlib.sha256(data).hexdigest()}

    if not egress_guard_check(root, result["request_sha256"]):
        result["error"] = "egress policy denied"
        return result

    start = time.time()
    try:
        req = urllib.request.Request(root + "/api/chat", data=data, headers={"Content-Type": "application/json"})
        with _NO_PROXY_OPENER.open(req, timeout=TIMEOUT_S) as resp:
            raw = json.loads(resp.read().decode("utf-8"))["message"]["content"]
        result["raw"] = raw
        result["parsed"] = json.loads(raw) if expect_json else raw
        result["ok"] = (not expect_json) or isinstance(result["parsed"], dict)
        if not result["ok"]:
            result["error"] = "model returned JSON that is not an object"
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "ignore")
        except Exception:
            pass
        # Fallback for Ollama versions where ChatRequest.format is string-only ("json"), not schema dict
        if expect_json and format_mode == "schema" and "ChatRequest.format of type string" in detail:
            body["format"] = "json"
            retry_data = json.dumps(body, sort_keys=True).encode("utf-8")
            try:
                req = urllib.request.Request(root + "/api/chat", data=retry_data, headers={"Content-Type": "application/json"})
                with _NO_PROXY_OPENER.open(req, timeout=TIMEOUT_S) as resp:
                    raw = json.loads(resp.read().decode("utf-8"))["message"]["content"]
                result["raw"] = raw
                result["parsed"] = json.loads(raw)
                result["ok"] = isinstance(result["parsed"], dict)
                if not result["ok"]:
                    result["error"] = "model returned JSON that is not an object"
                result["latency_s"] = round(time.time() - start, 3)
                result["digest"] = live_digest(model, base_url) if result["ok"] else result["digest"]
                return result
            except Exception as e2:
                detail = f"{detail} -> fallback failed: {e2}"
        result["error"] = f"HTTPError {e.code}: {detail or e.reason}"
    except (urllib.error.URLError, OSError, TimeoutError, KeyError, ValueError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
    result["latency_s"] = round(time.time() - start, 3)
    result["digest"] = live_digest(model, base_url) if result["ok"] else result["digest"]
    return result


if __name__ == "__main__":
    print(f"Testing {DEFAULT_MODEL} at {native_root()} (egress allowed: {egress_guard_check(native_root())})")
    r = chat('Reply with JSON {"verdict":"NEEDS_HUMAN_REVIEW","confidence":0.5,"fix_summary":"ping","claims":{}}.',
             "ping", format_mode="json")
    print(json.dumps({k: r[k] for k in ("ok", "latency_s", "error", "digest", "lock_digest")}, indent=2))
