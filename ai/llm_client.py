import os
import json
import urllib.request
import urllib.error

# llm_client.py
# OpenAI-compatible client abstraction targeting local Ollama by default.
# Enforces temperature=0 and JSON structured output for deterministic triage.
# Uses urllib as fallback if openai package is not installed.

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "ollama")
DEFAULT_MODEL = os.getenv("LLM_MODEL", "llama3.1:8b")

try:
    from openai import OpenAI
    client = OpenAI(base_url=OLLAMA_BASE_URL, api_key=OLLAMA_API_KEY)
    USE_SDK = True
except ImportError:
    client = None
    USE_SDK = False

def query_model(system_prompt: str, user_prompt: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Query the local LLM.
    Enforces temperature=0 for reproducibility and JSON format.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.0,
        "seed": 42,
        "response_format": {"type": "json_object"}
    }

    try:
        if USE_SDK and client:
            response = client.chat.completions.create(**payload)
            raw_content = response.choices[0].message.content
            return json.loads(raw_content)
        else:
            # Native HTTP fallback via urllib
            req_url = f"{OLLAMA_BASE_URL.rstrip('/')}/chat/completions"
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                req_url,
                data=data,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {OLLAMA_API_KEY}"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                raw_content = resp_json["choices"][0]["message"]["content"]
                return json.loads(raw_content)

    except Exception as e:
        # Safe fallback abstention as mandated by the rubric
        return {
            "verdict": "NEEDS_HUMAN_REVIEW",
            "priority": "UNASSIGNED",
            "confidence": 0.0,
            "fix_summary": f"LLM triage fallback: {e}",
            "grounding": {"validated": False, "rejected_claims": [str(e)]}
        }

if __name__ == "__main__":
    test_sys = "You output JSON. Respond with a greeting and status."
    test_user = "Hello, are you ready for triage?"
    print(f"Testing connection to {DEFAULT_MODEL} at {OLLAMA_BASE_URL}...")
    res = query_model(test_sys, test_user, DEFAULT_MODEL)
    print(json.dumps(res, indent=2))
