import os
import json
from openai import OpenAI

# llm_client.py
# OpenAI-compatible client abstraction targeting local Ollama by default.
# Enforces temperature=0 and JSON structured output for deterministic triage.

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
# For local Ollama, API key can be a dummy string
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "ollama")
DEFAULT_MODEL = "qwen2.5-coder:14b"

client = OpenAI(
    base_url=OLLAMA_BASE_URL,
    api_key=OLLAMA_API_KEY
)

def query_model(system_prompt: str, user_prompt: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Query the local LLM. 
    Enforces temperature=0 for reproducibility and JSON format.
    """
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0, # Deterministic by default
            seed=42,         # Fixed seed for reproducibility
            response_format={"type": "json_object"} # Structured output only
        )
        
        raw_content = response.choices[0].message.content
        return json.loads(raw_content)
        
    except Exception as e:
        print(f"Error querying LLM {model}: {e}")
        # Return a safe fallback abstention
        return {
            "verdict": "NEEDS_HUMAN_REVIEW",
            "priority": "UNASSIGNED",
            "confidence": 0.0,
            "fix_summary": "LLM query failed or produced invalid JSON.",
            "grounding": {"validated": False, "rejected_claims": [str(e)]}
        }

if __name__ == "__main__":
    # Quick connectivity test
    test_sys = "You output JSON. Respond with a greeting and status."
    test_user = "Hello, are you ready for triage?"
    print(f"Testing connection to {DEFAULT_MODEL} at {OLLAMA_BASE_URL}...")
    res = query_model(test_sys, test_user, "llama3.1:8b") # Test with a smaller model if needed
    print(json.dumps(res, indent=2))
