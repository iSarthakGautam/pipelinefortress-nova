import json
import os
import sys

# r3_model_sbom_stub.py
# Produces the MODEL rows R3 needs for the SBOM and docs/LICENSES.md, as a CycloneDX 1.5 fragment built from
# ai/models.lock.yaml. It is a fragment, not R3's SBOM.
# TODO(R3): merge these `components` into the real SBOM (Syft output) and copy the licence rows into
#           docs/LICENSES.md. Verify each licence on the model card; `license_osi_approved` is recorded as given.
#   python3 eval/stubs/r3_model_sbom_stub.py [out_path]

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "ai"))

from llm_client import load_lock


def build() -> dict:
    comps = []
    for m in load_lock():
        digest = str(m.get("digest", ""))
        comp = {"type": "machine-learning-model", "name": m["tag"], "version": m.get("parameters", "unknown"),
                "licenses": [{"license": {"name": m.get("license", "unknown")}}],
                "externalReferences": [{"type": "website", "url": m.get("source_url", "")}],
                "properties": [{"name": "quantisation", "value": str(m.get("quantisation", ""))},
                               {"name": "installed", "value": str(m.get("installed", False)).lower()},
                               {"name": "osi_approved", "value": str(m.get("license_osi_approved", False)).lower()}]}
        if digest.startswith("sha256:") and len(digest) == 71:
            comp["hashes"] = [{"alg": "SHA-256", "content": digest[7:]}]
        comps.append(comp)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps}


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "artifacts", "sbom", "models.cdx.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(build(), open(out, "w"), indent=2)
    print("wrote", os.path.relpath(out))
