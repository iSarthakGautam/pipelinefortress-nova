#!/usr/bin/env python3
"""Policy verifier fallback when conftest binary or Docker is not installed.
Implements the 10 CIS Kubernetes Benchmark 5.2.x / 5.7 rules from infra/policy/k8s.rego.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load_manifest(filepath: Path) -> dict:
    """Load deployment manifest via PyYAML if available, or lightweight line parser."""
    try:
        import yaml
        content = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        if not isinstance(content, dict):
            return {}
        pod_template = content.get("spec", {}).get("template", {}).get("spec", {})
        pod_sc = pod_template.get("securityContext", {}) or {}
        raw_containers = pod_template.get("containers", []) or []
        containers = []
        for rc in raw_containers:
            sc = rc.get("securityContext", {}) or {}
            caps = sc.get("capabilities", {}) or {}
            drop = caps.get("drop", []) or []
            res = rc.get("resources", {}) or {}
            limits = res.get("limits", {}) or {}
            containers.append({
                "name": rc.get("name", ""),
                "image": rc.get("image", ""),
                "securityContext": sc,
                "limits": limits,
                "capabilities_drop": drop,
            })
        return {
            "kind": content.get("kind", ""),
            "pod_securityContext": pod_sc,
            "containers": containers
        }
    except ImportError:
        pass

    # Lightweight regex/line parser fallback without external dependencies
    content = filepath.read_text(encoding="utf-8")
    data = {
        "kind": "",
        "pod_securityContext": {},
        "containers": []
    }
    mode = None
    submode = None
    current_container = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))

        if stripped.startswith("kind:"):
            data["kind"] = stripped.split(":", 1)[1].strip()
            continue

        if indent <= 6:
            if stripped == "securityContext:" and indent == 6:
                mode = "pod_sc"
            elif stripped == "containers:" and indent == 6:
                mode = "containers"
            else:
                mode = None
            submode = None
            continue

        if mode == "pod_sc":
            if ":" in stripped:
                k, v = [x.strip() for x in stripped.split(":", 1)]
                data["pod_securityContext"][k] = (v.lower() == "true") if v.lower() in ("true", "false") else v
            continue

        if mode == "containers":
            if indent == 8 and stripped.startswith("- name:"):
                current_container = {
                    "name": stripped.split(":", 1)[1].strip(),
                    "image": "",
                    "securityContext": {},
                    "limits": {},
                    "capabilities_drop": []
                }
                data["containers"].append(current_container)
                submode = None
                continue

            if not current_container:
                continue

            if indent == 10:
                if stripped.startswith("image:"):
                    current_container["image"] = stripped.split(":", 1)[1].strip()
                    submode = None
                elif stripped == "securityContext:":
                    submode = "c_sc"
                elif stripped == "resources:":
                    submode = "resources"
                else:
                    submode = None
                continue

            if submode == "c_sc":
                if indent == 12:
                    if stripped == "capabilities:":
                        submode = "c_caps"
                    elif ":" in stripped:
                        k, v = [x.strip() for x in stripped.split(":", 1)]
                        current_container["securityContext"][k] = (v.lower() == "true") if v.lower() in ("true", "false") else v
            elif submode == "c_caps":
                if indent > 12 and stripped.startswith("- "):
                    current_container["capabilities_drop"].append(stripped[2:].strip())
                elif indent <= 12:
                    submode = "c_sc"
            elif submode == "resources":
                if indent == 12 and stripped == "limits:":
                    submode = "limits"
            elif submode == "limits":
                if indent > 12 and ":" in stripped:
                    k, v = [x.strip().strip("\"'") for x in stripped.split(":", 1)]
                    current_container["limits"][k] = v
                elif indent <= 12:
                    submode = "resources"

    return data


def evaluate_policy(data: dict) -> list[str]:
    violations = []
    if data.get("kind") != "Deployment":
        return violations

    pod_sc = data.get("pod_securityContext", {})
    containers = data.get("containers", [])

    for c in containers:
        name = c.get("name", "unknown")
        c_sc = c.get("securityContext", {})

        # CIS 5.2.1: container is privileged
        if c_sc.get("privileged") is True:
            violations.append(f"{name}: container is privileged (CIS 5.2.1)")

        # CIS 5.2.6: runAsNonRoot is not true at pod or container level
        if not (pod_sc.get("runAsNonRoot") is True or c_sc.get("runAsNonRoot") is True):
            violations.append(f"{name}: runAsNonRoot is not true at pod or container level (CIS 5.2.6)")

        # CIS 5.2.6: runAsNonRoot is explicitly false
        if c_sc.get("runAsNonRoot") is False:
            violations.append(f"{name}: runAsNonRoot is explicitly false (CIS 5.2.6)")

        # CIS 5.2.4: root filesystem is writable
        if not (c_sc.get("readOnlyRootFilesystem") is True):
            violations.append(f"{name}: root filesystem is writable (CIS 5.2.4)")

        # CIS 5.2.5: allowPrivilegeEscalation is not false
        if not (c_sc.get("allowPrivilegeEscalation") is False):
            violations.append(f"{name}: allowPrivilegeEscalation is not false (CIS 5.2.5)")

        # CIS 5.2.9: capabilities.drop does not include ALL
        if "ALL" not in c.get("capabilities_drop", []):
            violations.append(f"{name}: capabilities.drop does not include ALL (CIS 5.2.9)")

        # Resources: memory & cpu limits
        limits = c.get("limits", {})
        if not limits.get("memory"):
            violations.append(f"{name}: no memory limit")
        if not limits.get("cpu"):
            violations.append(f"{name}: no cpu limit")

        # Image tag
        image = c.get("image", "")
        if image.endswith(":latest"):
            violations.append(f"{name}: image uses the mutable :latest tag")
        elif ":" not in image and "@" not in image:
            violations.append(f"{name}: image has no tag or digest (defaults to latest)")

    return violations


def main() -> int:
    hardened_path = ROOT / "infra/k8s/deployment.hardened.yaml"
    bad_path = ROOT / "infra/k8s/deployment.yaml"

    print("--> Running Rego policy checks via Python policy verifier (k8s.rego mirror)...")
    
    hardened_data = load_manifest(hardened_path)
    hardened_violations = evaluate_policy(hardened_data)
    
    bad_data = load_manifest(bad_path)
    bad_violations = evaluate_policy(bad_data)

    if hardened_violations:
        print(f"❌ Hardened manifest failed policy check with {len(hardened_violations)} violations:")
        for v in hardened_violations:
            print(f"   - {v}")
        return 1

    if not bad_violations:
        print("❌ Planted bad manifest unexpectedly passed policy check!")
        return 1

    print(f"✅ Rego policy verification passed: hardened passes 10/10, bad manifest fails {len(bad_violations)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

