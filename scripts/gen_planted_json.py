import json
from pathlib import Path

def convert_planted():
    lines = Path("ground_truth/planted.yaml").read_text(encoding="utf-8").splitlines()
    entries = []
    cur = None
    in_list = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 2 and stripped.startswith("- id:"):
            cur = {"id": stripped.split(":", 1)[1].strip().strip("\"'")}
            entries.append(cur)
            in_list = None
        elif cur is not None:
            if indent == 4 and ":" in stripped:
                k, v = [x.strip() for x in stripped.split(":", 1)]
                v = v.strip("\"'")
                if v == "[]":
                    cur[k] = []
                    in_list = None
                elif not v:
                    if k == "location":
                        cur[k] = {}
                        in_list = "location"
                    else:
                        cur[k] = []
                        in_list = k
                else:
                    if v.isdigit():
                        cur[k] = int(v)
                    elif v.lower() == "true":
                        cur[k] = True
                    elif v.lower() == "false":
                        cur[k] = False
                    else:
                        cur[k] = v
                    in_list = None
            elif indent == 6:
                if in_list == "location" and ":" in stripped:
                    k, v = [x.strip() for x in stripped.split(":", 1)]
                    v = v.strip("\"'")
                    cur["location"][k] = int(v) if v.isdigit() else v
                elif in_list and stripped.startswith("- "):
                    val = stripped[2:].strip().strip("\"'")
                    cur[in_list].append(val)

    Path("ground_truth/planted.json").write_text(json.dumps({"planted_vulnerabilities": entries}, indent=2), encoding="utf-8")
    print(f"Generated ground_truth/planted.json with {len(entries)} items")

if __name__ == "__main__":
    convert_planted()
