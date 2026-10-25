import json
import os
import re

# validate.py
# Grounding validator: the deterministic gate between the model's output and anything a human sees.
# It validates what the MODEL claims (triage.claims plus identifiers mentioned in fix_summary), not what
# the scanner reported. A claim survives only if it is proven by (a) the scanner record for this finding,
# or (b) an offline catalogue. Unproven claims are dropped and logged, never retried (hard rule 4).
#   CWE  -> MITRE catalogue in ai/data/cwe_ids.txt (cwec v4.20, ~1,400 IDs)
#   CVE  -> scanner record for this finding, or the small offline registry below
#   file/line/package/fixed_version -> must equal the scanner record; if VALIDATE_REPO_ROOT is set the
#           file must also exist there and the line must be in range (no slack)
# Limits: the CVE registry is a sample, so a model-claimed CVE the scanner did not report is rejected even if
# real. That is deliberate (fail closed). Scanner-supplied identifiers are trusted as scanner input.

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b")
FILE_LINE_RE = re.compile(r"\b([\w./\-]+\.[A-Za-z]{1,5}):(\d+)\b")
VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_HUMAN_REVIEW"}

# TODO(R2/R3): scanner-supplied CVEs are trusted via scan records; OFFLINE_KNOWN_CVES serves as offline test registry.
OFFLINE_KNOWN_CVES = {
    "CVE-2021-44228", "CVE-2023-38408", "CVE-2022-22965", "CVE-2021-45046",
    "CVE-2023-44487", "CVE-2022-42889", "CVE-2024-3094",
}

_cwe_cache = None


def load_cwe_catalogue() -> set:
    global _cwe_cache
    if _cwe_cache is None:
        with open(os.path.join(DATA_DIR, "cwe_ids.txt"), encoding="utf-8") as f:
            _cwe_cache = {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}
    return _cwe_cache


def _norm_path(p: str) -> str:
    return os.path.normpath(str(p).replace("\\", "/")).lstrip("./") if p else ""


def extract_claims(triage: dict) -> dict:
    """Union of the model's structured claims and anything claim-shaped inside its free text."""
    claims = triage.get("claims") if isinstance(triage.get("claims"), dict) else {}
    text = str(triage.get("fix_summary", ""))

    def as_list(v):
        return [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])

    file_lines = list(FILE_LINE_RE.findall(text))
    return {
        "cves": sorted(set(as_list(claims.get("cves"))) | set(CVE_RE.findall(text))),
        "cwes": sorted(set(as_list(claims.get("cwes"))) | set(CWE_RE.findall(text))),
        "package": claims.get("package") or None,
        "fixed_version": claims.get("fixed_version") or None,
        "file": claims.get("file") or None,
        "line": claims.get("line"),
        "text_file_lines": [f"{f}:{n}" for f, n in file_lines],
    }


def check_claims(scanner: dict, claims: dict, repo_root=None) -> list:
    """Returns human-readable rejection reasons (empty list == every claim is grounded)."""
    rejected = []
    scanner_cves = set(scanner.get("cve") or [])
    pkg = scanner.get("package") or {}
    # RESOLVED(R3): apps/vulnshop-api exists on main; VALIDATE_REPO_ROOT verifies file:line existence on real source.
    # TODO(R3): package/fixed_version check against scanner record; extend to CycloneDX model SBOM for supply-chain claims.
    repo_root = repo_root or os.getenv("VALIDATE_REPO_ROOT")

    for cve in claims.get("cves", []):
        if not CVE_RE.fullmatch(cve):
            rejected.append(f"Malformed CVE claim: {cve}")
        elif cve not in scanner_cves and cve not in OFFLINE_KNOWN_CVES:
            rejected.append(f"Unproven CVE claim (not in scanner record or offline registry): {cve}")

    catalogue = load_cwe_catalogue()
    for cwe in claims.get("cwes", []):
        if cwe not in catalogue:
            rejected.append(f"CWE claim not in MITRE catalogue: {cwe}")

    if claims.get("package") and pkg.get("name") != claims["package"]:
        rejected.append(f"Package claim does not match scanner record: {claims['package']}")
    if claims.get("fixed_version") and pkg.get("fixed_version") != claims["fixed_version"]:
        rejected.append(f"Unproven fixed_version claim: {claims['fixed_version']}")

    claimed_refs = []
    if claims.get("file"):
        claimed_refs.append((claims["file"], claims.get("line")))
    for ref in claims.get("text_file_lines", []):
        f, _, n = ref.rpartition(":")
        claimed_refs.append((f, int(n)))
    scanner_file = _norm_path(loc.get("file", ""))
    for f, n in claimed_refs:
        # L1 redaction only shows the model the basename, so a bare basename is a legitimate way to name the file
        same_file = _norm_path(f) == scanner_file or ("/" not in str(f) and f == os.path.basename(scanner_file))
        if not same_file:
            rejected.append(f"File claim does not match scanner location: {f}")
            continue
        if n is not None and loc.get("line") not in (None, n):
            rejected.append(f"Line claim does not match scanner location: {f}:{n}")
        if repo_root:
            full = os.path.join(repo_root, scanner_file)
            if not os.path.isfile(full):
                rejected.append(f"Claimed file does not exist in repo: {f}")
            elif n is not None:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    total = sum(1 for _ in fh)
                if not 1 <= int(n) <= total:
                    rejected.append(f"Claimed line out of range: {f}:{n} (file has {total} lines)")
    return rejected


def validate_triage_output(finding: dict, scanner=None, repo_root=None) -> dict:
    """Gates finding['triage'] in place. `scanner` is the raw scanner record (defaults to the finding's own
    top-level fields, which triage.py copies from the scanner). Strips `claims` from the output either way."""
    triage = finding.get("triage", {})
    claims = extract_claims(triage)
    rejected = check_claims(scanner if scanner is not None else finding, claims, repo_root)

    if triage.get("verdict") not in VALID_VERDICTS:
        rejected.append(f"Invalid verdict enum: {triage.get('verdict')}")

    triage.pop("claims", None)
    if rejected:
        triage["verdict"] = "NEEDS_HUMAN_REVIEW"
        triage["priority"] = "UNASSIGNED"
        triage["fix_summary"] = (f"Model output failed grounding validation ({len(rejected)} unproven claim(s)); "
                                 "see grounding.rejected_claims. Human review required.")
        triage["grounding"] = {"validated": False, "rejected_claims": rejected}
    else:
        triage["grounding"] = {"validated": True, "rejected_claims": []}
    finding["triage"] = triage
    return finding


if __name__ == "__main__":
    scanner = {"cve": ["CVE-2021-44228"], "location": {"file": "pom.xml", "line": 34}}
    good = {**scanner, "triage": {"verdict": "TRUE_POSITIVE", "fix_summary": "Upgrade log4j for CVE-2021-44228 (CWE-502).",
                                  "claims": {"cves": ["CVE-2021-44228"], "cwes": ["CWE-502"], "file": "pom.xml", "line": 34}}}
    print("grounded claims validated:", validate_triage_output(good)["triage"]["grounding"]["validated"])
    bad = {**scanner, "triage": {"verdict": "TRUE_POSITIVE", "fix_summary": "See made/up.py:99 and CVE-2031-12345.",
                                 "claims": {"cwes": ["CWE-99999"]}}}
    print(json.dumps(validate_triage_output(bad)["triage"]["grounding"], indent=2))
