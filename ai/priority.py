# priority.py
# Deterministic priority scorer. The model proposes a verdict and a fix; CODE decides priority from
# facts (severity, KEV, EPSS, reachability). This keeps "the LLM is a component" honest and makes
# priority reproducible and explainable (audit §4.5 #8: a KEV-listed log4shell must never get P2).

_ORDER = ["P1", "P2", "P3"]


def compute_priority(verdict: str, severity_norm: str, kev: bool, epss, reachable, is_new=True) -> str:
    """P1/P2/P3/UNASSIGNED. Only confirmed true positives get a priority."""
    if verdict != "TRUE_POSITIVE":
        return "UNASSIGNED"

    sev = (severity_norm or "UNKNOWN").upper()
    epss = epss if isinstance(epss, (int, float)) else 0.0

    if kev or epss >= 0.7 or sev == "CRITICAL":
        level = 0
    elif sev == "HIGH" or epss >= 0.1:
        level = 1
    elif sev == "UNKNOWN":
        level = 1  # severity missing: conservative, a human should look soon
    else:
        level = 2

    # reachable is tri-state: None means "not computed", which must NOT downgrade anything.
    if reachable is False and not kev:
        level = min(level + 1, 2)
    if is_new is False and not kev:
        level = min(level + 1, 2)
    return _ORDER[level]


if __name__ == "__main__":
    print(compute_priority("TRUE_POSITIVE", "HIGH", True, 0.97, None))   # P1 (KEV)
    print(compute_priority("TRUE_POSITIVE", "MEDIUM", False, None, None))  # P3
    print(compute_priority("FALSE_POSITIVE", "CRITICAL", True, 0.9, True))  # UNASSIGNED
