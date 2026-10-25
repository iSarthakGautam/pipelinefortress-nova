import base64
import binascii
import ipaddress
import json
import math
import os
import re
import sys
import time
import unicodedata
from urllib.parse import urlsplit

# redaction/redactor.py
# Four-layer redaction that runs BEFORE any prompt is built, plus the pre-egress tripwire and the egress guard.
#   L1 structural allowlist  - only the fields the model needs; attacker-chosen strings are scrubbed too
#   L2 secrets               - regex rules, base64-wrapped secrets, split-across-lines secrets, entropy scan
#   L3 entities              - emails, private/context-flagged IPv4, IPv6, internal hostnames
#   L4 canary tripwire       - fake secrets planted in a self-test; if ANY survives, or any raw secret shows up
#                              in the outbound prompt, the LLM call is blocked (a code gate, not a prompt rule)
# Redaction is defence in depth: the model is local, so this protects PR comments, logs and any future cloud mode.

# ---------------------------------------------------------------- canaries
# Built from parts so secret scanners don't flag this repo for its own fake secrets.
_CANARY_TAG = "CNRY4BF3A9"
CANARY_VALUES = [
    "AKIA" + "CNRY4BF3A9XYZ012",                      # looks like an AWS access key id (AKIA + 16)
    "ghp_" + "CNRY4bf3a9" + "Q" * 26,                  # looks like a GitHub PAT (ghp_ + 36)
    "canary-4bf3a9" + "@" + "canary-tripwire.example", # looks like an email
    "Cnry4bf3a9!" + "Tripwire#" + "2026",              # looks like a password value
]

# ---------------------------------------------------------------- L2 rules
_CONFUSABLES = {
    # Cyrillic and Greek letters that render like Latin ones
    **{ord(c): l for c, l in zip("АВСЕНІКМОРТХаеорсху", "ABCEHIKMOPTXaeopcxy")},
    **{ord(c): l for c, l in zip("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX")},
}


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _classes(s: str) -> int:
    return sum([any(c.islower() for c in s), any(c.isupper() for c in s), any(c.isdigit() for c in s),
                any(not c.isalnum() for c in s)])


def _plausible_secret_value(v: str) -> bool:
    # Skip code that merely READS a secret (os.getenv(...), request.form['x'], ${VAR}); keep literals.
    if len(v) < 8 or any(ch in v for ch in "()[]{}$<") or v.startswith(("os.", "env", "self.", "config.", "process.")):
        return False
    return _classes(v) >= 2


def _high_entropy(v: str) -> bool:
    return len(v) >= 20 and _classes(v) >= 3 and _shannon(v) >= 4.3


# (name, regex, group index to replace (0 = whole match), optional validator on the replaced text)
L2_RULES = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"), 0, None),
    ("CONNECTION_STRING_CREDS", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:([^\s@/]+)@"), 1, None),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), 0, None),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), 0, None),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprso]-[A-Za-z0-9-]{10,}\b"), 0, None),
    ("GCP_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0, None),
    ("STRIPE_KEY", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), 0, None),
    ("API_KEY_SK", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), 0, None),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0, None),
    ("BASIC_AUTH_HEADER", re.compile(r"(?i)\bauthorization['\"]?\s*[:=]\s*['\"]?(?:basic|bearer)\s+([A-Za-z0-9+/=._\-]{8,})"), 1, None),
    # key = value where the KEY NAME says it is a secret; value must look like a literal, not a lookup
    ("SECRET_VALUE", re.compile(
        r"(?i)\b[a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|credential|auth[_\-]?key)[a-z0-9_.\-]*['\"]?\s*[:=]\s*['\"]?([^\s'\",;]{6,})"),
     1, _plausible_secret_value),
]

_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_TOKEN_RUN = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_=\-]{20,}(?![A-Za-z0-9+/=_\-])")

# ---------------------------------------------------------------- L3 rules
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d]|\.\d)")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?|::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])")
_INTERNAL_HOST = re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:internal|corp|intranet|lan|local|svc|cluster\.local|home\.arpa)\b", re.I)
_IP_CONTEXT = re.compile(r"(?i)(?:host|ip|addr|address|server|connect|endpoint|proxy|gateway|dns|bind|listen|://|@)\W{0,6}$")


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)


def _replace(m, name, group, validator, collector):
    span_text = m.group(group)
    if span_text is None or span_text.startswith("<REDACTED") or (validator and not validator(span_text)):
        return m.group(0)
    if collector is not None:
        collector.append(span_text)
    full = m.group(0)
    start = m.start(group) - m.start(0)
    return full[:start] + f"<REDACTED:{name}>" + full[start + len(span_text):]


def _apply_rules(text: str, collector, skip=()) -> str:
    for name, pat, group, validator in L2_RULES:
        if name in skip:
            continue
        text = pat.sub(lambda m, n=name, g=group, v=validator: _replace(m, n, g, v, collector), text)
    return text


def _strict_b64_decode(run: str):
    try:
        raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return s if s and all(c.isprintable() or c in "\r\n\t" for c in s) else None


def apply_l2_pattern(text: str, collector=None) -> str:
    """L2: secrets. Rules, then base64-wrapped, then split-across-lines, then entropy."""
    if not text:
        return text
    text = _fold(text)

    # split secrets: 'AKIA...' + \n 'XXXX' -> look at a joined view; if it hides a secret the plain view doesn't, drop the snippet
    joined = re.sub(r"[\"'`\s+\\]+", "", text)
    # (fixed-format rules only: key=value rules capture different spans once whitespace is removed)
    plain_hits, joined_hits = [], []
    _apply_rules(text, plain_hits)
    _apply_rules(joined, joined_hits, skip=("SECRET_VALUE", "CONNECTION_STRING_CREDS"))
    new = [h for h in joined_hits if not any(h in p or p in h for p in plain_hits)]
    if new:
        if collector is not None:
            collector.extend(new)
        return "<REDACTED:SPLIT_SECRET_SUSPECTED>"

    text = _apply_rules(text, collector)

    def _b64(m):
        decoded = _strict_b64_decode(m.group(0))
        if decoded is None:
            return m.group(0)
        hits = []
        if _apply_rules(decoded, hits) != decoded or hits:
            if collector is not None:
                collector.append(m.group(0))
            return "<REDACTED:BASE64_SECRET>"
        return m.group(0)
    text = _B64_RUN.sub(_b64, text)

    def _entropy(m):
        if _high_entropy(m.group(0)):
            if collector is not None:
                collector.append(m.group(0))
            return "<REDACTED:HIGH_ENTROPY>"
        return m.group(0)
    return _TOKEN_RUN.sub(_entropy, text)


def _ipv4_repl(m):
    ip = m.group(0)
    try:
        private = ipaddress.ip_address(ip).is_private
    except ValueError:
        return ip
    before = m.string[max(0, m.start() - 24):m.start()]
    return "<REDACTED:IP_ADDRESS>" if private or _IP_CONTEXT.search(before) else ip


def apply_l3_semantic(text: str) -> str:
    """L3: entities. Private IPv4 always; other IPv4 only with host/ip/@/:// context so version strings survive."""
    if not text:
        return text
    text = _EMAIL.sub("<REDACTED:EMAIL>", text)
    text = _INTERNAL_HOST.sub("<REDACTED:INTERNAL_HOST>", text)
    text = _IPV6.sub(lambda m: "<REDACTED:IP_ADDRESS>" if m.group(0).count(":") >= 3 or "::" in m.group(0) else m.group(0), text)
    return _IPV4.sub(_ipv4_repl, text)


# ---------------------------------------------------------------- L1
def _scrub_untrusted_string(value: str, limit: int = 120) -> str:
    """rule_id and file names are chosen by whoever committed the code, so they are data AND a leak path."""
    value = "".join(c for c in str(value) if c.isprintable())[:limit]
    return apply_l3_semantic(apply_l2_pattern(value))


def apply_l1_structural(raw_finding: dict) -> dict:
    """L1: allowlist. Anything not listed here (runner ids, emails, commit info, full paths) is dropped."""
    loc = raw_finding.get("location") or {}
    return {
        "finding_id": raw_finding.get("finding_id", "UNKNOWN"),
        "tool": raw_finding.get("tool", "UNKNOWN"),
        "severity": raw_finding.get("severity_norm", "UNKNOWN"),
        "rule_id": _scrub_untrusted_string(raw_finding.get("rule_id", "")),
        "cwe": raw_finding.get("cwe", []),
        "cve": raw_finding.get("cve", []),
        "file_name": _scrub_untrusted_string(str(loc.get("file", "")).split("/")[-1]),
        "line": loc.get("line", 0),
        "snippet": (raw_finding.get("evidence") or {}).get("snippet") or (raw_finding.get("evidence") or {}).get("snippet_raw") or "",
    }


def redact_finding(raw_finding: dict) -> dict:
    """L1 -> L2 -> L3. (L4 is the tripwire below; it does not touch the payload.)"""
    finding = apply_l1_structural(raw_finding)
    if finding.get("snippet"):
        finding["snippet"] = apply_l3_semantic(apply_l2_pattern(finding["snippet"]))
    return finding


# ---------------------------------------------------------------- L4 tripwire
def canary_selftest() -> bool:
    """Plants fake secrets in a synthetic finding and proves the pipeline strips every one of them."""
    snippet = "\n".join([f"key = '{CANARY_VALUES[0]}'", f"gh = {CANARY_VALUES[1]}",
                         f"owner = {CANARY_VALUES[2]}", f"password = '{CANARY_VALUES[3]}'"])
    out = json.dumps(redact_finding({"finding_id": "canary", "evidence": {"snippet_raw": snippet}}))
    return not any(c in out for c in CANARY_VALUES)


def find_secrets(text: str) -> list:
    """Every secret-looking string L2 can see in `text` (used to check the OUTBOUND prompt)."""
    found = []
    apply_l2_pattern(text or "", found)
    return found


def assert_no_leak(raw_finding: dict, outbound_text: str) -> list:
    """Pre-egress gate. Returns what leaked (empty list == safe to send).
    Checks (a) canary values, (b) every secret L2 detects in the RAW snippet must be absent verbatim."""
    leaked = [c for c in CANARY_VALUES if c in outbound_text]
    raw_snippet = (raw_finding.get("evidence") or {}).get("snippet") or (raw_finding.get("evidence") or {}).get("snippet_raw") or ""
    leaked += [s for s in find_secrets(raw_snippet) if s and s in outbound_text]
    return leaked


# ---------------------------------------------------------------- egress guard
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def egress_log(url: str, body_sha256: str, allowed: bool) -> None:
    path = os.getenv("EGRESS_LOG")
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    host = (urlsplit(url).hostname or "?") if isinstance(url, str) else "?"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host,
                            "body_sha256": body_sha256, "decision": "allowed" if allowed else "denied"}) + "\n")


def egress_guard_check(url: str, body_sha256: str = "") -> bool:
    """Deny by default. Allows only http(s) to an EXACT loopback host with no userinfo.
    (startswith() let http://localhost.evil.com and http://localhost@evil.com through.)"""
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError on a malformed port
        allowed = (parts.scheme in ("http", "https") and parts.hostname in LOOPBACK_HOSTS
                   and not parts.username and not parts.password)
    except (ValueError, AttributeError):
        allowed = False
    egress_log(url, body_sha256, allowed)
    if not allowed:
        print(f"EGRESS BLOCKED: {url}", file=sys.stderr)
    return allowed


if __name__ == "__main__":
    sample = {"finding_id": "1", "evidence": {"snippet_raw":
              "Contact dev@company.com at 192.168.1.5 if api_key='AKIAIOSFODNN7EXAMPLE' fails. lodash 4.17.21.0"}}
    print(json.dumps(redact_finding(sample), indent=2))
    print("canary self-test passes:", canary_selftest())
    for u in ["http://localhost:11434", "http://localhost.evil.com", "http://localhost@evil.com", "https://api.openai.com"]:
        print(u, "->", egress_guard_check(u))
