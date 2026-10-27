#!/usr/bin/env python3
"""Install the team's local git hooks. Owner: R2. Works on Windows (Git Bash), macOS and Linux.

  python scripts/install_hooks.py            # install / update
  python scripts/install_hooks.py --force    # replace hooks you wrote yourself (backed up first)
  python scripts/install_hooks.py --uninstall

Hooks:
  pre-commit  gitleaks scans STAGED changes and blocks the commit if it finds a secret
  pre-push    refuses direct pushes to main (the README's team-contract hook)

gitleaks is downloaded into the hooks directory (never committed) and verified against the
SHA-256 values pinned below. Checking against a checksum file downloaded from the same release
would only catch corruption, not a tampered release.
"""
import argparse
import hashlib
import io
import os
import platform
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

GITLEAKS_VERSION = "8.30.1"
_BASE = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
# From gitleaks_8.30.1_checksums.txt; same version CI uses (.github/workflows/10-security-scan.yml)
ASSETS = {
    ("linux", "x64"): ("gitleaks_8.30.1_linux_x64.tar.gz",
                       "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
    ("linux", "arm64"): ("gitleaks_8.30.1_linux_arm64.tar.gz",
                         "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"),
    ("darwin", "x64"): ("gitleaks_8.30.1_darwin_x64.tar.gz",
                        "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"),
    ("darwin", "arm64"): ("gitleaks_8.30.1_darwin_arm64.tar.gz",
                          "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"),
    ("windows", "x64"): ("gitleaks_8.30.1_windows_x64.zip",
                         "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"),
}
_ARCH = {"x86_64": "x64", "amd64": "x64", "x64": "x64", "aarch64": "arm64", "arm64": "arm64"}

MARKER = "# managed-by: scripts/install_hooks.py"
# Recognised so the README's copy-paste version is upgraded in place, not treated as custom
LEGACY_PRE_PUSH_SIGNATURE = "Direct pushes to main are forbidden by team contract"

PRE_COMMIT = f"""#!/bin/sh
{MARKER} (R2). Re-run the script to update; don't edit by hand.
# Blocks commits whose staged changes contain a secret (gitleaks {GITLEAKS_VERSION} + repo .gitleaks.toml).
root="$(git rev-parse --show-toplevel)"
gl="$(git rev-parse --git-path hooks)/bin/gitleaks"
[ -f "$gl.exe" ] && gl="$gl.exe"
if [ ! -f "$gl" ]; then
  echo "pre-commit: gitleaks is not installed. Run: python scripts/install_hooks.py" >&2
  exit 1
fi
if ! "$gl" git --pre-commit --staged --redact --no-banner --ignore-gitleaks-allow \\
     --config "$root/.gitleaks.toml" "$root"; then
  cat >&2 <<'MSG'

Commit blocked: gitleaks found a possible secret in your staged changes (redacted above).
  * Real secret: unstage and delete it, ROTATE it, and tell the team today (no blame for
    escalating; TEAM_RESPONSIBILITIES "Safety").
  * Known fake (test fixture, canary): allowlist its EXACT value in .gitleaks.toml via a PR.
    Inline "gitleaks:allow" comments are ignored on purpose; suppressions get reviewed.
  * Deliberately planted secret (R3, ground_truth/planted.yaml): commit with --no-verify.
    Do NOT allowlist it. CI is supposed to catch it.
MSG
  exit 1
fi
"""

PRE_PUSH = f"""#!/bin/sh
{MARKER} (R2). Re-run the script to update; don't edit by hand.
# Team contract: no direct pushes to main (no server-side branch protection on this plan).
# Git passes one "<local ref> <local sha> <remote ref> <remote sha>" line per ref being pushed.
# Check where each one lands, not the checked-out branch: `git push origin feature:main` from a
# feature branch must be refused, and pushing a feature branch while on main must not be.
while read -r local_ref local_sha remote_ref remote_sha; do
  if [ "$remote_ref" = "refs/heads/main" ]; then
    echo "STOP: Direct pushes to main are forbidden by team contract. Please create a branch and open a PR." >&2
    exit 1
  fi
done
exit 0
"""

HOOKS = {"pre-commit": PRE_COMMIT, "pre-push": PRE_PUSH}


class InstallError(Exception):
    pass


def platform_key(system: str = None, machine: str = None) -> tuple:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    key = (system, _ARCH.get(machine, machine))
    if key not in ASSETS:
        raise InstallError(f"no pinned gitleaks build for {system}/{machine}; "
                           f"supported: {', '.join('/'.join(k) for k in sorted(ASSETS))}")
    return key


def verify_sha256(data: bytes, expected: str) -> None:
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise InstallError(f"checksum mismatch: expected {expected}, got {actual}. Refusing to install.")


def extract_binary(archive: bytes, asset_name: str) -> bytes:
    """Return only the gitleaks executable's bytes. Nothing else is written to disk."""
    want = "gitleaks.exe" if asset_name.endswith(".zip") else "gitleaks"
    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            for info in z.infolist():
                if Path(info.filename).name == want and not info.is_dir():
                    return z.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as t:
            for m in t.getmembers():
                if Path(m.name).name == want and m.isfile():
                    return t.extractfile(m).read()
    raise InstallError(f"{want} not found inside {asset_name}")


def download(url: str) -> bytes:
    # Only the pinned release URL; urllib would also accept file:// or other hosts
    if not url.startswith(_BASE + "/"):
        raise InstallError(f"refusing to download from unexpected URL: {url}")
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def git(repo: Path, *args) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise InstallError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout.strip()


def hooks_dir(repo: Path) -> Path:
    p = Path(git(repo, "rev-parse", "--git-path", "hooks"))
    return p if p.is_absolute() else (repo / p)


def installed_version(binary: Path) -> str:
    try:
        out = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=30)
        return out.stdout.strip().lstrip("v")
    except OSError:
        return ""


def install_gitleaks(hdir: Path, key: tuple, fetch=download, log=print) -> Path:
    asset, sha = ASSETS[key]
    binary = hdir / "bin" / ("gitleaks.exe" if key[0] == "windows" else "gitleaks")
    if binary.exists() and installed_version(binary) == GITLEAKS_VERSION:
        log(f"gitleaks {GITLEAKS_VERSION} already installed")
        return binary
    log(f"downloading {asset}")
    archive = fetch(f"{_BASE}/{asset}")
    verify_sha256(archive, sha)
    data = extract_binary(archive, asset)
    binary.parent.mkdir(parents=True, exist_ok=True)
    tmp = binary.with_suffix(binary.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.replace(tmp, binary)
    log(f"gitleaks {GITLEAKS_VERSION} installed (sha256 verified) -> {binary}")
    return binary


def write_hook(hdir: Path, name: str, content: str, force: bool, log=print) -> bool:
    """Write a hook. Returns False if skipped because a custom hook exists and force is off."""
    path = hdir / name
    if path.exists():
        current = path.read_text(encoding="utf-8", errors="replace")
        ours = MARKER in current or (name == "pre-push" and LEGACY_PRE_PUSH_SIGNATURE in current)
        if not ours:
            if not force:
                log(f"SKIPPED {name}: you have your own hook at {path}. Re-run with --force "
                    f"to replace it (it will be backed up).")
                return False
            backup = path.with_name(f"{name}.backup-{time.strftime('%Y%m%d%H%M%S')}")
            path.replace(backup)
            log(f"backed up your {name} hook -> {backup.name}")
    hdir.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:   # LF: sh on Windows needs it
        f.write(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log(f"installed {name} hook")
    return True


def uninstall(hdir: Path, log=print) -> None:
    for name in HOOKS:
        path = hdir / name
        if path.exists() and MARKER in path.read_text(encoding="utf-8", errors="replace"):
            path.unlink()
            log(f"removed {name} hook")
    for b in ("gitleaks", "gitleaks.exe"):
        if (hdir / "bin" / b).exists():
            (hdir / "bin" / b).unlink()
            log(f"removed {b}")


def main(argv=None, fetch=download) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="replace (and back up) hooks you wrote yourself")
    ap.add_argument("--uninstall", action="store_true", help="remove the hooks and binary this script installed")
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args(argv)
    try:
        repo = Path(git(args.repo, "rev-parse", "--show-toplevel"))
        hdir = hooks_dir(repo)
        if args.uninstall:
            uninstall(hdir)
            return 0
        install_gitleaks(hdir, platform_key(), fetch=fetch)
        results = [write_hook(hdir, name, content, args.force) for name, content in HOOKS.items()]
    except (InstallError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not all(results):
        return 1
    print("done. Test it: stage a file containing a fake key and run `git commit`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
