"""scripts/install_hooks.py. Unit tests use fake archives (no network). The end-to-end test runs
the real gitleaks when GITLEAKS_TEST_BIN points to a binary, and is skipped otherwise."""
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import install_hooks as ih  # noqa: E402

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def tar_gz(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for k, v in (("user.email", "t@example.com"), ("user.name", "t"), ("commit.gpgsign", "false")):
        subprocess.run(["git", "-C", str(tmp_path), "config", k, v], check=True)
    return tmp_path


@pytest.fixture
def fake_release(monkeypatch):
    """Point the current platform's asset at a fake archive with a matching pinned hash."""
    key = ih.platform_key()
    asset = ih.ASSETS[key][0]
    exe = "gitleaks.exe" if asset.endswith(".zip") else "gitleaks"
    payload = b"FAKE-GITLEAKS"
    archive = (zip_bytes if asset.endswith(".zip") else tar_gz)({"README.md": b"x", exe: payload})
    monkeypatch.setitem(ih.ASSETS, key, (asset, hashlib.sha256(archive).hexdigest()))
    calls = []

    def fetch(url):
        calls.append(url)
        return archive
    return fetch, calls, payload


# ------------------------------------------------------------------ pure helpers

@pytest.mark.parametrize("system,machine,expected", [
    ("Linux", "x86_64", ("linux", "x64")), ("Linux", "aarch64", ("linux", "arm64")),
    ("Darwin", "arm64", ("darwin", "arm64")), ("Windows", "AMD64", ("windows", "x64"))])
def test_platform_key(system, machine, expected):
    assert ih.platform_key(system, machine) == expected


def test_unsupported_platform():
    with pytest.raises(ih.InstallError, match="no pinned gitleaks build"):
        ih.platform_key("Windows", "ARM64")


def test_every_asset_has_a_sha256_and_matches_version():
    for asset, sha in ih.ASSETS.values():
        assert ih.GITLEAKS_VERSION in asset and len(sha) == 64 and int(sha, 16) >= 0


def test_checksum_mismatch_refuses():
    with pytest.raises(ih.InstallError, match="checksum mismatch"):
        ih.verify_sha256(b"tampered", "0" * 64)


def test_extract_only_the_binary():
    assert ih.extract_binary(tar_gz({"LICENSE": b"l", "gitleaks": b"BIN"}), "x.tar.gz") == b"BIN"
    assert ih.extract_binary(zip_bytes({"README.md": b"r", "gitleaks.exe": b"EXE"}), "x.zip") == b"EXE"
    with pytest.raises(ih.InstallError, match="not found"):
        ih.extract_binary(tar_gz({"evil/../../x": b"nope"}), "x.tar.gz")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "https://evil.example/gitleaks.tar.gz",
                                 "https://github.com/gitleaks/gitleaks/releases/download/v9.9.9/x"])
def test_download_refuses_unexpected_urls(url):
    with pytest.raises(ih.InstallError, match="unexpected URL"):
        ih.download(url)


def test_tampered_download_is_not_installed(tmp_path):
    key = ih.platform_key()
    with pytest.raises(ih.InstallError, match="checksum mismatch"):
        ih.install_gitleaks(tmp_path, key, fetch=lambda url: b"not the real archive", log=lambda *a: None)
    assert not (tmp_path / "bin").exists()


# ------------------------------------------------------------------ install into a real repo

@needs_git
def test_install_writes_hooks_and_binary(repo, fake_release):
    fetch, calls, payload = fake_release
    assert ih.main(["--repo", str(repo)], fetch=fetch) == 0
    hdir = repo / ".git" / "hooks"
    for name in ("pre-commit", "pre-push"):
        text = (hdir / name).read_bytes()
        assert ih.MARKER.encode() in text and b"\r\n" not in text      # LF for sh on Windows
        assert os.access(hdir / name, os.X_OK) or os.name == "nt"
    binary = next((hdir / "bin").iterdir())
    assert binary.read_bytes() == payload
    assert calls == [f"{ih._BASE}/{ih.ASSETS[ih.platform_key()][0]}"]
    assert b"--ignore-gitleaks-allow" in (hdir / "pre-commit").read_bytes()


@needs_git
def test_custom_hook_is_kept_unless_forced(repo, fake_release):
    fetch, _, _ = fake_release
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n")
    assert ih.main(["--repo", str(repo)], fetch=fetch) == 1          # skipped, reported
    assert hook.read_text() == "#!/bin/sh\necho mine\n"
    assert ih.main(["--repo", str(repo), "--force"], fetch=fetch) == 0
    assert ih.MARKER in hook.read_text()
    backups = list(hook.parent.glob("pre-commit.backup-*"))
    assert len(backups) == 1 and backups[0].read_text() == "#!/bin/sh\necho mine\n"


@needs_git
def test_readme_pre_push_hook_is_upgraded_in_place(repo, fake_release):
    fetch, _, _ = fake_release
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text('#!/bin/bash\necho "STOP: Direct pushes to main are forbidden by team contract."\n')
    assert ih.main(["--repo", str(repo)], fetch=fetch) == 0
    assert ih.MARKER in hook.read_text()
    assert not list(hook.parent.glob("pre-push.backup-*"))


@needs_git
def test_uninstall_removes_only_managed_hooks(repo, fake_release):
    fetch, _, _ = fake_release
    ih.main(["--repo", str(repo)], fetch=fetch)
    custom = repo / ".git" / "hooks" / "post-commit"
    custom.write_text("#!/bin/sh\n")
    assert ih.main(["--repo", str(repo), "--uninstall"]) == 0
    hdir = repo / ".git" / "hooks"
    assert not (hdir / "pre-commit").exists() and not (hdir / "pre-push").exists()
    assert not any((hdir / "bin").iterdir()) and custom.exists()


# ------------------------------------------------------------------ end to end with real gitleaks

REAL = os.environ.get("GITLEAKS_TEST_BIN")
# Built at runtime so this file never contains a detectable key (the repo's own hook and CI scan it)
FAKE_AWS_KEY = "AKIA" + "Q7XRWZ4M2PLKT5VN"


@needs_git
@pytest.mark.skipif(not REAL, reason="set GITLEAKS_TEST_BIN to a gitleaks 8.30.1 binary")
def test_real_hook_blocks_secret_and_allows_clean_commit(repo):
    hdir = repo / ".git" / "hooks"
    (hdir / "bin").mkdir(parents=True, exist_ok=True)
    shutil.copy(REAL, hdir / "bin" / Path(REAL).name)
    for name, content in ih.HOOKS.items():
        ih.write_hook(hdir, name, content, force=True, log=lambda *a: None)
    shutil.copy(ROOT / ".gitleaks.toml", repo / ".gitleaks.toml")

    def commit(fname, text):
        (repo / fname).write_text(text)
        subprocess.run(["git", "-C", str(repo), "add", fname], check=True)
        return subprocess.run(["git", "-C", str(repo), "commit", "-qm", fname], capture_output=True, text=True)

    ok = commit("clean.py", "print('hello')\n")
    assert ok.returncode == 0, ok.stderr

    leak = commit("settings.py", f'aws_access_key_id = "{FAKE_AWS_KEY}"\n')
    assert leak.returncode != 0 and "Commit blocked" in leak.stderr
    assert FAKE_AWS_KEY not in leak.stdout + leak.stderr                   # redacted

    subprocess.run(["git", "-C", str(repo), "reset", "-q"], check=True)    # only the next file staged
    bypass = commit("settings2.py", f'aws_access_key_id = "{FAKE_AWS_KEY}"  # gitleaks:allow\n')
    assert bypass.returncode != 0                                         # inline allow ignored

    subprocess.run(["git", "-C", str(repo), "reset", "-q"], check=True)
    canary = commit("redactor.py", 'CANARY_TOKEN = "CANARY_4bf3a9_SECRET"\n')
    assert canary.returncode == 0, canary.stderr                          # allowlisted exact value
