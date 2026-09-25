#!/usr/bin/env python3
"""OldGrid.io AMP release controller (stdlib only).

Selects an authenticated GitHub release for carthorsestudios/poobiverse-classic,
verifies the required asset triple, installs under the instance root, probes
local /healthz and /version, atomically promotes current, and supervises the
bundled Node process. AMP Update is not the normal path; Start/Restart drives
this controller.

Patterns for exclusive locking, safe extraction bounds, readiness-before-promote,
rollback-on-failed-candidate, and SIGTERM forwarding were informed by
carthorsestudios/scratch-mmo deployment/amp/amp_release_updater.py at
4e9fb28d0f97d2f4ef75fed83b2b082a3be4bcd3 (Carthorse Studios). Classic uses one
Node HTTP+WS process and does not carry Godot, a Go gateway, or Scratch's
mirrored control pair.

This is repository-authenticated HTTPS plus byte-integrity checking. It is not
a cryptographic publisher-signature system.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_ID = "poobiverse-classic"
GITHUB_OWNER = "carthorsestudios"
GITHUB_REPO = "poobiverse-classic"
GITHUB_API_HOST = "api.github.com"
GITHUB_API_VERSION = "2022-11-28"
USER_AGENT = "poobiverse-classic-amp/1.0"

ASSET_ZIP = "poobiverse_release.zip"
ASSET_MANIFEST = "release_manifest.json"
ASSET_CHECKSUMS = "checksums.sha256"
REQUIRED_ASSETS = (ASSET_ZIP, ASSET_MANIFEST, ASSET_CHECKSUMS)

TOKEN_ENV = "POOBIVERSE_GITHUB_TOKEN"
TAG_ENV = "POOBIVERSE_RELEASE_TAG"
PORT_ENV = "PORT"
HOST_ENV = "HOST"
DATA_DIR_ENV = "POOBIVERSE_DATA_DIR"
ORIGINS_ENV = "POOBIVERSE_ALLOWED_ORIGINS"
TRUSTED_PROXY_ENV = "POOBIVERSE_TRUSTED_PROXY_IPS"
LOCK_FD_ENV = "POOBIVERSE_INSTANCE_LOCK_FD"
LOG_ENV = "POOBIVERSE_CONTROLLER_LOG"

READY_PREFIX = "[OldGrid] Ready"

RELEASE_TAG_RE = re.compile(r"^main-([0-9a-f]{12})-run([0-9]+)-a([0-9]+)$")
BUILD_ID_RE = re.compile(r"^gha-([0-9]+)-([0-9]+)$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MAX_ZIP_UNCOMPRESSED = 512 * 1024 * 1024
MAX_ZIP_ENTRIES = 20_000
MAX_MANIFEST_BYTES = 256 * 1024
MAX_CHECKSUMS_BYTES = 64 * 1024
NETWORK_TIMEOUT = 5.0
DOWNLOAD_DEADLINE = 120.0
HEALTH_DEADLINE = 30.0
HEALTH_POLL = 0.25
HTTP_PROBE_TIMEOUT = 2.0
CHILD_STOP_DEADLINE = 15.0
CHILD_SIGKILL_GRACE = 2.0
MAX_REDIRECTS = 5
ALLOWED_ASSET_HOST_SUFFIXES = (
    "githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)

PINNED_NODE = "22.23.2"
CHECKPOINT = 2
ENTRYPOINT = "run.sh"

SECRET_ENV_KEYS = (TOKEN_ENV, "GITHUB_TOKEN")

MODE_FILE = 0o600
MODE_DIR = 0o700
MODE_EXEC = 0o755

_SECRETS: set[str] = set()
_stop_requested = False
_active_child: Optional["ChildProc"] = None
_pending_child_pid: int | None = None
_lock_held = False
_log_fd: Optional[int] = None

# Runtime essentials only. Updater credentials and test-control variables are never copied.
_GAME_ENV_PASSTHROUGH = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "USER", "LOGNAME", "TMPDIR", "SHELL",
)
TXN_FIELDS = ("phase", "candidateBuildId", "previousBuildId", "complete")
TXN_PHASES = ("downloaded", "extracting", "staging", "activating")
DEPLOY_FIELDS = ("buildId", "previousBuildId", "releaseTag", "sourceSha", "rolledBack")


class AmpError(Exception):
    """Fatal controller error."""


class Cancelled(Exception):
    """Stop requested before a child was committed."""


# ---------------------------------------------------------------------------
# Logging / secrets
# ---------------------------------------------------------------------------


def register_secret(value: str) -> None:
    text = str(value or "").strip()
    if len(text) >= 8:
        _SECRETS.add(text)


def redact(message: str) -> str:
    text = str(message)
    for secret in _SECRETS:
        if secret and secret in text:
            text = text.replace(secret, "***redacted***")
    return text


def log(message: str) -> None:
    line = redact(message)
    print(line, flush=True)
    if _log_fd is not None:
        try:
            os.write(_log_fd, (line + "\n").encode("utf-8", errors="replace"))
        except OSError:
            pass


def assert_no_secrets_in_argv(argv: list[str]) -> None:
    values = {
        os.environ.get(key, "").strip()
        for key in SECRET_ENV_KEYS
        if len(os.environ.get(key, "").strip()) >= 8
    }
    for arg in argv:
        if arg in values:
            raise AmpError("Refusing to run: a secret was passed on the command line")
        lowered = arg.lower()
        for key in SECRET_ENV_KEYS:
            if lowered.startswith(f"--{key.lower()}") or lowered.startswith(f"{key.lower()}="):
                raise AmpError(f"Refusing to accept {key} on the command line")


def install_controller_log(instance_root: Path) -> None:
    global _log_fd
    target = os.environ.get(LOG_ENV, "").strip()
    path = Path(target) if target else (instance_root / "state" / "poobiverse_controller.log")
    try:
        path = assert_safe_file_destination(instance_root, path)
    except AmpError as exc:
        log(f"WARNING: controller log disabled: {exc}")
        return
    try:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags, MODE_FILE)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            log("WARNING: controller log is not a regular file")
            return
        if st.st_size > 2 * 1024 * 1024:
            data = os.read(fd, st.st_size)[-512 * 1024 :]
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, data)
        os.lseek(fd, 0, os.SEEK_END)
        _log_fd = fd
    except OSError as exc:
        log(f"WARNING: controller log disabled: {exc}")


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def lexical_under(root: Path, path: Path) -> Path:
    """Absolute path that stays inside root without resolving symlinks."""
    root_abs = os.path.abspath(root)
    path_abs = os.path.abspath(path)
    rel = os.path.relpath(path_abs, root_abs)
    if rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        raise AmpError(f"Managed path escapes instance root: {path}")
    return Path(path_abs)


def assert_real_dir_chain(root: Path, directory: Path) -> None:
    """Every existing component from root through directory must be a real directory."""
    directory = lexical_under(root, directory)
    root_abs = os.path.abspath(root)
    if os.path.islink(root_abs) or not os.path.isdir(root_abs):
        raise AmpError("Instance root is not a real directory")
    rel = os.path.relpath(os.path.abspath(directory), root_abs)
    current = root_abs
    if rel == ".":
        return
    for part in rel.split(os.sep):
        if part in ("", ".", ".."):
            raise AmpError(f"Unsafe managed path component: {part!r}")
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise AmpError(f"Refusing symlink in managed path: {current}")
        if os.path.lexists(current):
            st = os.lstat(current)
            if not stat.S_ISDIR(st.st_mode):
                raise AmpError(f"Managed path component is not a directory: {current}")


def assert_safe_file_destination(root: Path, path: Path) -> Path:
    """Parent chain is real directories; the leaf is absent or a regular file (never a symlink)."""
    path = lexical_under(root, path)
    assert_real_dir_chain(root, path.parent)
    if os.path.lexists(path):
        if os.path.islink(path):
            raise AmpError(f"Refusing symlink destination: {path}")
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            raise AmpError(f"Refusing non-regular destination: {path}")
    return path


def secure_mkdir(path: Path, root: Path | None = None) -> None:
    if root is None:
        raise AmpError("secure_mkdir requires the instance root")
    path = lexical_under(root, path)
    root_abs = os.path.abspath(root)
    rel = os.path.relpath(os.path.abspath(path), root_abs)
    current = root_abs
    if rel == ".":
        return
    for part in rel.split(os.sep):
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise AmpError(f"Refusing symlink directory: {current}")
        if os.path.lexists(current):
            st = os.lstat(current)
            if not stat.S_ISDIR(st.st_mode):
                raise AmpError(f"Managed path exists and is not a directory: {current}")
        else:
            os.mkdir(current, MODE_DIR)
            os.chmod(current, MODE_DIR)
            if os.path.islink(current):
                raise AmpError(f"Refusing symlink directory: {current}")


def safe_unlink(path: Path, root: Path) -> None:
    if not os.path.lexists(path):
        return
    assert_safe_file_destination(root, path)
    os.unlink(path)


def safe_rmtree(path: Path, root: Path) -> None:
    path = lexical_under(root, path)
    if os.path.islink(path):
        raise AmpError(f"Refusing to delete symlink: {path}")
    if not os.path.lexists(path):
        return
    assert_real_dir_chain(root, path)

    def _onerror(func, target, exc_info):  # noqa: ARG001
        raise AmpError(f"Could not remove controller path: {target}")

    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        if os.path.islink(dirpath):
            raise AmpError(f"Refusing to walk symlink: {dirpath}")
        for name in list(dirnames):
            child = os.path.join(dirpath, name)
            if os.path.islink(child):
                os.unlink(child)
                dirnames.remove(name)
        for name in filenames:
            child = os.path.join(dirpath, name)
            if os.path.islink(child):
                os.unlink(child)
    shutil.rmtree(path)


def atomic_write_bytes(path: Path, data: bytes, mode: int = MODE_FILE, root: Path | None = None) -> None:
    path = Path(path)
    if root is not None:
        path = assert_safe_file_destination(root, path)
    elif path.is_symlink():
        raise AmpError(f"Refusing to write through symlink: {path}")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if root is not None and os.path.islink(path):
            os.unlink(tmp)
            raise AmpError(f"Refusing to replace symlink destination: {path}")
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, obj: Any, root: Path | None = None) -> None:
    atomic_write_bytes(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8"), root=root)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AmpError(f"Corrupt or unreadable JSON at {path.name}: {exc}") from exc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def is_within(parent: Path, child: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def resolve_managed(instance_root: Path, rel: str) -> Path:
    root = instance_root.resolve()
    target = (root / rel).resolve()
    if not is_within(root, target) and target != root:
        raise AmpError(f"Managed path escapes instance root: {rel}")
    return target


# ---------------------------------------------------------------------------
# Instance layout / lock
# ---------------------------------------------------------------------------


@dataclass
class Layout:
    root: Path
    control: Path
    incoming: Path
    releases: Path
    current: Path
    state: Path
    server_data: Path
    lock_path: Path
    txn_path: Path
    deploy_path: Path


def make_layout(root: Path) -> Layout:
    root = root.resolve()
    return Layout(
        root=root,
        control=root / "control",
        incoming=root / "incoming",
        releases=root / "releases",
        current=root / "current",
        state=root / "state",
        server_data=root / "server_data",
        lock_path=root / "state" / "instance.lock",
        txn_path=root / "state" / "transaction.json",
        deploy_path=root / "state" / "deployment.json",
    )


def ensure_layout(layout: Layout) -> None:
    if os.path.islink(layout.root) or not layout.root.is_dir():
        raise AmpError("Instance root is not a real directory")
    for path in (layout.control, layout.incoming, layout.releases, layout.state):
        secure_mkdir(path, layout.root)
    cache = layout.control / "cache"
    secure_mkdir(cache, layout.root)


def acquire_instance_lock(layout: Layout) -> int:
    global _lock_held
    ensure_layout(layout)
    lock_path = assert_safe_file_destination(layout.root, layout.lock_path)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(lock_path), flags, MODE_FILE)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AmpError("Refusing symlinked instance lock") from exc
        raise AmpError(f"Could not open instance lock: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AmpError("Instance lock is not a regular file")
        lst = os.lstat(lock_path)
        if stat.S_ISLNK(lst.st_mode) or lst.st_ino != st.st_ino or lst.st_dev != st.st_dev:
            raise AmpError("Refusing unsafe instance lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise AmpError("Instance lock is held by another controller; refusing second Start") from exc
        raise AmpError(f"Could not acquire instance lock: {exc}") from exc
    except AmpError:
        os.close(fd)
        raise
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    os.fsync(fd)
    clo = fcntl.fcntl(fd, fcntl.F_GETFD)
    fcntl.fcntl(fd, fcntl.F_SETFD, clo & ~fcntl.FD_CLOEXEC)
    _lock_held = True
    return fd


def resolve_data_dir(raw: str, layout: Layout) -> Path:
    text = (raw or "server_data").strip() or "server_data"
    if os.path.isabs(text):
        data = Path(os.path.abspath(text))
    else:
        data = Path(os.path.abspath(layout.root / text))
    # Refuse when the lexical path, or any existing prefix, lands in managed trees.
    forbidden_names = ("current", "releases", "incoming", "control", "state")
    try:
        rel = os.path.relpath(str(data), str(layout.root))
    except ValueError:
        rel = None
    if rel is not None and rel != ".." and not rel.startswith(".." + os.sep):
        first = rel.split(os.sep)[0]
        if first in forbidden_names or rel == ".":
            raise AmpError("POOBIVERSE_DATA_DIR must not resolve into current/releases/incoming/control/state")
    if os.path.islink(data):
        raise AmpError("POOBIVERSE_DATA_DIR must not be a symlink")
    real = Path(os.path.realpath(data)) if data.exists() else data
    for name in forbidden_names:
        banned = (layout.root / name).resolve()
        if real == banned or is_within(banned, real):
            raise AmpError("POOBIVERSE_DATA_DIR must not resolve into current/releases/incoming/control/state")
    data.mkdir(parents=True, exist_ok=True)
    return data


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


def request_stop(signum: int, _frame: Any) -> None:
    global _stop_requested
    _stop_requested = True
    log(f"Stop requested ({signum})")
    child = _active_child
    if child is not None and child.alive():
        child.terminate_group()
    pending = _pending_child_pid
    if pending:
        try:
            os.killpg(os.getpgid(pending), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            try:
                os.kill(pending, signal.SIGTERM)
            except OSError:
                pass


def install_signal_handlers() -> None:
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)


def check_cancelled() -> None:
    if _stop_requested:
        raise Cancelled("Stop requested")


# ---------------------------------------------------------------------------
# Child process
# ---------------------------------------------------------------------------


@dataclass
class ChildProc:
    proc: subprocess.Popen[Any]
    label: str
    run_sh: Path
    pgid: int

    def alive(self) -> bool:
        return self.proc.poll() is None

    def terminate_group(self) -> None:
        if not self.alive():
            return
        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            try:
                self.proc.send_signal(signal.SIGTERM)
            except OSError:
                pass

    def kill_group(self) -> None:
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            try:
                self.proc.kill()
            except OSError:
                pass

    def wait_stopped(self, deadline: float) -> int | None:
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            code = self.proc.poll()
            if code is not None:
                return int(code)
            time.sleep(0.05)
        if self.alive():
            self.kill_group()
            try:
                return int(self.proc.wait(timeout=CHILD_SIGKILL_GRACE))
            except subprocess.TimeoutExpired:
                return None
        return self.proc.poll()


def launch_run_sh(
    run_sh: Path,
    *,
    label: str,
    env: dict[str, str],
    lock_fd: int,
    cwd: Path,
) -> ChildProc:
    global _active_child, _pending_child_pid
    check_cancelled()
    if os.path.islink(run_sh) or not run_sh.is_file():
        raise AmpError(f"Refusing invalid run.sh: {run_sh}")
    if os.path.islink(cwd) or not cwd.is_dir():
        raise AmpError(f"Refusing invalid release directory: {cwd}")
    resolved = run_sh.resolve()
    if not is_within(cwd.resolve(), resolved):
        raise AmpError(f"run.sh escapes the release directory: {run_sh}")
    child_env = {}
    for key in _GAME_ENV_PASSTHROUGH:
        if key in env and env[key]:
            child_env[key] = env[key]
    for key in (PORT_ENV, HOST_ENV, DATA_DIR_ENV, ORIGINS_ENV, TRUSTED_PROXY_ENV, LOCK_FD_ENV):
        if key in env:
            child_env[key] = env[key]
    # Test preloader is attached by the harness wrapper on the already-filtered env.
    if "NODE_OPTIONS" in env:
        child_env["NODE_OPTIONS"] = env["NODE_OPTIONS"]
    child_env[LOCK_FD_ENV] = str(lock_fd)
    for key in list(child_env):
        if key in SECRET_ENV_KEYS or key.startswith("POOBIVERSE_TEST"):
            child_env.pop(key, None)
    log(f"Launching {label}: {run_sh}")
    check_cancelled()
    proc = subprocess.Popen(
        [str(run_sh)],
        cwd=str(cwd),
        env=child_env,
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        start_new_session=True,
        pass_fds=(lock_fd,),
    )
    _pending_child_pid = proc.pid
    try:
        if _stop_requested:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=CHILD_STOP_DEADLINE)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=CHILD_SIGKILL_GRACE)
            raise Cancelled("Stop requested during child handoff")
        pgid = os.getpgid(proc.pid)
        child = ChildProc(proc=proc, label=label, run_sh=run_sh, pgid=pgid)
        _active_child = child
        return child
    finally:
        _pending_child_pid = None


def stop_child(child: ChildProc | None, *, reason: str) -> int | None:
    global _active_child
    if child is None:
        return None
    log(f"Stopping {child.label} ({reason})")
    child.terminate_group()
    code = child.wait_stopped(CHILD_STOP_DEADLINE)
    if _active_child is child:
        _active_child = None
    return code


# ---------------------------------------------------------------------------
# GitHub transport (production + injectable)
# ---------------------------------------------------------------------------


class GitHubTransport:
    """Production HTTPS transport for the fixed GitHub API host.

    The CLI always constructs this class. Tests may replace `build_github_opener`
    or this class on the module before calling `main`; there is no environment switch.
    """

    instance_root: Path | None = None

    def get_json(self, path: str, token: str) -> Any:
        return self._api_json("GET", path, token)

    def download_asset(self, asset_id: int, token: str, dest: Path, *, cancel_check: Callable[[], None]) -> None:
        url = f"https://{GITHUB_API_HOST}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/assets/{asset_id}"
        self._request_bytes(
            url,
            token,
            accept="application/octet-stream",
            method="GET",
            allow_redirect_auth=False,
            cancel_check=cancel_check,
            max_bytes=MAX_ZIP_UNCOMPRESSED + 1024 * 1024,
            write_path=dest,
        )

    def get_ref_commit(self, ref: str, token: str) -> str:
        data = self.get_json(f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/git/ref/tags/{urllib.parse.quote(ref)}", token)
        if not isinstance(data, dict):
            raise AmpError("Unexpected git ref response")
        obj = data.get("object") or {}
        sha = str(obj.get("sha") or "")
        obj_type = str(obj.get("type") or "")
        if obj_type == "tag":
            # Annotated tag: peel once.
            tag = self.get_json(f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/git/tags/{sha}", token)
            if not isinstance(tag, dict):
                raise AmpError("Unexpected annotated tag response")
            peeled = (tag.get("object") or {})
            sha = str(peeled.get("sha") or "")
            obj_type = str(peeled.get("type") or "")
        if obj_type != "commit" or not SHA40_RE.match(sha):
            raise AmpError("Release tag does not resolve to a commit")
        return sha

    def _api_json(self, method: str, path: str, token: str) -> Any:
        if not path.startswith("/"):
            raise AmpError("Internal API path error")
        body = self._request_bytes(
            f"https://{GITHUB_API_HOST}{path}",
            token,
            accept="application/vnd.github+json",
            method=method,
            allow_redirect_auth=False,
            cancel_check=check_cancelled,
            max_bytes=2 * 1024 * 1024,
        )
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AmpError(f"GitHub API returned invalid JSON: {exc}") from exc

    def _request_bytes(
        self,
        url: str,
        token: str,
        *,
        accept: str,
        method: str,
        allow_redirect_auth: bool,
        cancel_check: Callable[[], None],
        max_bytes: int,
        write_path: Path | None = None,
    ) -> bytes | None:
        deadline = time.monotonic() + DOWNLOAD_DEADLINE
        current = url
        send_auth = True
        for _ in range(MAX_REDIRECTS + 1):
            cancel_check()
            if time.monotonic() > deadline:
                raise AmpError("Download deadline exceeded")
            parsed = urllib.parse.urlparse(current)
            if parsed.scheme != "https":
                raise AmpError("Refusing non-HTTPS GitHub URL")
            host = (parsed.hostname or "").lower()
            if send_auth and host != GITHUB_API_HOST:
                raise AmpError("Authorization only sent to api.github.com")
            if not send_auth and not _allowed_asset_host(host):
                raise AmpError(f"Refusing redirect host: {host}")
            headers = {
                "Accept": accept,
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            }
            if send_auth and token:
                headers["Authorization"] = f"Bearer {token}"
            remaining = max(1.0, min(NETWORK_TIMEOUT, deadline - time.monotonic()))
            req = urllib.request.Request(current, headers=headers, method=method)
            try:
                # Manual redirect handling so Authorization is stripped cross-host.
                opener = build_github_opener()
                with opener.open(req, timeout=remaining) as resp:
                    status = int(getattr(resp, "status", 200))
                    if status in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location") or ""
                        if not loc:
                            raise AmpError("Redirect without Location")
                        next_url = urllib.parse.urljoin(current, loc)
                        next_host = (urllib.parse.urlparse(next_url).hostname or "").lower()
                        # Strip auth on any host change.
                        if next_host != host:
                            send_auth = False
                        current = next_url
                        continue
                    if status != 200:
                        detail = _read_error_body(resp, deadline, cancel_check)
                        raise AmpError(f"GitHub HTTP {status}: {detail}")
                    return _stream_body(resp, max_bytes, deadline, cancel_check, write_path, root=self.instance_root)
            except NoRedirectError as exc:
                current = exc.location
                next_host = (urllib.parse.urlparse(current).hostname or "").lower()
                if next_host != host:
                    send_auth = False
                continue
            except urllib.error.HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308):
                    loc = exc.headers.get("Location") or ""
                    try:
                        exc.close()
                    except Exception:
                        pass
                    if not loc:
                        raise AmpError("Redirect without Location") from exc
                    next_url = urllib.parse.urljoin(current, loc)
                    next_host = (urllib.parse.urlparse(next_url).hostname or "").lower()
                    if next_host != (urllib.parse.urlparse(current).hostname or "").lower():
                        send_auth = False
                    current = next_url
                    continue
                # HTTPError is a real response body. Read it with the same cancellable
                # reader; do not call the buffered exc.read() path.
                cancel_check()
                try:
                    detail = _read_error_body(exc, deadline, cancel_check)
                except Cancelled:
                    raise
                raise AmpError(f"GitHub HTTP {exc.code}: {detail}") from exc
            except urllib.error.URLError as exc:
                raise AmpError(f"GitHub unreachable: {redact(str(exc.reason))}") from exc
        raise AmpError("Too many redirects")


def build_github_opener() -> urllib.request.OpenerDirector:
    """Production opener. Tests may replace this function; the CLI never selects another host."""
    return urllib.request.build_opener(NoRedirect)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise NoRedirectError(newurl)


class NoRedirectError(Exception):
    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location


def _allowed_asset_host(host: str) -> bool:
    host = host.lower()
    for suffix in ALLOWED_ASSET_HOST_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def _iter_layers(resp: Any):
    current = resp
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        moved = False
        for attr in ("fp", "raw"):
            nxt = getattr(current, attr, None)
            if nxt is not None and nxt is not current and id(nxt) not in seen:
                current = nxt
                moved = True
                break
        if not moved:
            break


def _response_socket(resp: Any):
    for layer in _iter_layers(resp):
        sock = getattr(layer, "_sock", None) or getattr(layer, "sock", None)
        if sock is not None and hasattr(sock, "settimeout"):
            return sock
    return None


def _body_reader(resp: Any):
    """Use HTTPResponse.read1 when the object is an urllib HTTPError wrapper."""
    fallback = resp
    for layer in _iter_layers(resp):
        if type(layer).__name__ == "HTTPResponse" and hasattr(layer, "read1"):
            return layer
        if hasattr(layer, "read1"):
            fallback = layer
    return fallback


def _close_response(resp: Any) -> None:
    close = getattr(resp, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:
        pass


def _abort_timed_out_read(resp: Any, cancel_check: Callable[[], None], exc: BaseException) -> None:
    """A timed-out buffered reader must not be retried. Stop wins over a generic timeout."""
    try:
        cancel_check()
    finally:
        _close_response(resp)
    raise AmpError("Download read timed out") from exc


def _read_slice(resp: Any, deadline: float, cancel_check: Callable[[], None]) -> bytes:
    """Return the next body chunk, or b'' at EOF.

    The socket timeout is the remaining overall deadline, capped at the 5-second
    request bound. A timeout closes the response and aborts; it is not treated as
    a would-block that can be retried on the same object.
    """
    cancel_check()
    if time.monotonic() >= deadline:
        raise AmpError("Download deadline exceeded")
    remaining = max(0.05, deadline - time.monotonic())
    wait = min(NETWORK_TIMEOUT, remaining)
    reader = _body_reader(resp)
    sock = _response_socket(resp)
    if sock is not None:
        try:
            sock.settimeout(wait)
        except OSError:
            pass
    try:
        chunk = reader.read1(8192) if hasattr(reader, "read1") else reader.read(8192)
    except (TimeoutError, socket.timeout) as exc:
        _abort_timed_out_read(resp, cancel_check, exc)
    except OSError as exc:
        text = str(exc).lower()
        if "timed out" in text or "cannot read from timed out" in text:
            _abort_timed_out_read(resp, cancel_check, exc)
        raise
    cancel_check()
    if chunk is None:
        return b""
    return bytes(chunk)


def _read_error_body(resp: Any, deadline: float, cancel_check: Callable[[], None]) -> str:
    """Bounded, cancellable text for an error response, including urllib.HTTPError."""
    cancel_check()
    try:
        data = _stream_body(resp, 2048, deadline, cancel_check, None) or b""
    finally:
        _close_response(resp)
    return redact(data.decode("utf-8", errors="replace"))


def _stream_body(
    resp: Any,
    max_bytes: int,
    deadline: float,
    cancel_check: Callable[[], None],
    write_path: Path | None,
    root: Path | None = None,
) -> bytes | None:
    if write_path is not None:
        if root is None:
            raise AmpError("Download destination requires the instance root")
        write_path = assert_safe_file_destination(root, write_path)
        partial = assert_safe_file_destination(root, write_path.with_name(write_path.name + ".partial"))
        total = 0
        try:
            flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(partial), flags, MODE_FILE)
            with os.fdopen(fd, "wb") as handle:
                while True:
                    chunk = _read_slice(resp, deadline, cancel_check)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise AmpError("Downloaded asset exceeds size bound")
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(partial, MODE_FILE)
            if os.path.islink(write_path):
                raise AmpError("Refusing to publish download onto a symlink")
            os.replace(str(partial), str(write_path))
        except Exception:
            try:
                if os.path.lexists(partial) and not os.path.islink(partial):
                    os.unlink(partial)
            except OSError:
                pass
            raise
        return None
    buf = io.BytesIO()
    total = 0
    while True:
        chunk = _read_slice(resp, deadline, cancel_check)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise AmpError("Response exceeds size bound")
        buf.write(chunk)
    return buf.getvalue()


def github_transport() -> "GitHubTransport":
    """Production CLI always constructs this fixed transport. Tests replace the class or opener."""
    return GitHubTransport()


# ---------------------------------------------------------------------------
# Release selection / verification
# ---------------------------------------------------------------------------


def parse_checksums(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
        if not m:
            raise AmpError("checksums.sha256 is malformed")
        digest, name = m.group(1), m.group(2)
        if name in out:
            raise AmpError(f"checksums.sha256 has duplicate entry for {name}")
        out[name] = digest
    for required in (ASSET_ZIP, ASSET_MANIFEST):
        if required not in out:
            raise AmpError(f"checksums.sha256 missing {required}")
    if ASSET_CHECKSUMS in out:
        raise AmpError("checksums.sha256 must not list itself")
    return out


def parse_manifest_structure(obj: Any) -> dict[str, Any]:
    """Parse and structurally validate a release manifest without enforcing controller CHECKPOINT.

    Used to inspect installed historical releases (e.g. v1) during cutover. Candidate
    downloads still go through validate_manifest(), which requires CHECKPOINT match.
    """
    if not isinstance(obj, dict):
        raise AmpError("release_manifest.json is malformed")
    required = {
        "manifestVersion",
        "appId",
        "sourceSha",
        "buildId",
        "releaseTag",
        "nodeVersion",
        "nodeArchiveSha256",
        "platform",
        "arch",
        "checkpointCompatibility",
        "entrypoint",
        "archive",
    }
    if set(obj.keys()) != required:
        raise AmpError("release_manifest.json has unexpected keys")
    if obj["manifestVersion"] != 1:
        raise AmpError("unsupported manifestVersion")
    if obj["appId"] != APP_ID:
        raise AmpError("manifest appId mismatch")
    source_sha = obj["sourceSha"]
    if not isinstance(source_sha, str) or not SHA40_RE.match(source_sha):
        raise AmpError("manifest sourceSha malformed")
    build_id = obj["buildId"]
    if not isinstance(build_id, str) or not BUILD_ID_RE.match(build_id):
        raise AmpError("manifest buildId malformed")
    release_tag = obj["releaseTag"]
    if release_tag is not None:
        if not isinstance(release_tag, str) or not RELEASE_TAG_RE.match(release_tag):
            raise AmpError("manifest releaseTag malformed")
        tm = RELEASE_TAG_RE.match(release_tag)
        bm = BUILD_ID_RE.match(build_id)
        assert tm and bm
        if not source_sha.startswith(tm.group(1)):
            raise AmpError("manifest releaseTag does not match sourceSha")
        if tm.group(2) != bm.group(1) or tm.group(3) != bm.group(2):
            raise AmpError("manifest releaseTag does not match buildId")
    if obj["nodeVersion"] != PINNED_NODE:
        raise AmpError("manifest nodeVersion mismatch")
    if obj["platform"] != "linux" or obj["arch"] != "x64":
        raise AmpError("manifest platform/arch mismatch")
    compat = obj["checkpointCompatibility"]
    if not isinstance(compat, dict):
        raise AmpError("manifest checkpointCompatibility malformed")
    mn, mx = compat.get("minimum"), compat.get("maximum")
    if not isinstance(mn, int) or not isinstance(mx, int) or mn != mx or mn < 1:
        raise AmpError("manifest checkpointCompatibility malformed")
    if obj["entrypoint"] != ENTRYPOINT:
        raise AmpError("manifest entrypoint must be run.sh")
    archive = obj["archive"]
    if not isinstance(archive, dict):
        raise AmpError("manifest archive malformed")
    if archive.get("filename") != ASSET_ZIP:
        raise AmpError("manifest archive.filename mismatch")
    if not isinstance(archive.get("bytes"), int) or archive["bytes"] < 1:
        raise AmpError("manifest archive.bytes malformed")
    if not isinstance(archive.get("sha256"), str) or not SHA256_RE.match(archive["sha256"]):
        raise AmpError("manifest archive.sha256 malformed")
    return obj


def is_checkpoint_compatible(manifest: dict[str, Any]) -> bool:
    compat = manifest.get("checkpointCompatibility")
    if not isinstance(compat, dict):
        return False
    return compat.get("minimum") == CHECKPOINT and compat.get("maximum") == CHECKPOINT


def validate_manifest(obj: Any) -> dict[str, Any]:
    """Strict candidate/runtime validation: structure plus this controller's CHECKPOINT."""
    parsed = parse_manifest_structure(obj)
    if not is_checkpoint_compatible(parsed):
        raise AmpError(f"manifest checkpointCompatibility must be minimum=maximum={CHECKPOINT}")
    return parsed


def read_installed_manifest_structure(release_dir: Path) -> dict[str, Any]:
    meta = read_json(release_dir / ".amp-identity.json")
    if not isinstance(meta, dict) or "manifest" not in meta:
        raise AmpError("installed release .amp-identity.json is malformed")
    return parse_manifest_structure(meta["manifest"])


def select_assets(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise AmpError("Release has no assets list")
    # Ignore source-code ZIP style names that are not our payload.
    found: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "")
        if name in REQUIRED_ASSETS:
            if name in found:
                raise AmpError(f"Release has duplicate asset {name}")
            found[name] = asset
    missing = [n for n in REQUIRED_ASSETS if n not in found]
    if missing:
        raise AmpError(f"Release missing required assets: {', '.join(missing)}")
    return found


def fetch_selected_release(transport: GitHubTransport, token: str, tag_override: str) -> dict[str, Any]:
    if tag_override:
        path = f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tags/{urllib.parse.quote(tag_override)}"
        release = transport.get_json(path, token)
    else:
        release = transport.get_json(f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest", token)
    if not isinstance(release, dict):
        raise AmpError("Unexpected release payload")
    if release.get("draft") is True:
        raise AmpError("Selected release is a draft")
    if not tag_override and release.get("prerelease") is True:
        raise AmpError("Latest release is a prerelease; refusing")
    if tag_override and release.get("prerelease") is True:
        # Explicit tag may be pre-release only if published non-draft — still refuse for Classic stable path.
        raise AmpError("Configured release tag is a prerelease; refusing")
    tag = str(release.get("tag_name") or "")
    if not RELEASE_TAG_RE.match(tag):
        raise AmpError(f"Release tag is not a Classic published identity: {tag!r}")
    return release


def resolve_release_commit(transport: GitHubTransport, token: str, release: dict[str, Any]) -> str:
    tag = str(release.get("tag_name") or "")
    return transport.get_ref_commit(tag, token)


# ---------------------------------------------------------------------------
# Safe ZIP extract
# ---------------------------------------------------------------------------


def preflight_zip(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise AmpError("ZIP has too many entries")
    total = 0
    seen: set[str] = set()
    for info in infos:
        name = info.filename
        if not name or name.startswith("/") or name.startswith("\\") or "\\" in name:
            raise AmpError(f"ZIP member path refused: {name!r}")
        if name.endswith("/"):
            parts = name.rstrip("/").split("/")
        else:
            parts = name.split("/")
        if any(p in ("", ".", "..") for p in parts):
            raise AmpError(f"ZIP member path refused: {name!r}")
        if name in seen:
            raise AmpError(f"ZIP has duplicate member: {name}")
        seen.add(name)
        if stat.S_ISLNK(info.external_attr >> 16) or info.create_system == 3 and ((info.external_attr >> 16) & 0o170000) == 0o120000:
            raise AmpError(f"ZIP symlink refused: {name}")
        mode = info.external_attr >> 16
        if mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode) and not name.endswith("/"):
            # Some tools leave mode 0; allow. Refuse exotic types when set.
            ftype = mode & 0o170000
            if ftype not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise AmpError(f"ZIP special file refused: {name}")
        if not name.endswith("/"):
            total += int(info.file_size)
            if total > MAX_ZIP_UNCOMPRESSED:
                raise AmpError("ZIP uncompressed size exceeds bound")
    return infos


def safe_extract(zip_path: Path, dest: Path, root: Path) -> None:
    if os.path.lexists(dest):
        if os.path.islink(dest) or not dest.is_dir():
            raise AmpError("Extract staging directory must be empty/nonexistent")
        extras = [name for name in os.listdir(dest) if name != OWNED_NAME]
        if extras or not (dest / OWNED_NAME).is_file():
            raise AmpError("Extract staging directory must be empty/nonexistent")
    else:
        secure_mkdir(dest, root)
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = preflight_zip(zf)
        # Detect file/dir collisions among members.
        files = {i.filename.rstrip("/") for i in infos if not i.filename.endswith("/")}
        dirs = {i.filename.rstrip("/") for i in infos if i.filename.endswith("/")}
        if files & dirs:
            raise AmpError("ZIP has file/directory name collisions")
        for info in infos:
            target = dest / info.filename
            if not is_within(dest, target if info.filename.endswith("/") else target.parent) and not is_within(dest, target):
                # Double-check resolved path.
                resolved = (dest / info.filename).resolve()
                if not is_within(dest.resolve(), resolved) and resolved != dest.resolve():
                    raise AmpError("ZIP member escapes destination")
            if info.filename.endswith("/"):
                secure_mkdir(target, root)
                continue
            secure_mkdir(target.parent, root)
            with zf.open(info, "r") as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
            mode = info.external_attr >> 16
            # Ordinary executable bits only; strip setuid/setgid/sticky.
            if mode & 0o111:
                os.chmod(target, MODE_EXEC)
            else:
                os.chmod(target, MODE_FILE)
    run_sh = dest / ENTRYPOINT
    if not run_sh.is_file() or run_sh.is_symlink():
        raise AmpError("Extracted package missing run.sh")
    os.chmod(run_sh, MODE_EXEC)
    node = dest / "runtime" / "bin" / "node"
    if node.is_file() and not node.is_symlink():
        os.chmod(node, MODE_EXEC)
    build_info_path = dest / "build-info.json"
    if not build_info_path.is_file():
        raise AmpError("Extracted package missing build-info.json")


def validate_installed_identity(release_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    info = validate_manifest_build_info_pair(manifest, read_json(release_dir / "build-info.json"))
    run_sh = release_dir / ENTRYPOINT
    if run_sh.is_symlink() or not run_sh.is_file():
        raise AmpError("Installed run.sh invalid")
    node = release_dir / "runtime" / "bin" / "node"
    if node.is_symlink() or not node.is_file():
        raise AmpError("Installed bundled Node missing")
    return info


def validate_manifest_build_info_pair(manifest: dict[str, Any], build_info: Any) -> dict[str, Any]:
    if not isinstance(build_info, dict):
        raise AmpError("build-info.json malformed")
    for key in ("appId", "sourceSha", "buildId", "releaseTag", "nodeVersion", "platform", "arch", "checkpointVersion"):
        if key not in build_info:
            raise AmpError("build-info.json missing fields")
    if build_info["appId"] != manifest["appId"]:
        raise AmpError("build-info appId mismatch")
    if build_info["sourceSha"] != manifest["sourceSha"]:
        raise AmpError("build-info sourceSha mismatch")
    if build_info["buildId"] != manifest["buildId"]:
        raise AmpError("build-info buildId mismatch")
    if build_info["releaseTag"] != manifest["releaseTag"]:
        raise AmpError("build-info releaseTag mismatch")
    if build_info["nodeVersion"] != manifest["nodeVersion"]:
        raise AmpError("build-info nodeVersion mismatch")
    if build_info["platform"] != "linux" or build_info["arch"] != "x64":
        raise AmpError("build-info platform mismatch")
    if build_info["checkpointVersion"] != CHECKPOINT:
        raise AmpError("build-info checkpointVersion mismatch")
    return build_info


# ---------------------------------------------------------------------------
# Health / identity
# ---------------------------------------------------------------------------


def http_get_json(url: str, timeout: float = HTTP_PROBE_TIMEOUT) -> tuple[int, Any]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536)
            status = int(resp.status)
            return status, json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise AmpError(f"probe failed {url}: {redact(str(exc))}") from exc


def wait_ready(
    *,
    port: int,
    child: ChildProc,
    expected: dict[str, Any],
) -> None:
    health_url = f"http://127.0.0.1:{port}/healthz"
    version_url = f"http://127.0.0.1:{port}/version"
    deadline = time.monotonic() + HEALTH_DEADLINE
    last = "no probe"
    while time.monotonic() < deadline:
        check_cancelled()
        if not child.alive():
            raise AmpError("Child exited before becoming ready")
        try:
            h_status, health = http_get_json(health_url)
            v_status, version = http_get_json(version_url)
            if h_status != 200 or v_status != 200:
                last = f"http status health={h_status} version={v_status}"
            else:
                if not isinstance(health, dict) or health.get("status") != "ok":
                    last = f"health not ok: {health!r}"
                elif health.get("checkpointVersion") != CHECKPOINT:
                    last = "health checkpoint mismatch"
                else:
                    node_ver = str(version.get("nodeVersion") or "").lstrip("v")
                    if version.get("appId") != expected["appId"]:
                        last = "version appId mismatch"
                    elif version.get("sourceSha") != expected["sourceSha"]:
                        last = "version sourceSha mismatch"
                    elif version.get("buildId") != expected["buildId"]:
                        last = "version buildId mismatch"
                    elif version.get("releaseTag") != expected["releaseTag"]:
                        last = "version releaseTag mismatch"
                    elif node_ver != expected["nodeVersion"]:
                        last = f"version node mismatch {node_ver!r}"
                    elif not child.alive():
                        last = "child died during ready check"
                    else:
                        return
        except AmpError as exc:
            last = str(exc)
        time.sleep(HEALTH_POLL)
    raise AmpError(f"Readiness deadline exceeded: {last}")


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_port_free(port: int, timeout: float = 10.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not port_in_use(port):
            return
        time.sleep(0.1)
    raise AmpError(f"Port {port} still in use after stop")


# ---------------------------------------------------------------------------
# Current symlink / transaction
# ---------------------------------------------------------------------------


def canonical_build_id(raw: Any, *, allow_none: bool) -> str | None:
    if raw is None and allow_none:
        return None
    if not isinstance(raw, str) or not BUILD_ID_RE.fullmatch(raw):
        raise AmpError("transaction build id is not a canonical buildId")
    if raw != os.path.basename(raw) or ".." in raw or "/" in raw or "\\" in raw:
        raise AmpError("transaction build id is not a canonical buildId")
    return raw


def release_path(layout: Layout, build_id: str) -> Path:
    if not BUILD_ID_RE.fullmatch(build_id):
        raise AmpError("refusing non-canonical release id")
    path = lexical_under(layout.root, layout.releases / build_id)
    if os.path.abspath(path.parent) != os.path.abspath(layout.releases):
        raise AmpError("release path escaped releases/")
    if os.path.islink(path):
        raise AmpError(f"Refusing symlinked release path: {path}")
    return path


def read_current_target(layout: Layout) -> Path | None:
    if not os.path.lexists(layout.current):
        return None
    if not os.path.islink(layout.current):
        raise AmpError("current exists but is not a managed symlink")
    link = os.readlink(str(layout.current))
    if os.path.isabs(link):
        raise AmpError("current symlink must be relative")
    parts = Path(link).parts
    if ".." in parts or parts[:1] != ("releases",) or len(parts) != 2:
        raise AmpError("current symlink target is not a release directory")
    build_id = parts[1]
    if not BUILD_ID_RE.fullmatch(build_id):
        raise AmpError("current symlink target is not a canonical build id")
    target = release_path(layout, build_id)
    if not target.is_dir():
        raise AmpError("current symlink target is missing")
    return target


def atomic_symlink(layout: Layout, target: Path) -> None:
    target = release_path(layout, target.name)
    if not target.is_dir() or os.path.islink(target):
        raise AmpError("symlink target must be a real release directory")
    assert_real_dir_chain(layout.root, layout.root)
    tmp = layout.root / ".current.new"
    if os.path.lexists(tmp):
        if os.path.islink(tmp) or (os.path.isfile(tmp) and not os.path.islink(tmp)):
            os.unlink(tmp)
        else:
            raise AmpError("refusing to replace unexpected .current.new")
    os.symlink(os.path.join("releases", target.name), str(tmp))
    os.replace(str(tmp), str(layout.current))


def validate_txn(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj.keys()) != set(TXN_FIELDS):
        raise AmpError("transaction record schema mismatch")
    phase = obj.get("phase")
    if phase not in TXN_PHASES:
        raise AmpError(f"transaction phase is unsupported: {phase!r}")
    complete = obj.get("complete")
    if not isinstance(complete, bool):
        raise AmpError("transaction complete flag is malformed")
    allow_missing_candidate = phase == "downloaded"
    candidate = canonical_build_id(obj.get("candidateBuildId"), allow_none=allow_missing_candidate)
    previous = canonical_build_id(obj.get("previousBuildId"), allow_none=True)
    if phase != "downloaded" and not candidate:
        raise AmpError("transaction candidate is required")
    if phase == "activating" and complete:
        raise AmpError("activating transaction cannot already be complete")
    return {
        "phase": phase,
        "candidateBuildId": candidate,
        "previousBuildId": previous,
        "complete": complete,
    }


def write_txn(layout: Layout, obj: dict[str, Any] | None) -> None:
    if obj is None:
        safe_unlink(layout.txn_path, layout.root)
        return
    atomic_write_json(layout.txn_path, validate_txn(obj), root=layout.root)


def load_txn(layout: Layout) -> dict[str, Any] | None:
    if not os.path.lexists(layout.txn_path):
        return None
    if os.path.islink(layout.txn_path):
        raise AmpError("transaction.json is a symlink; refusing")
    data = read_json(layout.txn_path)
    return validate_txn(data)


OWNED_NAME = ".amp-owned.json"


def _identity_manifest(directory: Path) -> dict[str, Any] | None:
    meta = directory / ".amp-identity.json"
    if os.path.islink(directory) or os.path.islink(meta) or not meta.is_file():
        return None
    try:
        saved = read_json(meta)
        manifest = validate_manifest(saved.get("manifest"))
    except AmpError:
        return None
    build_id = manifest.get("buildId")
    if not isinstance(build_id, str) or not BUILD_ID_RE.fullmatch(build_id):
        return None
    return manifest


def controller_owned_release(layout: Layout, build_id: str) -> bool:
    try:
        path = release_path(layout, build_id)
    except AmpError:
        return False
    if os.path.islink(path) or not path.is_dir():
        return False
    manifest = _identity_manifest(path)
    return bool(manifest and manifest.get("buildId") == build_id and path.name == build_id)


def controller_owned_failed(path: Path) -> bool:
    name = path.name
    if not name.startswith("failed-") or os.path.islink(path) or not path.is_dir():
        return False
    build_id = name[len("failed-") :]
    if not BUILD_ID_RE.fullmatch(build_id):
        return False
    manifest = _identity_manifest(path)
    return bool(manifest and manifest.get("buildId") == build_id)


def read_ownership(directory: Path) -> dict[str, Any] | None:
    marker = directory / OWNED_NAME
    if os.path.islink(directory) or os.path.islink(marker) or not marker.is_file():
        return None
    try:
        data = read_json(marker)
    except AmpError:
        return None
    if not isinstance(data, dict) or data.get("createdByController") is not True:
        return None
    if data.get("appId") != APP_ID or data.get("kind") not in ("incoming", "staging"):
        return None
    build_id = data.get("buildId")
    if build_id is not None and (not isinstance(build_id, str) or not BUILD_ID_RE.fullmatch(build_id)):
        return None
    return data


def controller_owns_work(directory: Path, kind: str, build_id: str | None) -> bool:
    if os.path.islink(directory) or not directory.is_dir():
        return False
    marker = read_ownership(directory)
    if marker is None or marker.get("kind") != kind:
        return False
    marked = marker.get("buildId")
    if kind == "staging":
        if not build_id or directory.name != f".staging-{build_id}" or marked != build_id:
            return False
    elif kind == "incoming":
        if not re.fullmatch(r"dl-[0-9]+", directory.name):
            return False
        if build_id is not None and marked not in (None, build_id):
            return False
    return True


def claim_controller_dir(layout: Layout, path: Path, kind: str, build_id: str | None) -> None:
    """Create a previously absent work directory and record that this controller owns it.

    An existing path is removed only when it already carries this controller's marker.
    A familiar name without that marker is a refusal, not an adoption.
    """
    if kind not in ("incoming", "staging"):
        raise AmpError("unsupported ownership kind")
    if kind == "staging":
        if not build_id or not BUILD_ID_RE.fullmatch(build_id) or path.name != f".staging-{build_id}":
            raise AmpError("staging ownership requires the canonical build id")
    if kind == "incoming" and not re.fullmatch(r"dl-[0-9]+", path.name):
        raise AmpError("incoming work path is not controller-shaped")
    if os.path.lexists(path):
        if os.path.islink(path) or not controller_owns_work(path, kind, build_id):
            raise AmpError(f"Refusing unowned destination {path.name}")
        safe_rmtree(path, layout.root)
    secure_mkdir(path, layout.root)
    atomic_write_json(
        path / OWNED_NAME,
        {"appId": APP_ID, "kind": kind, "buildId": build_id, "createdByController": True},
        root=layout.root,
    )


def _delete_owned_incoming(layout: Layout) -> None:
    incoming = layout.incoming
    if not incoming.is_dir() or os.path.islink(incoming):
        return
    for entry in list(incoming.iterdir()):
        if controller_owns_work(entry, "incoming", None):
            safe_rmtree(entry, layout.root)


def apply_retention(layout: Layout, current_id: str, previous_id: str | None) -> None:
    keep = {current_id}
    if previous_id:
        keep.add(previous_id)
    incomplete: list[Path] = []
    for entry in list(layout.releases.iterdir()):
        name = entry.name
        if os.path.islink(entry):
            continue
        if name in keep:
            continue
        if name.startswith(".staging-"):
            build_id = name[len(".staging-") :]
            if controller_owns_work(entry, "staging", build_id):
                incomplete.append(entry)
            continue
        if name.startswith("failed-"):
            if controller_owned_failed(entry):
                incomplete.append(entry)
            continue
        if BUILD_ID_RE.fullmatch(name) and controller_owned_release(layout, name):
            safe_rmtree(entry, layout.root)
    incomplete.sort(key=lambda item: item.stat().st_mtime)
    while len(incomplete) > 1:
        oldest = incomplete.pop(0)
        if os.path.islink(oldest):
            continue
        if oldest.name.startswith(".staging-"):
            build_id = oldest.name[len(".staging-") :]
            if controller_owns_work(oldest, "staging", build_id):
                safe_rmtree(oldest, layout.root)
        elif controller_owned_failed(oldest):
            safe_rmtree(oldest, layout.root)


def _deployment_for_candidate(layout: Layout, build_id: str, previous: str | None, *, rolled_back: bool) -> None:
    manifest = _identity_manifest(release_path(layout, build_id))
    if manifest is None or manifest.get("buildId") != build_id:
        raise AmpError("committed release has no usable identity")
    write_deployment(
        layout,
        {
            "buildId": build_id,
            "previousBuildId": previous,
            "releaseTag": manifest.get("releaseTag"),
            "sourceSha": manifest["sourceSha"],
            "rolledBack": rolled_back,
        },
    )


def _finish_activation_deployment(layout: Layout, candidate: str, previous: str | None) -> None:
    """Write the deployment record for a current pointer that already names the candidate."""
    recorded = load_deployment(layout)
    if recorded and recorded.get("buildId") == candidate:
        if recorded.get("previousBuildId") != previous:
            raise AmpError("deployment previous does not match the activating transaction; evidence unchanged")
        return
    if recorded is not None and previous is not None and recorded.get("buildId") != previous:
        raise AmpError("deployment is not the pre-promotion selection; evidence unchanged")
    if recorded is not None and previous is None and recorded.get("buildId") != candidate:
        raise AmpError("deployment contradicts a first install; evidence unchanged")
    _deployment_for_candidate(layout, candidate, previous, rolled_back=False)


def recover_transaction(layout: Layout) -> None:
    if not os.path.lexists(layout.txn_path):
        return
    try:
        txn = load_txn(layout)
    except AmpError as exc:
        raise AmpError(f"Refusing corrupt transaction; evidence left unchanged: {exc}") from exc
    if txn is None:
        return
    phase = txn["phase"]
    candidate = txn["candidateBuildId"]
    previous = txn["previousBuildId"]
    log(f"Recovering interrupted transaction phase={phase}")
    if phase in ("downloaded", "extracting"):
        staging = layout.releases / f".staging-{candidate}" if candidate else None
        if staging is not None and os.path.lexists(staging):
            if os.path.islink(staging) or not controller_owns_work(staging, "staging", candidate):
                raise AmpError("Unowned staging evidence; transaction left unchanged")
        _delete_owned_incoming(layout)
        if staging is not None and os.path.lexists(staging) and controller_owns_work(staging, "staging", candidate):
            safe_rmtree(staging, layout.root)
        write_txn(layout, None)
        return
    if phase == "staging":
        if not candidate or not controller_owned_release(layout, candidate):
            raise AmpError("Interrupted staging has no verified candidate; evidence unchanged")
        write_txn(layout, None)
        return
    if phase == "activating":
        try:
            cur = read_current_target(layout)
        except AmpError as exc:
            raise AmpError(f"Interrupted activation has an unusable current pointer: {exc}") from exc
        candidate_owned = bool(candidate and controller_owned_release(layout, candidate))
        candidate_path = layout.releases / candidate if candidate else None
        if candidate_path is not None and os.path.lexists(candidate_path) and not candidate_owned:
            raise AmpError("Candidate path is not a proven release; evidence unchanged")
        if cur is None and previous is None:
            # First install has not published current. A verified candidate can be
            # retried through ordinary readiness. Do not invent current or touch data.
            if not candidate_owned:
                raise AmpError("First install candidate is not a verified release; evidence unchanged")
            if load_deployment(layout) is not None:
                raise AmpError("deployment exists without a current selection; evidence unchanged")
            _delete_owned_incoming(layout)
            write_txn(layout, None)
            return
        if candidate and cur is not None and cur.name == candidate and candidate_owned:
            _finish_activation_deployment(layout, candidate, previous)
            _delete_owned_incoming(layout)
            write_txn(layout, None)
            apply_retention(layout, candidate, previous)
            return
        if previous and cur is not None and cur.name == previous and controller_owned_release(layout, previous):
            recorded = load_deployment(layout)
            if recorded is not None and recorded.get("buildId") != previous:
                raise AmpError("deployment contradicts the uncommitted activation; evidence unchanged")
            _delete_owned_incoming(layout)
            write_txn(layout, None)
            return
        if cur is None and previous and controller_owned_release(layout, previous):
            recorded = load_deployment(layout)
            if recorded is not None and recorded.get("buildId") == previous:
                atomic_symlink(layout, release_path(layout, previous))
                write_txn(layout, None)
                return
        raise AmpError("Interrupted activation is ambiguous; evidence unchanged")
    raise AmpError(f"Unknown transaction phase: {phase!r}")


# ---------------------------------------------------------------------------
# Install / deploy
# ---------------------------------------------------------------------------


def verify_triple_files(zip_path: Path, manifest_path: Path, checksums_path: Path) -> dict[str, Any]:
    if any(p.is_symlink() or not p.is_file() for p in (zip_path, manifest_path, checksums_path)):
        raise AmpError("Release triple paths must be regular files")
    checksum_text = checksums_path.read_text(encoding="utf-8")
    if len(checksum_text.encode("utf-8")) > MAX_CHECKSUMS_BYTES:
        raise AmpError("checksums.sha256 too large")
    digests = parse_checksums(checksum_text)
    manifest_bytes = manifest_path.read_bytes()
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise AmpError("release_manifest.json too large")
    if sha256_file(manifest_path) != digests[ASSET_MANIFEST]:
        raise AmpError("release_manifest.json checksum mismatch")
    if sha256_file(zip_path) != digests[ASSET_ZIP]:
        raise AmpError("poobiverse_release.zip checksum mismatch")
    manifest = validate_manifest(json.loads(manifest_bytes.decode("utf-8")))
    if manifest["archive"]["sha256"] != digests[ASSET_ZIP]:
        raise AmpError("manifest archive.sha256 does not match checksums")
    if manifest["archive"]["bytes"] != zip_path.stat().st_size:
        raise AmpError("manifest archive.bytes does not match ZIP size")
    if manifest["releaseTag"] is None:
        raise AmpError("releaseTag=null artifact is not eligible for GitHub deployment")
    return manifest


def load_deployment(layout: Layout) -> dict[str, Any] | None:
    if not os.path.lexists(layout.deploy_path):
        return None
    if os.path.islink(layout.deploy_path):
        raise AmpError("deployment.json is a symlink; refusing")
    data = read_json(layout.deploy_path)
    if not isinstance(data, dict) or set(data.keys()) != set(DEPLOY_FIELDS):
        raise AmpError("deployment record schema mismatch")
    canonical_build_id(data.get("buildId"), allow_none=False)
    canonical_build_id(data.get("previousBuildId"), allow_none=True)
    if not isinstance(data.get("rolledBack"), bool):
        raise AmpError("deployment record schema mismatch")
    tag = data.get("releaseTag")
    if tag is not None and not isinstance(tag, str):
        raise AmpError("deployment record schema mismatch")
    sha = data.get("sourceSha")
    if not isinstance(sha, str) or not SHA40_RE.fullmatch(sha):
        raise AmpError("deployment record schema mismatch")
    return data


def write_deployment(layout: Layout, obj: dict[str, Any]) -> None:
    required = {
        "buildId": obj.get("buildId"),
        "previousBuildId": obj.get("previousBuildId"),
        "releaseTag": obj.get("releaseTag"),
        "sourceSha": obj.get("sourceSha"),
        "rolledBack": obj.get("rolledBack"),
    }
    load_probe = dict(required)
    # Validate by the same rules without writing first.
    canonical_build_id(load_probe["buildId"], allow_none=False)
    canonical_build_id(load_probe["previousBuildId"], allow_none=True)
    if not isinstance(load_probe["rolledBack"], bool):
        raise AmpError("deployment record schema mismatch")
    sha = load_probe["sourceSha"]
    if not isinstance(sha, str) or not SHA40_RE.fullmatch(sha):
        raise AmpError("deployment record schema mismatch")
    atomic_write_json(layout.deploy_path, required, root=layout.root)


def installed_release_ok(layout: Layout, build_id: str, expected_manifest: dict[str, Any] | None = None) -> Path | None:
    release_dir = layout.releases / build_id
    meta = release_dir / ".amp-identity.json"
    if not release_dir.is_dir() or not meta.is_file():
        return None
    try:
        saved = read_json(meta)
        manifest = validate_manifest(saved.get("manifest"))
        validate_installed_identity(release_dir, manifest)
        if expected_manifest is not None:
            for key in ("sourceSha", "buildId", "releaseTag", "archive"):
                if manifest.get(key) != expected_manifest.get(key):
                    return None
        return release_dir
    except AmpError:
        return None


def download_and_install(
    layout: Layout,
    transport: GitHubTransport,
    token: str,
    release: dict[str, Any],
    tag_commit: str,
) -> tuple[Path, dict[str, Any]]:
    assets = select_assets(release)
    tag = str(release["tag_name"])
    previous = read_current_target(layout)
    prev_name = previous.name if previous else None
    write_txn(
        layout,
        {
            "phase": "downloaded",
            "candidateBuildId": None,
            "previousBuildId": prev_name,
            "complete": False,
        },
    )
    check_cancelled()
    work = layout.incoming / f"dl-{os.getpid()}"
    claim_controller_dir(layout, work, "incoming", None)
    transport.instance_root = layout.root
    try:
        # Fetch small metadata first so an already-installed release can skip the ZIP.
        for name in (ASSET_MANIFEST, ASSET_CHECKSUMS):
            asset_id = assets[name].get("id")
            if not isinstance(asset_id, int):
                raise AmpError(f"Asset {name} missing numeric id")
            log(f"Downloading {name}")
            transport.download_asset(asset_id, token, work / name, cancel_check=check_cancelled)
        check_cancelled()
        checksum_text = (work / ASSET_CHECKSUMS).read_text(encoding="utf-8")
        digests = parse_checksums(checksum_text)
        if sha256_file(work / ASSET_MANIFEST) != digests[ASSET_MANIFEST]:
            raise AmpError("release_manifest.json checksum mismatch")
        manifest = validate_manifest(json.loads((work / ASSET_MANIFEST).read_text(encoding="utf-8")))
        if manifest["releaseTag"] != tag:
            raise AmpError("manifest releaseTag does not match selected GitHub tag")
        if manifest["sourceSha"] != tag_commit:
            raise AmpError("manifest sourceSha does not match tag commit")
        build_id = str(manifest["buildId"])
        existing = installed_release_ok(layout, build_id, manifest)
        if existing is not None:
            log(f"Release {build_id} already installed and verified; skipping ZIP download/extract")
            write_txn(layout, None)
            return existing, manifest

        asset_id = assets[ASSET_ZIP].get("id")
        if not isinstance(asset_id, int):
            raise AmpError(f"Asset {ASSET_ZIP} missing numeric id")
        log(f"Downloading {ASSET_ZIP}")
        transport.download_asset(asset_id, token, work / ASSET_ZIP, cancel_check=check_cancelled)
        check_cancelled()
        manifest = verify_triple_files(work / ASSET_ZIP, work / ASSET_MANIFEST, work / ASSET_CHECKSUMS)
        if manifest["releaseTag"] != tag or manifest["sourceSha"] != tag_commit:
            raise AmpError("manifest identity mismatch after ZIP download")
        build_id = str(manifest["buildId"])

        write_txn(
            layout,
            {
                "phase": "extracting",
                "candidateBuildId": build_id,
                "previousBuildId": previous.name if previous else None,
                "complete": False,
            },
        )
        staging = layout.releases / f".staging-{build_id}"
        claim_controller_dir(layout, staging, "staging", build_id)
        check_cancelled()
        safe_extract(work / ASSET_ZIP, staging, layout.root)
        validate_installed_identity(staging, manifest)
        identity = {
            "manifest": manifest,
            "checksums": checksum_text,
            "tagCommit": tag_commit,
            "releaseTag": tag,
        }
        atomic_write_json(staging / ".amp-identity.json", identity, root=layout.root)
        shutil.copy2(work / ASSET_MANIFEST, staging / ASSET_MANIFEST)
        shutil.copy2(work / ASSET_CHECKSUMS, staging / ASSET_CHECKSUMS)
        final = release_path(layout, build_id)
        if os.path.lexists(final):
            current = read_current_target(layout)
            if current is not None and current.name == build_id:
                raise AmpError("Identity collision with the committed current release")
            recorded = load_deployment(layout)
            if recorded and recorded.get("previousBuildId") == build_id:
                raise AmpError("Identity collision with the previous successful release")
            if not controller_owned_release(layout, build_id):
                raise AmpError("Release path exists but is not a proven controller release")
            safe_rmtree(final, layout.root)
        staging.rename(final)
        write_txn(
            layout,
            {
                "phase": "staging",
                "candidateBuildId": build_id,
                "previousBuildId": previous.name if previous else None,
                "complete": True,
            },
        )
        return final, manifest
    finally:
        if controller_owns_work(work, "incoming", None):
            safe_rmtree(work, layout.root)


def child_env_for(layout: Layout, data_dir: Path, port: int, host: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in _GAME_ENV_PASSTHROUGH:
        value = os.environ.get(key)
        if value:
            env[key] = value
    env[PORT_ENV] = str(port)
    env[HOST_ENV] = host
    env[DATA_DIR_ENV] = str(data_dir)
    origins = os.environ.get(ORIGINS_ENV, "").strip()
    env[ORIGINS_ENV] = origins or "https://oldgrid.io"
    trusted = os.environ.get(TRUSTED_PROXY_ENV, "")
    if trusted:
        env[TRUSTED_PROXY_ENV] = trusted
    return env


def select_retained_previous(current_name: str | None, starting_name: str, recorded: dict[str, Any] | None) -> str | None:
    """Previous successful release id, stable across a same-release restart."""
    if recorded and current_name == starting_name and recorded.get("buildId") == starting_name:
        prev = recorded.get("previousBuildId")
        return prev if isinstance(prev, str) else None
    if current_name and current_name != starting_name:
        return current_name
    if recorded:
        prev = recorded.get("previousBuildId")
        return prev if isinstance(prev, str) else None
    return None


def promote_and_supervise(
    layout: Layout,
    release_dir: Path,
    manifest: dict[str, Any],
    *,
    data_dir: Path,
    port: int,
    host: str,
    lock_fd: int,
    rolled_back: bool = False,
) -> int:
    global _active_child
    previous = read_current_target(layout)
    recorded = load_deployment(layout)
    prev_id = select_retained_previous(previous.name if previous else None, release_dir.name, recorded)
    write_txn(
        layout,
        {
            "phase": "activating",
            "candidateBuildId": release_dir.name,
            "previousBuildId": prev_id,
            "complete": False,
        },
    )
    env = child_env_for(layout, data_dir, port, host)
    child = launch_run_sh(release_dir / ENTRYPOINT, label="candidate", env=env, lock_fd=lock_fd, cwd=release_dir)
    try:
        wait_ready(port=port, child=child, expected=manifest)
    except (AmpError, Cancelled) as exc:
        log(f"Candidate failed readiness: {exc}")
        stop_child(child, reason="candidate-failed")
        wait_port_free(port)
        if _stop_requested:
            write_txn(layout, None)
            raise
        if previous is None:
            write_txn(layout, None)
            raise AmpError("First install failed; no previous release to roll back to") from exc
        failed = layout.releases / f"failed-{release_dir.name}"
        if (
            release_dir.exists()
            and not os.path.islink(release_dir)
            and previous.resolve() != release_dir.resolve()
            and controller_owned_release(layout, release_dir.name)
        ):
            if os.path.lexists(failed):
                if os.path.islink(failed) or not controller_owned_failed(failed):
                    raise AmpError("Refusing to replace an unowned failed-release directory")
                safe_rmtree(failed, layout.root)
            try:
                release_dir.rename(failed)
            except OSError as rename_exc:
                raise AmpError(f"Could not retain failed candidate: {rename_exc}") from rename_exc
        try:
            prev_manifest = read_installed_manifest_structure(previous)
        except AmpError as parse_exc:
            write_txn(layout, None)
            raise AmpError("No checkpoint-compatible rollback release is available") from parse_exc
        if not is_checkpoint_compatible(prev_manifest):
            write_txn(layout, None)
            raise AmpError("No checkpoint-compatible rollback release is available") from exc
        log(f"Rolling back code to {previous.name}")
        rb_manifest = validate_manifest(prev_manifest)
        check_cancelled()
        rb_child = launch_run_sh(previous / ENTRYPOINT, label="rollback", env=env, lock_fd=lock_fd, cwd=previous)
        try:
            wait_ready(port=port, child=rb_child, expected=rb_manifest)
        except (AmpError, Cancelled) as rb_exc:
            stop_child(rb_child, reason="rollback-failed")
            raise AmpError(f"Rollback failed: {rb_exc}") from rb_exc
        if _stop_requested:
            stop_child(rb_child, reason="stop")
            raise Cancelled("Stop requested before rollback publication")
        kept_prev = None
        if recorded and recorded.get("buildId") == previous.name:
            prior = recorded.get("previousBuildId")
            kept_prev = prior if isinstance(prior, str) else None
        atomic_symlink(layout, previous)
        write_deployment(
            layout,
            {
                "buildId": previous.name,
                "previousBuildId": kept_prev,
                "releaseTag": rb_manifest["releaseTag"],
                "sourceSha": rb_manifest["sourceSha"],
                "rolledBack": True,
            },
        )
        write_txn(layout, None)
        apply_retention(layout, previous.name, kept_prev)
        log(f"{READY_PREFIX} port={port} build={previous.name} rollback=1")
        return supervise_until_exit(rb_child)

    if _stop_requested:
        stop_child(child, reason="stop")
        raise Cancelled("Stop requested before promotion")
    atomic_symlink(layout, release_dir)
    kept_previous = prev_id
    if previous is not None and previous.name != release_dir.name:
        kept_previous = previous.name
    write_deployment(
        layout,
        {
            "buildId": release_dir.name,
            "previousBuildId": kept_previous,
            "releaseTag": manifest["releaseTag"],
            "sourceSha": manifest["sourceSha"],
            "rolledBack": False,
        },
    )
    write_txn(layout, None)
    apply_retention(layout, release_dir.name, kept_previous)
    log(f"{READY_PREFIX} port={port} build={release_dir.name}")
    return supervise_until_exit(child)


def supervise_until_exit(child: ChildProc) -> int:
    global _active_child
    _active_child = child
    while child.alive():
        if _stop_requested:
            code = stop_child(child, reason="stop")
            return 0 if code == 0 else (code if code is not None else 1)
        time.sleep(0.2)
    code = child.proc.poll()
    log(f"Supervised child exited code={code}")
    _active_child = None
    return int(code if code is not None else 1)


def run_existing_current(
    layout: Layout,
    *,
    data_dir: Path,
    port: int,
    host: str,
    lock_fd: int,
) -> int:
    current = read_current_target(layout)
    if current is None:
        raise AmpError("No verified current release installed")
    try:
        structured = read_installed_manifest_structure(current)
    except AmpError as exc:
        raise AmpError(f"Installed current release identity is invalid: {exc}") from exc
    if not is_checkpoint_compatible(structured):
        raise AmpError("Installed current release is checkpoint-incompatible with this controller")
    manifest = validate_manifest(structured)
    validate_installed_identity(current, manifest)
    env = child_env_for(layout, data_dir, port, host)
    child = launch_run_sh(current / ENTRYPOINT, label="current", env=env, lock_fd=lock_fd, cwd=current)
    try:
        wait_ready(port=port, child=child, expected=manifest)
    except (AmpError, Cancelled) as exc:
        stop_child(child, reason="current-failed")
        raise AmpError(f"Existing current failed readiness: {exc}") from exc
    log(f"{READY_PREFIX} port={port} build={current.name}")
    return supervise_until_exit(child)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def require_tools() -> None:
    for tool in ("python3",):
        # We are already python3; still document.
        _ = tool
    if shutil.which("bash") is None and os.name == "posix":
        # bash is required for AMP Start wrapper; controller itself is python.
        log("WARNING: bash not found on PATH (required for AMP Start wrapper)")


def parse_port(raw: str | None) -> int:
    text = (raw or "").strip()
    if not text:
        raise AmpError("PORT is required")
    if not re.match(r"^[1-9][0-9]{0,4}$", text):
        raise AmpError("PORT must be 1..65535")
    port = int(text)
    if port < 1 or port > 65535:
        raise AmpError("PORT must be 1..65535")
    return port


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    assert_no_secrets_in_argv(sys.argv)
    parser = argparse.ArgumentParser(description="OldGrid.io AMP controller")
    parser.add_argument("--instance-root", default=os.getcwd())
    parser.add_argument("--deploy-and-supervise", action="store_true", default=True)
    parser.add_argument("--check-only", action="store_true")
    args, _unknown = parser.parse_known_args(argv)

    install_signal_handlers()
    require_tools()

    layout = make_layout(Path(args.instance_root))
    ensure_layout(layout)
    install_controller_log(layout.root)

    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        register_secret(token)
    tag_override = os.environ.get(TAG_ENV, "").strip()
    port = parse_port(os.environ.get(PORT_ENV))
    host = os.environ.get(HOST_ENV, "").strip() or "127.0.0.1"
    data_dir = resolve_data_dir(os.environ.get(DATA_DIR_ENV, "server_data"), layout)

    lock_fd = acquire_instance_lock(layout)
    log(f"Instance lock acquired fd={lock_fd} pid={os.getpid()}")
    try:
        recover_transaction(layout)
        check_cancelled()

        if args.check_only:
            log("check-only complete")
            return 0

        if not token:
            # Offline path: run verified current if present.
            log("No POOBIVERSE_GITHUB_TOKEN; attempting existing current")
            return run_existing_current(layout, data_dir=data_dir, port=port, host=host, lock_fd=lock_fd)

        transport = github_transport()
        transport.instance_root = layout.root
        try:
            release = fetch_selected_release(transport, token, tag_override)
            tag_commit = resolve_release_commit(transport, token, release)
            release_dir, manifest = download_and_install(layout, transport, token, release, tag_commit)
        except Cancelled:
            log("Cancelled before child start")
            return 1
        except AmpError as exc:
            log(f"Update selection/install failed: {exc}")
            if read_current_target(layout) is not None and not _stop_requested:
                log("Preserving verified current")
                return run_existing_current(layout, data_dir=data_dir, port=port, host=host, lock_fd=lock_fd)
            raise

        check_cancelled()
        return promote_and_supervise(
            layout,
            release_dir,
            manifest,
            data_dir=data_dir,
            port=port,
            host=host,
            lock_fd=lock_fd,
        )
    except Cancelled:
        log("Cancelled")
        stop_child(_active_child, reason="cancelled")
        return 1
    except AmpError as exc:
        log(f"ERROR: {exc}")
        stop_child(_active_child, reason="error")
        return 1
    except Exception as exc:  # noqa: BLE001
        log(f"ERROR: unexpected: {redact(str(exc))}")
        log(redact(traceback.format_exc()))
        stop_child(_active_child, reason="unexpected")
        return 1
    finally:
        # Lock FD stays open until process exit so inherited children keep it.
        pass


if __name__ == "__main__":
    sys.exit(main())
