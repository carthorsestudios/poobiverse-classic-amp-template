#!/usr/bin/env python3
"""Generate/validate the Classic AMP bootstrap pin and encoded Start command.

Pins CONTROLLER_SHA256 from control/poobiverse_amp.py (LF-normalized), embeds it
into tools/bootstrap_source.sh, and writes App.CommandLineArgs in
poobiverseclassic.kvp using the proven AMP space-safe base64 wrapper:

  /bin/bash -lc eval${IFS}$(printf${IFS}%s${IFS}<b64>|base64${IFS}-d)

Usage:
  python tools/generate_bootstrap.py          # write pins + kvp
  python tools/generate_bootstrap.py --check  # validate only
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROLLER = ROOT / "control" / "poobiverse_amp.py"
BOOTSTRAP = ROOT / "tools" / "bootstrap_source.sh"
KVP = ROOT / "poobiverseclassic.kvp"

WRAPPER_PREFIX = "eval${IFS}$(printf${IFS}%s${IFS}"
WRAPPER_SUFFIX = "|base64${IFS}-d)"
PIN_RE = re.compile(r"^CONTROLLER_SHA256=([0-9a-f]*)$", re.MULTILINE)
ARGS_RE = re.compile(r"^App\.CommandLineArgs=.*$", re.MULTILINE)


def normalize_newlines(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def controller_digest() -> str:
    if not CONTROLLER.is_file():
        raise SystemExit(f"Missing {CONTROLLER}")
    return hashlib.sha256(normalize_newlines(CONTROLLER.read_bytes())).hexdigest()


def installer_to_one_liner(script: str) -> str:
    lines: list[str] = []
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        while line.endswith(";"):
            line = line[:-1].rstrip()
        lines.append(line)
    if not lines:
        raise SystemExit("bootstrap source is empty")
    result = lines[0]
    join_with_space_after = ("{", "then", "else", "do", "&&", "||")
    for line in lines[1:]:
        if result.endswith(join_with_space_after):
            result = f"{result} {line}"
        else:
            result = f"{result}; {line}"
    return result


def encode_bootstrap(script: str) -> str:
    return base64.b64encode(installer_to_one_liner(script).encode("utf-8")).decode("ascii")


def build_start_args(script: str) -> str:
    return f"-lc {WRAPPER_PREFIX}{encode_bootstrap(script)}{WRAPPER_SUFFIX}"


def decode_from_args(cmd: str) -> str:
    match = re.search(
        r"printf\$\{IFS\}%s\$\{IFS\}([A-Za-z0-9+/=]+)\|base64\$\{IFS\}-d\)",
        cmd,
    )
    if not match:
        raise SystemExit("App.CommandLineArgs missing expected base64 bootstrap payload")
    return base64.b64decode(match.group(1)).decode("utf-8")


def write_pin(script: str, digest: str) -> str:
    updated, count = PIN_RE.subn(f"CONTROLLER_SHA256={digest}", script, count=1)
    if count != 1:
        raise SystemExit("bootstrap_source.sh must contain exactly one CONTROLLER_SHA256= line")
    return updated


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    digest = controller_digest()
    bootstrap_text = BOOTSTRAP.read_text(encoding="utf-8")
    pinned = PIN_RE.search(bootstrap_text)
    if not pinned:
        raise SystemExit("CONTROLLER_SHA256 missing from bootstrap_source.sh")
    current_pin = pinned.group(1)

    if check_only:
        errors: list[str] = []
        if current_pin != digest:
            errors.append(f"stale pin: bootstrap has {current_pin}, controller is {digest}")
        if not KVP.is_file():
            errors.append("missing poobiverseclassic.kvp")
        else:
            kvp = KVP.read_text(encoding="utf-8")
            m = ARGS_RE.search(kvp)
            if not m:
                errors.append("App.CommandLineArgs missing")
            else:
                args = m.group(0).split("=", 1)[1]
                parts = args.split(" ")
                if len(parts) != 2 or parts[0] != "-lc":
                    errors.append("App.CommandLineArgs must be exactly two AMP argv tokens: -lc <wrapper>")
                decoded = decode_from_args(args)
                if f"CONTROLLER_SHA256={digest}" not in decoded and f"CONTROLLER_SHA256={current_pin}" not in decoded:
                    errors.append("decoded Start command does not carry CONTROLLER_SHA256")
                if current_pin == digest:
                    expected = build_start_args(write_pin(bootstrap_text, digest))
                    if args != expected:
                        errors.append("decoded-command drift: App.CommandLineArgs does not match regenerated bootstrap")
                # Ensure decoded form execs python (not tee / background).
                if "exec python3" not in decoded:
                    errors.append("decoded bootstrap must exec python3")
                if "| tee" in decoded or " tee " in decoded:
                    errors.append("decoded bootstrap must not use tee")
        if errors:
            for err in errors:
                print(f"ERROR: {err}", file=sys.stderr)
            return 1
        print(f"ok CONTROLLER_SHA256={digest}")
        return 0

    updated_bootstrap = write_pin(bootstrap_text, digest)
    BOOTSTRAP.write_text(updated_bootstrap, encoding="utf-8", newline="\n")
    start_args = build_start_args(updated_bootstrap)
    kvp = KVP.read_text(encoding="utf-8")
    new_kvp, count = ARGS_RE.subn(f"App.CommandLineArgs={start_args}", kvp, count=1)
    if count != 1:
        raise SystemExit("Failed to update App.CommandLineArgs in poobiverseclassic.kvp")
    KVP.write_text(new_kvp, encoding="utf-8", newline="\n")
    print(f"CONTROLLER_SHA256={digest}")
    print("Wrote tools/bootstrap_source.sh and App.CommandLineArgs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
