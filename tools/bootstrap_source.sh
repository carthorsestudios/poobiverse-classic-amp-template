#!/usr/bin/env bash
# Readable AMP Start bootstrap for OldGrid.io.
# Embedded into poobiverseclassic.kvp via tools/generate_bootstrap.py (base64 + ${IFS} wrapper).
# Pins CONTROLLER_SHA256 from control/poobiverse_amp.py. Never hand-edit the pin.
#
# Trust: download the public controller into a private same-directory temp file, verify
# SHA-256 against the template pin, then atomically publish it. Never follow a destination
# symlink and never exec a digest mismatch. Offline restarts reuse a pin-matching cache.
# A changed controller pin is a template refresh, not routine operator work.
set -e
CONTROLLER_URL=https://raw.githubusercontent.com/carthorsestudios/poobiverse-classic-amp-template/main/control/poobiverse_amp.py
CONTROLLER_SHA256=dba81ec588e3d1dd4ee425e4b4aa0bd7061708521409e45eb8b819281d86d077
CONTROLLER_MODE=700
CONTROL_DIR=control
CACHE_DIR=control/cache
DL_PID=
TMP=

need() {
	command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required tool missing: $1" >&2; exit 1; }
}
need bash
need mktemp
need python3
if command -v sha256sum >/dev/null 2>&1; then
	digest_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	digest_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	digest_of() { python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
fi

on_signal() {
	if test -n "$DL_PID"; then
		kill "$DL_PID" 2>/dev/null || true
		wait "$DL_PID" 2>/dev/null || true
		DL_PID=
	fi
	if test -n "$TMP"; then
		rm -f "$TMP"
		TMP=
	fi
	exit 1
}
trap on_signal TERM INT

if test -L "$CONTROL_DIR" || test -L "$CACHE_DIR"; then
	echo "ERROR: refusing symlinked control directory" >&2
	exit 1
fi
mkdir -p "$CONTROL_DIR" "$CACHE_DIR"
if test -L "$CONTROL_DIR" || test -L "$CACHE_DIR"; then
	echo "ERROR: refusing symlinked control directory" >&2
	exit 1
fi
chmod 700 "$CONTROL_DIR" "$CACHE_DIR" 2>/dev/null || true

CACHE_FILE="$CACHE_DIR/poobiverse_amp-$CONTROLLER_SHA256.py"
AUTHORITATIVE="$CONTROL_DIR/poobiverse_amp.py"

verify_file() {
	test ! -L "$1" || { echo "ERROR: refusing symlink $1" >&2; return 1; }
	test -f "$1" || return 1
	test -s "$1" || { echo "ERROR: refusing empty $1" >&2; return 1; }
	got=$(digest_of "$1") || return 1
	test "$got" = "$CONTROLLER_SHA256" || { echo "ERROR: controller digest mismatch" >&2; return 1; }
}

publish_atomic() {
	src="$1"
	dest="$2"
	parent=$(dirname "$dest")
	if test -L "$dest" || test -L "$parent" || test -L "$src"; then
		echo "ERROR: refusing unsafe controller publication path" >&2
		return 1
	fi
	stage=$(mktemp "$parent/.publish.XXXXXX")
	cp "$src" "$stage"
	chmod "$CONTROLLER_MODE" "$stage"
	if ! verify_file "$stage"; then
		rm -f "$stage"
		return 1
	fi
	if test -L "$dest"; then
		rm -f "$stage"
		echo "ERROR: refusing symlink destination $dest" >&2
		return 1
	fi
	mv -T "$stage" "$dest"
}

exec_verified_cache() {
	chmod "$CONTROLLER_MODE" "$CACHE_FILE" 2>/dev/null || true
	if test -L "$AUTHORITATIVE"; then
		echo "ERROR: authoritative controller is a symlink; executing verified cache" >&2
		exec python3 "$CACHE_FILE" --deploy-and-supervise
	fi
	if ! publish_atomic "$CACHE_FILE" "$AUTHORITATIVE"; then
		echo "ERROR: atomic publish refused; executing verified cache" >&2
		exec python3 "$CACHE_FILE" --deploy-and-supervise
	fi
	exec python3 "$AUTHORITATIVE" --deploy-and-supervise
}

if verify_file "$CACHE_FILE"; then
	exec_verified_cache
fi

TMP=$(mktemp "$CONTROL_DIR/.tmp-poobiverse_amp.XXXXXX")
fetch_ok=0
if command -v curl >/dev/null 2>&1; then
	curl -fsSL --max-time 30 "$CONTROLLER_URL" -o "$TMP" & DL_PID=$!
	if wait "$DL_PID"; then fetch_ok=1; fi
	DL_PID=
elif command -v wget >/dev/null 2>&1; then
	wget -q -T 30 -O "$TMP" "$CONTROLLER_URL" & DL_PID=$!
	if wait "$DL_PID"; then fetch_ok=1; fi
	DL_PID=
else
	python3 -c 'import socket,sys,urllib.request; socket.setdefaulttimeout(30); urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$CONTROLLER_URL" "$TMP" & DL_PID=$!
	if wait "$DL_PID"; then fetch_ok=1; fi
	DL_PID=
fi

if test "$fetch_ok" -eq 1 && verify_file "$TMP"; then
	if test -L "$CACHE_FILE"; then
		echo "ERROR: refusing symlinked cache file" >&2
	else
		publish_atomic "$TMP" "$CACHE_FILE" || true
	fi
	rm -f "$TMP"
	TMP=
	if verify_file "$CACHE_FILE"; then
		exec_verified_cache
	fi
fi

if test -n "$TMP"; then
	rm -f "$TMP"
	TMP=
fi

if verify_file "$CACHE_FILE"; then
	echo "WARNING: download/verify failed; reusing pin-matching cached controller" >&2
	exec_verified_cache
fi

if verify_file "$AUTHORITATIVE"; then
	echo "WARNING: download/verify failed; reusing pin-matching authoritative controller" >&2
	exec python3 "$AUTHORITATIVE" --deploy-and-supervise
fi

echo "ERROR: no verified controller available (first install requires a successful pinned download)" >&2
exit 1
