#!/bin/sh
# ==============================================================================
# Container entrypoint.
#
# Prepares the writable locations the panel needs, then hands off to the CMD.
# Everything here is best-effort: a read-only or oddly-mounted volume must never
# stop the panel from booting.
# ==============================================================================
set -e

DATA_DIR="${DATA_DIR:-/data}"
VENDOR_DIR="${VENDOR_DIR:-/app/vendor}"

mkdir -p "$DATA_DIR" "$VENDOR_DIR" 2>/dev/null || true

# Railway volumes are usually root-owned; make sure the data directory is
# writable by the process that will actually run.
if [ ! -w "$DATA_DIR" ]; then
  chmod 0777 "$DATA_DIR" 2>/dev/null || true
fi
if [ ! -w "$VENDOR_DIR" ]; then
  chmod 0777 "$VENDOR_DIR" 2>/dev/null || true
fi

if [ ! -w "$DATA_DIR" ]; then
  echo "[entrypoint] WARNING: $DATA_DIR is not writable; panel settings and" >&2
  echo "[entrypoint]          tunnels will not survive a redeploy." >&2
fi

if [ -x /usr/local/bin/anytls-server ]; then
  echo "[entrypoint] anytls-server: $(/usr/local/bin/anytls-server --version 2>&1 | head -n1 || echo present)"
else
  echo "[entrypoint] anytls-server not baked in; the panel will download it on demand."
fi

exec "$@"