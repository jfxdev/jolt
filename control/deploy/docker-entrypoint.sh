#!/bin/sh
set -eu

JOLT_PUID="${PUID:-${UID:-1000}}"
JOLT_PGID="${PGID:-${GID:-1000}}"
JOLT_UMASK="${UMASK:-077}"
JOLT_CONTROL_DATA="${CONTROL_TOWER_DATA_DIR:-/var/lib/jolt-control}"

fail() {
  echo "jolt-control: $*" >&2
  exit 1
}

case "$JOLT_PUID" in
  ''|*[!0-9]*) fail "PUID must be a numeric UID, got '$JOLT_PUID'" ;;
esac
case "$JOLT_PGID" in
  ''|*[!0-9]*) fail "PGID must be a numeric GID, got '$JOLT_PGID'" ;;
esac
case "$JOLT_UMASK" in
  ???|0???)
    case "$JOLT_UMASK" in *[!0-7]*) fail "UMASK must contain only octal digits, got '$JOLT_UMASK'" ;; esac
    ;;
  *) fail "UMASK must be a three- or four-digit octal value, got '$JOLT_UMASK'" ;;
esac

prepare_data_directory() {
  mkdir -p "$JOLT_CONTROL_DATA" || fail "cannot create internal directory $JOLT_CONTROL_DATA"
  chown -R "$JOLT_PUID:$JOLT_PGID" "$JOLT_CONTROL_DATA" || \
    fail "cannot set $JOLT_PUID:$JOLT_PGID on $JOLT_CONTROL_DATA"
  chmod 0700 "$JOLT_CONTROL_DATA" || fail "cannot set mode 0700 on $JOLT_CONTROL_DATA"
}

validate_access() {
  [ -d "$JOLT_CONTROL_DATA" ] && [ -r "$JOLT_CONTROL_DATA" ] && \
    [ -w "$JOLT_CONTROL_DATA" ] && [ -x "$JOLT_CONTROL_DATA" ] || \
    fail "$JOLT_CONTROL_DATA is not accessible to UID:GID $JOLT_PUID:$JOLT_PGID; run without Docker user: override or correct the volume ownership"
}

umask "$JOLT_UMASK"

if [ "$(id -u)" = "0" ]; then
  prepare_data_directory
  exec su-exec "$JOLT_PUID:$JOLT_PGID" "$@"
fi

if [ "$(id -u)" != "$JOLT_PUID" ] || [ "$(id -g)" != "$JOLT_PGID" ]; then
  fail "container started as $(id -u):$(id -g), but PUID:PGID is $JOLT_PUID:$JOLT_PGID"
fi
validate_access
exec "$@"
