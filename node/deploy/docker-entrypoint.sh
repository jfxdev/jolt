#!/bin/sh
set -eu

JOLT_PUID="${PUID:-${UID:-1000}}"
JOLT_PGID="${PGID:-${GID:-1000}}"
JOLT_UMASK="${UMASK:-002}"
JOLT_DATA_PATH="${JOLT_DATA_DIR:-/var/lib/jolt}"
JOLT_KEYS_PATH="${JOLT_KEYS_DIR:-/var/lib/jolt-keys}"
JOLT_OWNED_PATHS="${JOLT_OWNED_PATHS:-}"

fail() {
  echo "jolt-node: $*" >&2
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

prepare_internal_directory() {
  path="$1"
  mode="$2"
  mkdir -p "$path" || fail "cannot create internal directory $path"
  chown -R "$JOLT_PUID:$JOLT_PGID" "$path" || fail "cannot set $JOLT_PUID:$JOLT_PGID on $path"
  chmod "$mode" "$path" || fail "cannot set mode $mode on $path"
}

prepare_mount_directory() {
  path="$1"
  [ -n "$path" ] && [ "$path" != "/" ] || fail "refusing unsafe JOLT_OWNED_PATHS entry '$path'"
  [ -d "$path" ] || fail "managed mount $path is not mounted as a directory"
  chown -R "$JOLT_PUID:$JOLT_PGID" "$path" || fail "cannot set $JOLT_PUID:$JOLT_PGID on managed mount $path"
}

validate_access() {
  path="$1"
  [ -d "$path" ] && [ -r "$path" ] && [ -w "$path" ] && [ -x "$path" ] || \
    fail "$path is not accessible to UID:GID $JOLT_PUID:$JOLT_PGID; run without Docker user: override or correct the volume ownership"
}

umask "$JOLT_UMASK"

if [ "$(id -u)" = "0" ]; then
  prepare_internal_directory "$JOLT_DATA_PATH" 0750
  prepare_internal_directory "$JOLT_KEYS_PATH" 0700

  OLD_IFS="$IFS"
  IFS=:
  set -f
  for path in $JOLT_OWNED_PATHS; do
    [ -n "$path" ] && prepare_mount_directory "$path"
  done
  set +f
  IFS="$OLD_IFS"

  exec su-exec "$JOLT_PUID:$JOLT_PGID" "$@"
fi

if [ "$(id -u)" != "$JOLT_PUID" ] || [ "$(id -g)" != "$JOLT_PGID" ]; then
  fail "container started as $(id -u):$(id -g), but PUID:PGID is $JOLT_PUID:$JOLT_PGID"
fi
validate_access "$JOLT_DATA_PATH"
validate_access "$JOLT_KEYS_PATH"
exec "$@"
