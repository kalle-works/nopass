#!/bin/sh
# Monthly restore drill: decrypts the newest local backup, restores it into a
# throwaway Postgres running inside this pod, and checks the result. Exits
# non-zero on any failed check, so a failed Job is the alert.
#
# Reads both dump formats: nopwd-*.dump.age (age, identity in AGE_IDENTITY_FILE)
# and the older nopwd-*.dump.enc (openssl AES-256-CBC, BACKUP_PASSPHRASE).
#
# Env: AGE_IDENTITY_FILE (default /age/identity), BACKUP_PASSPHRASE (legacy dumps only)
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups}"
WORK_DIR="${WORK_DIR:-/tmp}"
MAX_AGE_HOURS="${MAX_AGE_HOURS:-36}"
AGE_IDENTITY_FILE="${AGE_IDENTITY_FILE:-/age/identity}"
PGDATA="$WORK_DIR/pgdata"
SOCKET_DIR="$WORK_DIR/pgsock"

fail() {
  echo "RESTORE DRILL FAILED: $*" >&2
  exit 1
}

# shellcheck disable=SC2012
LATEST=$(ls -1t "$BACKUP_DIR"/nopwd-*.dump.age "$BACKUP_DIR"/nopwd-*.dump.enc 2>/dev/null | head -n 1 || true)
[ -n "$LATEST" ] || fail "no backups in $BACKUP_DIR"
echo "drilling $LATEST"

# The filename carries the UTC timestamp; a drill of a stale backup proves
# nothing about last night's job
STAMP=$(basename "$LATEST" | sed -E 's/^nopwd-([0-9]{8})-([0-9]{6})\.dump\.(age|enc)$/\1\2/')
BACKUP_EPOCH=$(date -u -d "$(echo "$STAMP" | sed -E 's/^(....)(..)(..)(..)(..)(..)$/\1-\2-\3 \4:\5:\6/')" +%s) \
  || fail "cannot parse timestamp from $LATEST"
AGE_HOURS=$(( ($(date -u +%s) - BACKUP_EPOCH) / 3600 ))
[ "$AGE_HOURS" -le "$MAX_AGE_HOURS" ] || fail "newest backup is ${AGE_HOURS}h old (limit ${MAX_AGE_HOURS}h)"

case "$LATEST" in
  *.dump.age)
    [ -r "$AGE_IDENTITY_FILE" ] || fail "no age identity at $AGE_IDENTITY_FILE"
    age -d -i "$AGE_IDENTITY_FILE" -o "$WORK_DIR/restore.dump" "$LATEST" || fail "decryption failed"
    ;;
  *.dump.enc)
    [ -n "${BACKUP_PASSPHRASE:-}" ] || fail "legacy dump needs BACKUP_PASSPHRASE"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
      -in "$LATEST" -out "$WORK_DIR/restore.dump" -pass env:BACKUP_PASSPHRASE \
      || fail "decryption failed"
    ;;
esac
trap 'rm -f "$WORK_DIR/restore.dump"; pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true' EXIT

rm -rf "$PGDATA" "$SOCKET_DIR"
mkdir -p "$SOCKET_DIR"
initdb -D "$PGDATA" -U drill --auth=trust >/dev/null
pg_ctl -D "$PGDATA" -w -o "-c listen_addresses='' -c unix_socket_directories=$SOCKET_DIR" start >/dev/null

export PGHOST="$SOCKET_DIR" PGUSER=drill
createdb drill
# --no-owner/--no-privileges: the production roles do not exist here
pg_restore -d drill --no-owner --no-privileges --exit-on-error "$WORK_DIR/restore.dump" \
  || fail "pg_restore reported errors"

# Prints the first column of the single-row result of a query
q() { psql -d drill -At -v ON_ERROR_STOP=1 -c "$1"; }

for t in users devices vaults vault_items sync_events sessions; do
  [ "$(q "SELECT to_regclass('public.$t') IS NOT NULL")" = "t" ] || fail "table $t missing"
done

[ "$(q "SELECT count(*) FROM _sqlx_migrations")" -gt 0 ] || fail "no applied migrations recorded"
[ "$(q "SELECT count(*) FROM _sqlx_migrations WHERE NOT success")" = "0" ] || fail "restored database records a failed migration"

USERS=$(q "SELECT count(*) FROM users")
[ "$USERS" -gt 0 ] || fail "users table is empty"

# An account without its wrapped vault key or SRP verifier cannot log in
# after a restore, even though the columns are NOT NULL
BROKEN=$(q "SELECT count(*) FROM users WHERE length(protected_symmetric_key) = 0 OR length(srp_verifier) = 0")
[ "$BROKEN" = "0" ] || fail "$BROKEN users lack key material"

echo "restore drill passed: $USERS users, $(q "SELECT count(*) FROM vault_items") vault items, backup ${AGE_HOURS}h old"
