#!/bin/sh
# End-to-end test of backup.sh and restore-drill.sh against a real Postgres.
# Run from the repo root: ops/test.sh (needs docker).
#
# Guarantees checked:
#   - a backup that cannot reach the offsite remote fails the job
#   - a good backup is verified offsite and stamps last-success
#   - the drill passes on a good backup and fails, for the stated reason, on a
#     stale one and on a restored database without users
set -eu

PG_IMAGE=$(sed -n 's/^FROM \(postgres:[^ ]*\).*/\1/p' ops/Dockerfile)
IMAGE=nopwd-ops:test
NET=nopwd-ops-test-$$

cleanup() {
  docker rm -f "$NET-db" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NET-backups" "$NET-tmp" "$NET-offsite" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() { echo "TEST FAILED: $*" >&2; exit 1; }

docker build -q -f ops/Dockerfile -t "$IMAGE" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$NET-db" --network "$NET" \
  -e POSTGRES_PASSWORD=t -e POSTGRES_USER=nopass -e POSTGRES_DB=nopass_test \
  "$PG_IMAGE" >/dev/null
until docker exec "$NET-db" pg_isready -U nopass -d nopass_test >/dev/null 2>&1; do sleep 1; done
sleep 2

psql_db() { docker exec -i "$NET-db" psql -q -U nopass -d nopass_test -v ON_ERROR_STOP=1 "$@"; }
for f in crates/nopass-api/src/db/migrations/*.sql; do psql_db < "$f"; done
# sqlx's bookkeeping table, as the API leaves it
psql_db -c "CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, success BOOLEAN NOT NULL);
            INSERT INTO _sqlx_migrations VALUES (1, true), (13, true);
            INSERT INTO users (email_hash, srp_salt, srp_verifier, kdf_params, protected_symmetric_key, protected_symmetric_key_iv)
            VALUES ('h', '\\x01', 'v'::bytea, '{}', '\\x01', '\\x01');" \
  || fail "seeding failed (users columns changed? update the seed)"

# Named volumes rather than bind mounts: Docker Desktop reports bind-mounted
# files as root-owned, and git refuses repositories owned by another user
docker volume create "$NET-backups" >/dev/null
docker volume create "$NET-tmp" >/dev/null
docker volume create "$NET-offsite" >/dev/null

# Runs a command in the ops image with the test volumes, as the job's user
in_volumes() {
  user=$1; shift
  docker run --rm --user "$user" --network "$NET" \
    -v "$NET-backups:/backups" -v "$NET-tmp:/tmp" -v "$NET-offsite:/offsite.git" "$@"
}
in_volumes root --entrypoint chown "$IMAGE" -R 70:70 /backups /tmp /offsite.git
in_volumes 70 --entrypoint git "$IMAGE" init -q --bare /offsite.git

run_in_image() {
  script=$1; shift
  # --entrypoint mirrors the CronJob's command, which replaces the image entrypoint
  in_volumes 70 --entrypoint "$script" \
    -e DATABASE_URL="postgres://nopass:t@$NET-db:5432/nopass_test" \
    -e BACKUP_PASSPHRASE="${PASS:-correct}" "$@" "$IMAGE"
}

echo "backup with an unreachable offsite remote must fail"
if OUT=$(run_in_image backup.sh -e OFFSITE_REPO=/does-not-exist.git 2>&1); then
  fail "backup succeeded although the offsite push could not work"
fi
# the dump and its decrypt check passed, so the failure must come from the push
echo "$OUT" | grep -q "does-not-exist.git" || fail "backup failed for another reason: $OUT"
in_volumes 70 --entrypoint sh "$IMAGE" -c '[ ! -e /backups/last-success ] && rm -f /backups/nopwd-*.dump.enc' \
  || fail "last-success stamped for a failed backup"

echo "backup with a reachable remote must pass and be verified"
run_in_image backup.sh -e OFFSITE_REPO=/offsite.git >/dev/null || fail "good backup failed"
# shellcheck disable=SC2016
in_volumes 70 --entrypoint sh "$IMAGE" -c '[ -s /backups/last-success ] && [ "$(git -C /offsite.git ls-tree --name-only main | wc -l)" -eq 1 ]' \
  || fail "last-success missing or the offsite does not hold the dump"

echo "drill on a good backup must pass"
run_in_image restore-drill.sh >/dev/null || fail "drill failed on a good backup"

echo "drill on a stale backup must fail"
in_volumes 70 --entrypoint sh "$IMAGE" -c 'mv /backups/nopwd-2*.dump.enc /backups/nopwd-20200101-000000.dump.enc'
if OUT=$(run_in_image restore-drill.sh 2>&1); then fail "drill passed on a stale backup"; fi
echo "$OUT" | grep -q "RESTORE DRILL FAILED: newest backup is" || fail "stale backup failed for another reason: $OUT"

echo "drill on a database without users must fail"
psql_db -c "DELETE FROM users"
in_volumes 70 --entrypoint sh "$IMAGE" -c 'rm -f /backups/nopwd-*.dump.enc' 
run_in_image backup.sh -e OFFSITE_REPO=/offsite.git >/dev/null || fail "backup of empty database failed"
if OUT=$(run_in_image restore-drill.sh 2>&1); then fail "drill passed on a database without users"; fi
echo "$OUT" | grep -q "RESTORE DRILL FAILED: users table is empty" || fail "empty database failed for another reason: $OUT"

echo "ops tests passed"
