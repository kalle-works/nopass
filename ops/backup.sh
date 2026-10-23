#!/bin/sh
# Nightly encrypted dump of the nopwd database, kept on the Hetzner volume
# (14 newest) and pushed offsite (7 newest, single rolling commit).
#
# The job succeeds only when the dump decrypts and lists, and the offsite
# remote points at the commit that was pushed. Any other outcome exits
# non-zero, so a failed Job is the single signal that the backup is not safe.
#
# Required env: DATABASE_URL, BACKUP_PASSPHRASE, OFFSITE_REPO
# Files: /secrets/deploy-key, /known-hosts/known_hosts (pinned host keys)
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups}"
WORK_DIR="${WORK_DIR:-/tmp}"
KEEP_LOCAL=14
KEEP_OFFSITE=7

TS=$(date -u +%Y%m%d-%H%M%S)
DUMP="$WORK_DIR/nopwd-$TS.dump"
ENC="$BACKUP_DIR/nopwd-$TS.dump.enc"

echo "dumping nopwd database"
pg_dump "$DATABASE_URL" -Fc -f "$DUMP"

echo "encrypting"
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -in "$DUMP" -out "$ENC" -pass env:BACKUP_PASSPHRASE
rm -f "$DUMP"

# A dump that does not decrypt back into a readable archive is not a backup
echo "verifying the encrypted dump"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -in "$ENC" -pass env:BACKUP_PASSPHRASE | pg_restore --list >/dev/null

# Tier 1 retention: newest $KEEP_LOCAL on the Hetzner volume. Names are
# generated timestamps, so ls ordering is safe.
# shellcheck disable=SC2012
ls -1t "$BACKUP_DIR"/nopwd-*.dump.enc | tail -n +$((KEEP_LOCAL + 1)) | xargs -r rm -f

echo "pushing offsite (rolling $KEEP_OFFSITE, constant-size repo)"
case "$OFFSITE_REPO" in
  git@*|ssh://*)
    grep -q '^github.com ' /known-hosts/known_hosts \
      || { echo "known_hosts has no github.com entry, refusing to push" >&2; exit 1; }
    mkdir -p "$WORK_DIR/.ssh"
    cp /secrets/deploy-key "$WORK_DIR/.ssh/id_ed25519"
    chmod 600 "$WORK_DIR/.ssh/id_ed25519"
    # ssh resolves ~ from passwd, not $HOME, so name every file explicitly
    export GIT_SSH_COMMAND="ssh -i $WORK_DIR/.ssh/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=/known-hosts/known_hosts -o StrictHostKeyChecking=yes"
    ;;
esac

OFF="$WORK_DIR/off"
rm -rf "$OFF"
mkdir -p "$OFF"
cd "$OFF"
git init -q -b main
git remote add origin "$OFFSITE_REPO"
# shellcheck disable=SC2012
ls -1t "$BACKUP_DIR"/nopwd-*.dump.enc | head -n "$KEEP_OFFSITE" | while read -r f; do cp "$f" .; done
git add -A
git -c user.email=backup@nopwd.dev -c user.name=nopwd-backup \
  commit -q -m "nopwd encrypted backups (rolling)"
git push -q --force origin main

LOCAL_HEAD=$(git rev-parse HEAD)
REMOTE_HEAD=$(git ls-remote origin refs/heads/main | cut -f1)
if [ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]; then
  echo "offsite verification failed: remote main is '$REMOTE_HEAD', expected $LOCAL_HEAD" >&2
  exit 1
fi

date -u +%s > "$BACKUP_DIR/last-success"
echo "backup complete: nopwd-$TS.dump.enc ($(stat -c%s "$ENC") bytes), offsite verified at $LOCAL_HEAD"
