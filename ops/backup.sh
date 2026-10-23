#!/bin/sh
# Nightly encrypted dump of the nopwd database, kept on the Hetzner volume
# (14 newest) and pushed offsite (7 newest, single rolling commit).
#
# pg_dump streams straight into age, encrypted to a public key, so no plaintext
# dump ever touches a disk and this job cannot decrypt what it writes. The
# private key lives only with the restore drill and in the password manager.
# Because the job cannot read its own output back, the monthly restore drill is
# what proves a dump decrypts and restores; here the job checks that pg_dump
# succeeded (pipefail), that the file is not implausibly small, and that the
# offsite remote points at the commit that was pushed. Any other outcome exits
# non-zero, so a failed Job is the single signal that the backup is not safe.
#
# Older dumps (nopwd-*.dump.enc, openssl AES-256-CBC with BACKUP_PASSPHRASE) stay
# in the retention window and the offsite repository until they age out; the
# restore drill still reads them.
#
# Required env: DATABASE_URL, AGE_RECIPIENT (age1... public key), OFFSITE_REPO
# Files: /secrets/deploy-key, /known-hosts/known_hosts (pinned host keys)
set -eu
# busybox ash, the shell in the ops image, has pipefail
# shellcheck disable=SC3040
set -o pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
WORK_DIR="${WORK_DIR:-/tmp}"
MIN_DUMP_BYTES="${MIN_DUMP_BYTES:-1024}"
KEEP_LOCAL=14
KEEP_OFFSITE=7

case "${AGE_RECIPIENT:-}" in
  age1*) ;;
  *) echo "AGE_RECIPIENT is not an age public key (see DEPLOY.md, Backups); refusing to write an unencrypted or unreadable dump" >&2; exit 1 ;;
esac

TS=$(date -u +%Y%m%d-%H%M%S)
ENC="$BACKUP_DIR/nopwd-$TS.dump.age"
PARTIAL="$ENC.partial"
OFF="$WORK_DIR/off"

# A half-written file must never look like a backup, and the deploy key copy
# should not outlive the job
trap 'rm -f "$PARTIAL"; rm -rf "$OFF" "$WORK_DIR/.ssh"' EXIT

echo "dumping and encrypting nopwd database"
pg_dump "$DATABASE_URL" -Fc | age -r "$AGE_RECIPIENT" -o "$PARTIAL"
SIZE=$(stat -c%s "$PARTIAL")
[ "$SIZE" -ge "$MIN_DUMP_BYTES" ] || { echo "dump is only $SIZE bytes, refusing to keep it" >&2; exit 1; }
mv "$PARTIAL" "$ENC"

# Tier 1 retention: newest $KEEP_LOCAL on the Hetzner volume, old and new
# format together. Names are generated timestamps, so ls ordering is safe.
list_backups() {
  # shellcheck disable=SC2012
  ls -1t "$BACKUP_DIR"/nopwd-*.dump.age "$BACKUP_DIR"/nopwd-*.dump.enc 2>/dev/null || true
}
list_backups | tail -n +$((KEEP_LOCAL + 1)) | xargs -r rm -f

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

rm -rf "$OFF"
mkdir -p "$OFF"
cd "$OFF"
git init -q -b main
git remote add origin "$OFFSITE_REPO"
list_backups | head -n "$KEEP_OFFSITE" | while read -r f; do cp "$f" .; done
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
echo "backup complete: nopwd-$TS.dump.age ($SIZE bytes), offsite verified at $LOCAL_HEAD"
