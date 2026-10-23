#!/bin/sh
# Applies the migrations of the last release tag, seeds an account and an item
# in that schema, applies the current migrations and checks the account still
# works (crates/nopass-api/tests/upgrade_test.rs).
#
# Run from the repo root with DATABASE_URL pointing at a Postgres the test may
# create databases in. FROM_TAG defaults to the newest v* tag.
set -eu

FROM_TAG="${FROM_TAG:-$(git tag --list 'v*' --sort=-v:refname | head -n 1)}"
[ -n "$FROM_TAG" ] || { echo "no release tag found (fetch tags: git fetch --tags)" >&2; exit 1; }

DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
git archive "$FROM_TAG" crates/nopass-api/src/db/migrations | tar -x -C "$DIR"

echo "upgrading from $FROM_TAG"
OUT=$(UPGRADE_FROM_MIGRATIONS_DIR="$DIR/crates/nopass-api/src/db/migrations" \
  cargo test -p nopass-api --test upgrade_test -- --ignored 2>&1) || { echo "$OUT"; exit 1; }
echo "$OUT"
# An ignored test that is renamed or removed would pass with zero tests run
echo "$OUT" | grep -q "1 passed" || { echo "upgrade test did not run" >&2; exit 1; }
