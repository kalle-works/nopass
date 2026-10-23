#!/bin/sh
# Pins a release in k8s/kustomization.yaml: sets the tag and digest of the api,
# web and ops images. Run by the Publish images workflow, which opens a PR
# with the result; Flux applies it once merged.
#
# Usage: scripts/bump-images.sh <tag> <api-digest> <web-digest> <ops-digest>
#   scripts/bump-images.sh v0.3.0 sha256:… sha256:… sha256:…
# KUSTOMIZATION overrides the file to edit (used by tests).
set -eu

[ "$#" -eq 4 ] || { echo "usage: $0 <tag> <api-digest> <web-digest> <ops-digest>" >&2; exit 2; }
TAG=$1
KUSTOMIZATION="${KUSTOMIZATION:-k8s/kustomization.yaml}"

case "$TAG" in v[0-9]*) ;; *) echo "tag must look like v1.2.3, got '$TAG'" >&2; exit 2 ;; esac
for d in "$2" "$3" "$4"; do
  printf '%s' "$d" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo "not a sha256 digest: '$d'" >&2; exit 2; }
done

set_image() {
  name=$1 digest=$2
  # Fails loudly when the image is missing from the file instead of adding a stray entry
  yq -e ".images[] | select(.name == \"ghcr.io/kalle-works/$name\")" "$KUSTOMIZATION" >/dev/null
  NAME="ghcr.io/kalle-works/$name" TAG="$TAG" DIGEST="$digest" yq -i \
    '(.images[] | select(.name == strenv(NAME))) |= (.newTag = strenv(TAG) | .digest = strenv(DIGEST))' \
    "$KUSTOMIZATION"
}

set_image nopwd-api "$2"
set_image nopwd-web "$3"
set_image nopwd-ops "$4"
