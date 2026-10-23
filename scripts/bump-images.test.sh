#!/bin/sh
# A release bump must pin every workload image, including the CronJobs, to the
# released digest in the manifests Flux renders, and must reject bad input.
set -eu

API=sha256:$(printf 'a%.0s' $(seq 64))
WEB=sha256:$(printf 'b%.0s' $(seq 64))
OPS=sha256:$(printf 'c%.0s' $(seq 64))

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R k8s "$WORK/k8s"

KUSTOMIZATION="$WORK/k8s/kustomization.yaml" scripts/bump-images.sh v9.9.9 "$API" "$WEB" "$OPS"
RENDERED=$(kubectl kustomize "$WORK/k8s")

for want in "nopwd-api:v9.9.9@$API" "nopwd-web:v9.9.9@$WEB" "nopwd-ops:v9.9.9@$OPS"; do
  echo "$RENDERED" | grep -q "image: ghcr.io/kalle-works/$want" || { echo "rendered manifests lack $want" >&2; exit 1; }
done
# api, web, backup and drill: four workloads, none left on an old pin
[ "$(echo "$RENDERED" | grep -c 'image: ghcr.io/kalle-works/')" -eq 4 ] || { echo "unexpected number of pinned images" >&2; exit 1; }
if echo "$RENDERED" | grep 'image: ghcr.io/kalle-works/' | grep -v '@sha256:'; then
  echo "an image is not pinned by digest" >&2; exit 1
fi

if KUSTOMIZATION="$WORK/k8s/kustomization.yaml" scripts/bump-images.sh latest "$API" "$WEB" "$OPS" 2>/dev/null; then
  echo "accepted a tag that is not a version" >&2; exit 1
fi
if KUSTOMIZATION="$WORK/k8s/kustomization.yaml" scripts/bump-images.sh v9.9.10 "$API" "$WEB" "sha256:short" 2>/dev/null; then
  echo "accepted a malformed digest" >&2; exit 1
fi
echo "bump-images tests passed"
