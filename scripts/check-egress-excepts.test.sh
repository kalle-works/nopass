#!/bin/sh
# The egress check must pass the real policies, and must fail on an open ::/0
# rule that lacks the IPv6 private and link-local excepts.
set -eu

scripts/check-egress-excepts.sh k8s/network-policies.yaml >/dev/null \
  || { echo "the real policies fail the egress check" >&2; exit 1; }

if OUT=$(scripts/check-egress-excepts.sh scripts/testdata/egress-ipv6-open.yaml 2>&1); then
  echo "an open ::/0 rule without excepts passed the egress check" >&2; exit 1
fi
echo "$OUT" | grep -q "v6-open ::/0 does not exclude fe80::/10" \
  || { echo "failed for another reason: $OUT" >&2; exit 1; }
echo "egress check tests passed"
