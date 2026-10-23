#!/bin/sh
# Every NetworkPolicy egress rule that opens 0.0.0.0/0 must carve out the
# private, carrier-grade NAT and link-local ranges, or "public internet" also
# means nodes, other pods and the cloud metadata service.
set -eu

FILE="${1:-k8s/network-policies.yaml}"

# Prints "<policy> <missing range>" for each open rule that lacks a range
# shellcheck disable=SC2016
MISSING=$(yq -o=json -N '.' "$FILE" | jq -r -s '
  ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16"] as $required
  | .[] | select(.kind == "NetworkPolicy") | .metadata.name as $name
  | (.spec.egress // [])[] | (.to // [])[]
  | select(.ipBlock.cidr? == "0.0.0.0/0")
  | (.ipBlock.except // []) as $except
  | $required[] | select(. as $r | $except | index($r) | not)
  | "\($name) does not exclude \(.)"')

OPEN=$(yq -o=json -N '.' "$FILE" | jq -s '[.[] | select(.kind == "NetworkPolicy") | (.spec.egress // [])[] | (.to // [])[] | select(.ipBlock.cidr? == "0.0.0.0/0")] | length')
[ "$OPEN" -gt 0 ] || { echo "no 0.0.0.0/0 egress rule found in $FILE: update this check" >&2; exit 1; }

if [ -n "$MISSING" ]; then
  echo "$MISSING" >&2
  exit 1
fi
echo "egress excepts ok ($OPEN open rules)"
