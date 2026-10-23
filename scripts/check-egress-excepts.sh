#!/bin/sh
# Every NetworkPolicy egress rule that opens the whole internet must carve out
# the private, carrier-grade NAT and link-local ranges of its address family, or
# "public internet" also means nodes, other pods and the cloud metadata service:
#   0.0.0.0/0  must exclude 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16
#   ::/0       must exclude fc00::/7 (unique local) and fe80::/10 (link-local)
set -eu

FILE="${1:-k8s/network-policies.yaml}"

JSON=$(yq -o=json -N '.' "$FILE" | jq -s '.')

# Prints "<policy> <cidr> does not exclude <range>" for each open rule that lacks a range
# shellcheck disable=SC2016
MISSING=$(echo "$JSON" | jq -r '
  {"0.0.0.0/0": ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16"],
   "::/0": ["fc00::/7","fe80::/10"]} as $required
  | .[] | select(.kind == "NetworkPolicy") | .metadata.name as $name
  | (.spec.egress // [])[] | (.to // [])[]
  | select(.ipBlock.cidr? as $c | $required | has($c // ""))
  | .ipBlock.cidr as $cidr | (.ipBlock.except // []) as $except
  | $required[$cidr][] | select(. as $r | $except | index($r) | not)
  | "\($name) \($cidr) does not exclude \(.)"')

# shellcheck disable=SC2016
OPEN=$(echo "$JSON" | jq '[.[] | select(.kind == "NetworkPolicy") | (.spec.egress // [])[] | (.to // [])[] | select(.ipBlock.cidr? == "0.0.0.0/0" or .ipBlock.cidr? == "::/0")] | length')
[ "$OPEN" -gt 0 ] || { echo "no open egress rule found in $FILE: update this check" >&2; exit 1; }

if [ -n "$MISSING" ]; then
  echo "$MISSING" >&2
  exit 1
fi
echo "egress excepts ok ($OPEN open rules)"
