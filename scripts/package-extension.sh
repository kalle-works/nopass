#!/usr/bin/env bash
# Build and package the browser extension for the Chrome Web Store.
# Usage: ./scripts/package-extension.sh [api-base-url]
set -euo pipefail

API_BASE="${1:-https://api.nopwd.dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/apps/extension/nopwd-extension.zip"

echo "Building extension against $API_BASE …"
cd "$ROOT/apps/extension"
PNPM="pnpm"
command -v pnpm >/dev/null 2>&1 || PNPM="npx pnpm@9.15.4"
VITE_API_BASE="$API_BASE" $PNPM build

# The store rejects packages with stray files — zip only what the manifest needs
cd dist
rm -f "$OUT"
zip -qr "$OUT" manifest.json background.js content.js webauthn-inject.js base64.js popup.js popup.css ./*.woff2 icons src

echo "Packaged: $OUT"
unzip -l "$OUT"
