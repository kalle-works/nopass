# Capabilities

`default.json` grants the main window `sql:allow-load`, `sql:allow-select` and
`sql:allow-execute`. tauri-plugin-sql scopes permissions per command, not per
statement or per database, so `allow-execute` cannot be narrowed to the few
statements the app runs (`src/hooks/useLocalDb.ts`: the two CREATE TABLE
statements, an upsert, `DELETE FROM vault_items` and the sync_state upsert).

What limits the exposure instead:

- Only the app's own frontend can call the plugin. The production CSP is
  `script-src 'self'` with no `unsafe-inline`, so no injected script runs there
  (`scripts/check-csp.mjs` fails the build if that changes).
- The database holds only ciphertext (`vault_items.blob*`) and sync cursors. No
  key, password or plaintext is stored in it.

If the plugin gains statement scopes, narrow `sql:allow-execute` to them.
