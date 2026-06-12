# Chrome Web Store listing — nopwd

## Name
nopwd — zero-knowledge password manager

## Summary (132 chars max)
Passwords, passkeys, and 2FA codes — encrypted on your device before they
ever leave it. The server can't read your vault.

## Description
nopwd is a password manager that treats your secrets as yours alone.
Everything — logins, passkeys, cards, notes, SSH keys — is encrypted on your
device with keys derived from your master password. Our servers store
ciphertext they cannot decrypt. Not as a promise: as math (Argon2id,
AES-256-GCM, SRP-6a — the client is open source).

This extension gives you:

- **Autofill** for usernames and passwords on any site
- **Passkeys**: create and use WebAuthn passkeys that sync inside your
  encrypted vault instead of being locked to one device
- **2FA codes** alongside your passwords
- Vault search from the toolbar popup

Works with your nopwd account — vault management, breach auditing, one-time
secret sharing, and an offline recovery kit live at nopwd.dev.

## Permission justifications (for review)
- `host_permissions <all_urls>`: autofill must detect login forms and the
  passkey authenticator must respond to WebAuthn calls on any site the user
  visits. No page content is collected or transmitted.
- Content script in the MAIN world (`webauthn-inject.js`): required to wrap
  `navigator.credentials.create/get` so the extension can act as a passkey
  authenticator. It only forwards WebAuthn requests the page itself initiates,
  always behind an explicit user-consent dialog, and falls back to the
  browser's native authenticator in every other case.
- `storage`: `storage.session` (RAM-only, cleared when the browser exits,
  trusted extension contexts only) holds the unlocked session so the vault
  does not re-lock every time the MV3 service worker idles out.
  `storage.local` holds only the last-used email for sign-in prefill — never
  passwords, keys, or vault data.

## Privacy disclosure
The extension sends nothing to anyone except the user's own nopwd API
(end-to-end encrypted vault data) — no analytics, no tracking, no third
parties.

## Category
Productivity → Tools

## Assets needed before submission
- [ ] 128×128 icon (exists: icons/128.png)
- [ ] 1280×800 screenshots: popup with vault items; passkey consent overlay;
      autofill button on a login form
- [ ] 440×280 small promo tile
