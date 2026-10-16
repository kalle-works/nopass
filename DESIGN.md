# nopwd Design System

Version 2. Replaces the 2026 brutalist system (0px radius, chartreuse, Martian Mono).

## Product

**What it is:** a zero-knowledge vault for the credentials developers work with: website logins, API keys, TOTP codes and notes. The same vault is reachable from the web, the browser extension and the CLI.

**Who it's for:** developers and small technical teams. AI provider keys are one use case among several, not the whole pitch.

**Tone:** plain and specific. State what the product does and what the server can't see. Skip hype, fear and jokes at the user's expense.

- Do: "The server stores ciphertext. Your master password never leaves this device." / "Copied. Clipboard clears in 30s." / "No reset. Save your recovery kit."
- Don't: "Military-grade encryption." / "Peace of mind." / "Use a different product." / "Supercharge your workflow."

## Principles

1. **The credential is the hero.** Every screen exists to find, read, copy or fill a secret. Chrome around it stays quiet.
2. **One system, three surfaces.** Web vault, extension popup and CLI output share tokens, components and wording.
3. **Keyboard first, touch safe.** Every action has a keyboard path and a visible, always-on control. Nothing is hover-only.
4. **State is spelled out.** Colors never carry meaning alone; status always has a word next to it.
5. **Explain cryptography once, in the right place.** Routine flows don't mention Argon2id. The security page and the recovery kit do.

---

## Tokens

All tokens live in `packages/ui/src/theme.css`, which the web app and the extension both import. Components never use literal hex values.

Colors are defined in OKLCH. The hex values below are approximate and only for reference.

### Theme selection

- Default is the system preference (`prefers-color-scheme`).
- A persistent override (`data-theme="light" | "dark"` on `<html>`) is stored per device.
- Marketing, auth, vault and popup all follow the same setting. There is no "dark-only" area.

### Neutral scale

A 12-step gray with a faint cool tint, after Radix. Steps have fixed roles:

| Step | Role | Light | Dark |
|---|---|---|---|
| 1 | App background | `#FCFCFD` | `#0E0F11` |
| 2 | Subtle background (sidebar, list) | `#F7F8F9` | `#141518` |
| 3 | Component background | `#EFF0F3` | `#1B1D21` |
| 4 | Component hover | `#E7E9ED` | `#22252A` |
| 5 | Component active / selected | `#DFE2E7` | `#292C32` |
| 6 | Divider | `#D7DAE0` | `#30343A` |
| 7 | Control border | `#C9CDD5` | `#3A3F46` |
| 8 | Control border hover / strong | `#ADB3BD` | `#4C525B` |
| 9 | Placeholder, disabled text | `#8A919C` | `#6A717C` |
| 10 | Icons | `#7D8490` | `#7B828D` |
| 11 | Secondary text | `#5C6370` | `#A7AEB8` |
| 12 | Primary text | `#1A1D22` | `#EDEEF0` |

Semantic aliases: `--bg`, `--bg-subtle`, `--surface`, `--surface-hover`, `--surface-active`, `--divider`, `--border`, `--border-strong`, `--text-faint`, `--icon`, `--text-muted`, `--text`.

Contrast rules: `--text-muted` on `--bg` and `--bg-subtle` is at least 4.5:1 in both themes. `--border` against its surface is at least 3:1 for inputs. Text is never dimmed with opacity.

### Accent

One accent, used only for the primary action on a screen, focus rings, selection markers and links. Ember orange, chosen so it can't be mistaken for a status color.

| Token | Light | Dark |
|---|---|---|
| `--accent` | `#D2491B` | `#FF7A45` |
| `--accent-hover` | `#B53C13` | `#FF915F` |
| `--accent-fg` (text on accent) | `#FFFFFF` | `#1A0B04` |
| `--accent-subtle` (selected row bg) | `#FCEEE8` | `#2A1912` |
| `--accent-text` (accent as text) | `#B53C13` | `#FF915F` |
| `--focus` | `#D2491B` | `#FF7A45` |

At most one accent-filled button is visible per view.

### Status

| Token | Light | Dark | Use |
|---|---|---|---|
| `--success` | `#1D7A4E` | `#5BD69A` | Saved, connected, strong |
| `--warning` | `#8A5A00` | `#F2C35B` | Expiring, reused, weak |
| `--danger` | `#C42B32` | `#FF7B7F` | Breached, delete, error |
| `--*-subtle` | 8% tint on `--bg` | 14% tint on `--bg` | Banner and badge backgrounds |

`--danger` filled buttons use white text on `#B4232A` (light) and `#1A0506` on `--danger` (dark) to keep 4.5:1.

### Secret glyph colors

Used by `<SecretText>` to color characters in revealed passwords, the generator preview and the recovery key.

| Token | Light | Dark | Applies to |
|---|---|---|---|
| `--glyph-letter` | `--text` | `--text` | Letters |
| `--glyph-digit` | `#2563C9` | `#7FB0FF` | 0–9 |
| `--glyph-symbol` | `#B5398C` | `#F08BCF` | Everything else |

These are the only blue and pink in the system. They exist so `0`/`O` and `l`/`1` can be told apart at a glance.

---

## Typography

- **UI:** Geist (variable), via `next/font/google` on the web and bundled locally in the extension.
- **Mono:** Geist Mono for every secret, key, ID, URL host, fingerprint, command and timestamp in tables. Turn on `tabular-nums` for numbers in columns.

| Role | Size / line height | Weight | Tracking |
|---|---|---|---|
| Display (marketing hero) | 56/60, 36/40 mobile | 600 | -0.03em |
| H1 (page title) | 24/32 | 600 | -0.015em |
| H2 (section) | 18/26 | 600 | -0.01em |
| H3 (panel title) | 15/22 | 600 | 0 |
| Body | 15/22 web, 14/20 popup | 400 | 0 |
| Small / meta | 13/18 | 400 | 0 |
| Label | 13/18 | 500 | 0 |
| Mono value | 14/20 | 400 | 0 |
| Mono small | 12/16 | 400 | 0 |

The minimum size is 12px. Labels use sentence case. There is no tracked uppercase except the keyboard hint glyphs in `<Kbd>`.

---

## Geometry

- **Spacing:** 4px base. The scale is 4, 8, 12, 16, 20, 24, 32, 40, 48, 64, 96.
- **Radius:** `--radius-sm` 4px (badges, kbd), `--radius` 6px (buttons, inputs, rows), `--radius-lg` 10px (cards, panels, dialogs, popover), `--radius-full` only for avatars and the TOTP ring.
- **Borders:** 1px. Dividers use `--divider`, controls use `--border`.
- **Shadows:** only on floating layers (menus, dialogs, toasts, command palette). One token: `--shadow-overlay`. Flat surfaces separate by background step and border.
- **Control heights:** 32px compact, 36px default, 44px on touch and in the popup's main actions.
- **Row heights:** vault list 52px (two lines), compact 36px (one line). Table rows 44px. Popup rows 52px.
- **Focus:** 2px `--focus` outline, 2px offset, on `:focus-visible` only. Never removed.

---

## Motion

- Color and background transitions: 120ms ease-out.
- Overlays (menu, dialog, palette, toast): 160ms fade plus at most 4px of translate.
- Selection and list changes are not animated.
- `prefers-reduced-motion: reduce` removes all translate and pulse; fades drop to 0ms.

---

## Icons

- Lucide, 16px in UI and 14px in dense rows, 1.5px stroke, `currentColor`, color `--icon`.
- An icon sits next to a label or has an `aria-label` and a tooltip. Icon-only buttons are 32px square minimum.
- No icons in colored rounded squares. No locks, shields or keys as decoration.
- Item types use a small set: globe (login), key-round (API key), file-text (note), clock (TOTP), credit-card (card).
- Logins show the site favicon at 20px when available, falling back to a 20px monogram on `--surface-active`.

---

## Components

All shared components live in `packages/ui`, and both the web vault and the popup use them.

### Button

| Variant | Look |
|---|---|
| `primary` | `--accent` background, `--accent-fg` text. One per view. |
| `secondary` | `--surface` background, 1px `--border`, `--text`. Hover: `--surface-hover`, `--border-strong`. |
| `ghost` | No background or border, `--text-muted`. Hover: `--surface-hover`, `--text`. |
| `danger` | Filled danger as defined above. Only inside confirmation dialogs. |

Sizes `sm` 32px, `md` 36px, `lg` 44px. Label weight 500. An optional trailing `<Kbd>` shows the shortcut. Pending state keeps the width and shows a spinner plus a verb ("Unlocking…").

### Field

- A visible label above every input. Placeholders are examples, not labels.
- 36px input, `--surface` background, 1px `--border`, 6px radius. Hover `--border-strong`, focus ring as above, error `--danger` border plus a message below with an icon.
- Password inputs have a reveal toggle: a real button with `aria-label="Show password"` / `"Hide password"`, in the tab order.
- Set `autocomplete` correctly on every auth field.

### SecretText

Renders a secret value.
- Masked: exactly 12 `•` characters regardless of length, so length doesn't leak.
- Revealed: Geist Mono with glyph colors. Auto re-masks after 30s or when the window loses focus.
- Large type: a dialog with one character per cell, numbered beneath, for reading aloud.

### SecretRow

The core unit of the vault detail and the popup.

```
Label (13/18 muted)
value in mono                         [Reveal] [Copy]
```

- Copy and reveal are always visible, not hover-only.
- Clicking the value copies it. The copy button changes to a check and "Copied" for 1.5s, and a 30s ring shows the clipboard clear countdown.
- Clipboard is cleared after 30s only if it still holds the copied value.
- Optional footer line for warnings ("Reused on 3 other items") in `--warning`.

### ItemRow (list)

- 20px favicon or type icon, title (500) and subtitle (username, host or key prefix) in `--text-muted`.
- Right side: badges (TOTP, shared, breached) and one quick action (copy password, or copy key).
- Selected: `--accent-subtle` background plus a 2px `--accent` marker on the left edge.
- Arrow keys move, Enter opens, `c` copies the main secret, `u` copies the username.

### Badge

12/16 text, 4px radius, 2px 6px padding. Neutral (`--surface-active`, `--text-muted`) or status (`--*-subtle`, status text). Always contains a word.

### Command palette

- `⌘K` / `Ctrl+K` everywhere in the vault and popup.
- One input, grouped results (Items, Actions, Navigation) and actions based on the selection (Copy password, Copy TOTP, Open URL, Share, Edit).
- Footer shows `↵ Open`, `⌘C Copy` and `esc Close`.

### Dialog and sheet

- `role="dialog"`, `aria-modal`, focus trap, Escape to close, focus goes back to the trigger.
- Dialogs: 10px radius, max width 480px, overlay `rgb(0 0 0 / 0.5)`.
- Destructive confirmations name the object: "Delete 'GitHub'? This can't be undone."

### Toast

- Bottom-center, `role="status"` with `aria-live="polite"`. Errors use `role="alert"`.
- Only for results that happen off-screen (saved in background, sync failed). Copy feedback is inline on the button, not a toast.

### EmptyState

- One sentence on what's missing, one primary action and an optional CLI line.
- Filtered-empty is different from vault-empty: "No items match 'gith' in Work." plus "Clear filters".
- Vault-empty: "Your vault is empty." Primary "Import from 1Password, Bitwarden or CSV", secondary "New item", and `$ nopwd import .env`.

### StrengthMeter

Four segments plus a word and an estimated crack time: "Strong · centuries to guess". Uses zxcvbn. Colors: danger, warning, warning, success.

### CodeBlock

- Command blocks use `--surface-hover` with a 1px `--divider` border, 10px radius and Geist Mono 13/20.
- `$` prompt in `--text-faint`, not selectable and not copied. Output lines in `--text-muted`.
- A copy button top-right. No fake window chrome (traffic-light dots).
- Tabs above for OS or shell when commands differ.

---

## Layouts

### Web vault

```
┌──────────┬──────────────┬─────────────────────────────┐
│ Sidebar  │ List         │ Detail                      │
│ 232px    │ 360px        │ flex, min 480px             │
│          │ search  + New│ title, favicon, actions     │
│ Vaults   │              │ SecretRows                  │
│ Types    │ ItemRows     │ notes                       │
│ Health   │              │ metadata (created, updated) │
│ ──────── │              │                             │
│ Settings │              │                             │
└──────────┴──────────────┴─────────────────────────────┘
```

- **Sidebar:** account and vault switcher at the top, then All items, Favorites, types with counts, Health, Shared links and Activity. Settings, Devices, Import and Billing sit in a lower group. Lock button with `⌘L` at the bottom.
- **List header:** search (`/` focuses it) searching title, username, host, tags and notes, then sort and "New" (`n`).
- **Detail:** read mode by default. "Edit" (`e`) switches the same pane to inline editing; no modal editing.
- **Responsive:** at 1024–1279px, details replace the list with a back button. Below 768px the sidebar becomes a drawer. Selection, filters and scroll position are kept across switches.

### Settings pages (Devices, Activity, Shares, Billing, Recovery, Import)

- A single column, max 760px, inside the vault shell. Page title as H1, one-sentence description, then content.
- Tables follow the Tailscale pattern: name with "This device" badge, platform, last active (relative, exact on hover), location and a row menu. The destructive action is in the menu and is confirmed.
- Activity: actor, plain verb ("Signed in", "Created share link"), target in mono, device, time. A note at the top says what the server can't see (item contents, which secret was copied).

### Health

- Category cards in a grid: Breached, Reused, Weak, Missing 2FA. Each shows a count, one sentence on why it matters and "Review" which filters the list.
- No overall score gauge.

### Auth (login, register, recover, share open)

- Centered 400px column on `--bg`, logotype top-left of the page, footer links bottom.
- Register flow: email, master password with StrengthMeter (minimum "Strong"), confirm, then a recovery kit step that can't be skipped: download the PDF and tick "I've saved my recovery kit" before continuing.
- Login: email (remembered), master password, "Unlocking your vault…" while deriving keys, a visible "Forgot master password? Use your recovery kit" link.

### Extension popup

```
┌──────────────────────────────── 380px ┐
│ nopwd   account@…           [⌘K] [Lock]│
│ [search…                              ]│
│ github.com                             │
│  GitHub · kalle@…              [Fill]  │
│ ─────────────                          │
│ All items                              │
│  …                                     │
│ [+ New]                 [Open vault ↗] │
└────────────────────────────────────────┘
```

- Fixed 380px wide, up to 580px tall, results scroll.
- The active hostname heads the "For this site" section. If there is no match: "No logins for github.com" plus "Save a login" and "Search all items".
- Each row has one 32px "Fill" button. Clicking the row opens details with SecretRows.
- After Fill, the popup checks the content script result. On success it closes; on failure it stays open and says "Couldn't find a login form on this page."
- Auth screens in the popup use the same Field component with visible labels.

### Marketing

- **Nav:** logotype, Security, Docs, Pricing, GitHub. Right side: Log in (ghost), Create vault (primary).
- **Hero:** left-aligned. Headline "Your passwords and API keys, encrypted before they leave your device." One supporting sentence. Primary "Create your vault", secondary "Install the CLI" which opens a CodeBlock. On the right, a real screenshot of the vault in the current theme, in a 10px-radius frame with a 1px border.
- **Sections in order:**
  1. Three surfaces (web, extension, CLI), each with a real capture.
  2. Security model diagram: what the server stores and what never leaves the device.
  3. CLI section with tabs.
  4. Comparison table with 1Password and Bitwarden.
  5. Pricing.
  6. Footer with changelog, source and status.
- Sections separate by 96px of space (48px mobile) and a 1px divider. No alternating background bands.
- The maximum content width is 1120px with a 24px gutter (16px mobile).

---

## Accessibility

- WCAG 2.2 AA in both themes, checked for every token pair listed above.
- Full keyboard paths; visible focus everywhere; skip link to main content in the vault.
- Live regions for copy feedback, toasts and unlock progress.
- Hit targets at least 32px on desktop and 44px on touch.
- Respect `prefers-reduced-motion` and `prefers-contrast: more` (which swaps borders to `--border-strong`).

---

## Don't

- Hover-only actions.
- Opacity-dimmed text or 10px labels.
- Tracked uppercase eyebrows.
- Gradients, glows, glassmorphism, blobs or 3D illustrations.
- Fake terminal window chrome.
- A grid of three cards each holding an icon in a rounded square.
- Lock, shield or vault-door imagery.
- More than one accent button per view.
- Security score dials.
- Toasts for copy feedback.
- Modal editing of items.
- Literal hex values in components.
- Security claims the code doesn't back.
