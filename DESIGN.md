# nopwd Design System

## Brand

**What it is**: Zero-knowledge secrets manager for AI developers.
**Who it's for**: Developers building with LLMs — storing API keys, injecting them into agents and scripts via CLI, sharing secrets across teams without anyone holding plaintext.
**Positioning**: Not a consumer password manager. A secrets layer for the AI stack. The CLI is the primary interface; the web is the management surface.
**Tone**: Direct, blunt, technical. No marketing speak. "Your API keys don't belong in a `.env` file." Speak to developers who have been burned.

---

## Color

### Light mode (primary)

| Token | Value | Use |
|---|---|---|
| `--bg` | `#F7F5F0` | Page background (warm cream) |
| `--surface` | `#FFFFFF` | Card, panel background |
| `--surface-subtle` | `#F0EDE6` | Subtle section backgrounds |
| `--border` | `#D8D4CC` | Dividers, input borders |
| `--text` | `#111110` | Primary text |
| `--text-muted` | `#6B6760` | Labels, secondary text |
| `--accent` | `#D6FF3F` | CTA buttons, active states, highlights |
| `--accent-hover` | `#C4EE30` | Accent hover |
| `--danger` | `#E8321A` | Errors, destructive actions |
| `--success` | `#2D7A1F` | Success states, match indicators |
| `--code-bg` | `#0F0E0C` | Terminal and code block backgrounds |
| `--code-text` | `#F4F1E8` | Code text on dark terminal blocks |
| `--code-muted` | `#9C988D` | Comments, dimmed code |
| `--code-green` | `#7CFF6B` | Success lines in terminal output |
| `--code-red` | `#FF5C39` | Error/danger lines in terminal output |

### Dark mode (vault interior + auth screens)

| Token | Value | Use |
|---|---|---|
| `--bg` | `#070706` | Page background |
| `--surface` | `#11110F` | Card, panel background |
| `--surface-elevated` | `#181713` | Raised surfaces |
| `--border` | `#2B2923` | Dividers, input borders |
| `--text` | `#F4F1E8` | Primary text |
| `--text-muted` | `#9C988D` | Labels, secondary text |

The accent, danger, success, and code tokens are shared between modes.

**Rule**: The marketing site and landing page use light mode. Auth screens (login, register) and the vault interior use dark mode.

---

## Typography

```
Display / headings / labels / code: Martian Mono
Body / paragraphs / UI text: IBM Plex Sans
```

| Scale | Font | Weight | Size |
|---|---|---|---|
| Hero | Martian Mono | 800 ExtraBold | 56–72px |
| H1 | Martian Mono | 700 Bold | 40–48px |
| H2 | Martian Mono | 600 SemiBold | 28–32px |
| H3 | Martian Mono | 600 SemiBold | 20–24px |
| Body large | IBM Plex Sans | 400 | 18px |
| Body | IBM Plex Sans | 400 | 16px |
| Small / label | IBM Plex Sans | 500 | 13–14px |
| Mono small | Martian Mono | 400 | 12–13px |
| Badge / eyebrow | Martian Mono | 600 | 11px uppercase tracked |

---

## Geometry

- **Border radius**: 0px everywhere. Sharp corners, no rounding. No exceptions.
- **Borders**: 1px `--border` on cards and inputs. Never 2px decorative.
- **Shadows**: None on light mode surfaces. Use border + background contrast instead.
- **Spacing unit**: 4px base. Common: 8, 12, 16, 24, 32, 48, 64, 96px.
- **Max content width**: 1200px. Section padding: 96px vertical desktop, 48px mobile.
- **Grid**: 12-column, 24px gutter on desktop. Single column on mobile.

---

## Components

### Buttons

```
Primary: bg --accent, text --text (#111110), font Martian Mono semibold
         hover: bg --accent-hover
         No border radius. Min height 44px. Padding 12px 24px.

Ghost:   bg transparent, border 1px --border, text --text-muted
         hover: border --text, text --text

Danger:  bg --danger, text white
```

No pill buttons. No gradient buttons. No shadow on buttons.

### Inputs

```
bg --surface, border 1px --border, text --text
focus: border --text (1px, not shadow)
error: border --danger
font: IBM Plex Sans 16px
height: 44px, padding: 0 12px
border-radius: 0
```

### Code / Terminal blocks

Dark islands on the light page. These are the visual anchors.

```
bg --code-bg (#0F0E0C)
text --code-text (#F4F1E8)
font Martian Mono 13px
padding 20px 24px
border-radius 0
border: 1px solid #2B2923

Prompt line: text #D6FF3F (chartreuse)
Output line: text #F4F1E8
Success line (✓): text #7CFF6B
Error line (✗): text #FF5C39
Comment: text #9C988D
```

Example terminal block:
```
$ nopwd get ANTHROPIC_API_KEY | python agent.py
✓ agent completed — key never written to disk
```

### Cards

```
bg --surface, border 1px --border, padding 32px
No shadow, no radius
Hover state (if interactive): border --text, bg --surface-subtle
```

### Badges / eyebrows

```
font Martian Mono 11px uppercase letter-spacing 0.1em
color --text-muted
No background, no border — just text
```

Trust bar (used under hero):
```
AES-256-GCM · Argon2id · SRP-6a · Zero-knowledge · Open source
font Martian Mono 12px, color --text-muted, separator "·"
```

---

## Page Patterns

### Landing page hero

Two-column layout (desktop). Left: headline + subtext + CTAs. Right: live terminal block showing CLI usage.

Primary headline formula: One blunt, direct claim. Martian Mono ExtraBold. No tagline wordplay.
Good: "Your API keys don't belong in a `.env` file."
Good: "Zero-knowledge secrets for your AI stack."
Bad: "The password manager of the future."

CTA hierarchy:
1. Primary (chartreuse): "Get started free" or "Get started →"
2. Secondary (ghost): "$ brew install nopwd" (terminal-styled)

### Sections

Use generous whitespace between sections — 96px vertical padding. Sections are separated by 1px `--border` horizontal rules, not by alternating background colors.

Section eyebrow → H2 → body → cards/content. Always top-left aligned, never centered (exception: pricing cards).

### Pricing cards

Three columns: Free / Pro / Teams. Each card:
- Plan name in Martian Mono H3
- Price large (Martian Mono H1) + period small
- Feature list with `—` prefix (not checkmarks on free, `✓` on paid)
- CTA button full-width at bottom

Highlight the recommended plan with a 1px `--text` border (not a colored background band).

### Code comparison pattern (anti-.env use case)

```
[dark terminal block]
❌  OPENAI_API_KEY=sk-proj-...  (in .env, git history, CI logs)

vs

✓   $ nopwd get OPENAI_API_KEY  (zero-knowledge, never on disk)
```

This pattern appears on landing and in docs. It is the core conversion argument.

---

## What Not To Do

- No rounded corners (not even 4px)
- No pill buttons or pill badges
- No gradient backgrounds or gradient text
- No drop shadows
- No decorative illustrations or SVG blob shapes
- No stock photography
- No icons with rounded backgrounds (lock in a circle, shield, etc.)
- No blue anywhere — the current design system has no blue
- No `text-gray-500` — use `--text-muted` tokens
- Do not use consumer password manager conventions (vault with lock icon, shield, etc.)
- Do not center-align body copy on wide viewports
- Do not put marketing copy in the vault interior — vault is a utility, not a marketing surface

---

## Voice

**Do**: "Your API keys don't belong in a `.env` file." / "Zero-knowledge by construction." / "Server holds zero plaintext." / "No reset. Write it down."

**Don't**: "Secure your digital life." / "Keeping your passwords safe since..." / "Enterprise-grade security for everyone." / "Peace of mind."

Speak to the developer who already understands why `.env` is dangerous. Don't explain things they know. Respect their time.

---

## File Attachment / Assets

- Icons: inline SVG, 16×16 or 20×20, 1.5px stroke, no fill, `currentColor`
- Images: none (use terminal blocks and typography instead)
- Fonts: `next/font/google` — `Martian_Mono` + `IBM_Plex_Sans`
