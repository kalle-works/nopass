/**
 * Content script — runs in the context of every web page.
 *
 * Responsibilities:
 * 1. Detect username/password input pairs and inject an autofill button
 * 2. Tell the background which frame the user is interacting with, so a fill
 *    goes to that frame only
 * 3. Receive FILL_CREDENTIALS from the background SW and fill the fields,
 *    never into a field the user cannot see
 */

import { initWebauthnRelay } from "../webauthn/relay";

interface FillMessage {
  type: "FILL_CREDENTIALS";
  username: string;
  password: string;
  /** Origin the background matched the item against */
  origin: string;
}

// Passkey relay must be listening before the page calls navigator.credentials
initWebauthnRelay();

// ─── Field detection ─────────────────────────────────────────────────────────

function findPasswordFields(): HTMLInputElement[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>("input[type='password']"));
}

/**
 * True if the user can see the field. Pages (or ads framed into them) plant
 * invisible login fields to harvest autofilled credentials, so a fill skips
 * anything hidden, transparent, zero-size, off-screen, or aria-hidden.
 */
function isFillable(el: HTMLInputElement): boolean {
  if (!el.isConnected || el.disabled || el.readOnly || el.hidden) return false;
  if (el.closest("[aria-hidden='true'], [inert]")) return false;
  if (
    typeof el.checkVisibility === "function" &&
    !el.checkVisibility({ opacityProperty: true, visibilityProperty: true })
  ) {
    return false;
  }
  const style = getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
  if (style.opacity !== "" && Number(style.opacity) === 0) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width < 1 || rect.height < 1) return false;
  // Positioned out of the document (left: -9999px and friends)
  if (rect.right + window.scrollX <= 0 || rect.bottom + window.scrollY <= 0) return false;
  return true;
}

function findUsernameField(passwordField: HTMLInputElement): HTMLInputElement | null {
  // Walk backwards through form elements to find the nearest email/text input
  const form = passwordField.form;
  const inputs = form
    ? Array.from(form.querySelectorAll<HTMLInputElement>("input"))
    : Array.from(document.querySelectorAll<HTMLInputElement>("input"));

  const idx = inputs.indexOf(passwordField);
  for (let i = idx - 1; i >= 0; i--) {
    const el = inputs[i];
    if (!el) continue;
    const t = el.type;
    if ((t === "text" || t === "email" || t === "tel" || t === "") && isFillable(el)) return el;
  }
  return null;
}

// ─── Autofill button ──────────────────────────────────────────────────────────
//
// The button is an overlay appended to <body>, positioned over the field's
// right edge. Reparenting the field into a wrapper (the obvious alternative)
// breaks `width: 100%` sizing and detaches React refs on framework pages.

const ATTR = "data-nopass-injected";
const BTN_SIZE = 24;

// Inline-menu button styling. It lives in the page's light DOM (the field
// overlay must stay a direct <body> child), so every style is set inline on
// the element rather than through page-affectable stylesheets or classes.
// Values mirror the nopwd design tokens in packages/ui/src/theme.css for both
// themes; the page's own theme is unknown, so the system preference decides.
interface OverlayPalette {
  bg: string;
  bgHover: string;
  border: string;
  icon: string;
  accent: string;
}

const LIGHT_PALETTE: OverlayPalette = {
  bg: "#ffffff",
  bgHover: "#eff0f3",
  border: "#c9cdd5",
  icon: "#6f7682",
  accent: "#d2491b",
};

const DARK_PALETTE: OverlayPalette = {
  bg: "#1b1d21",
  bgHover: "#22252a",
  border: "#3a3f46",
  icon: "#8b929d",
  accent: "#ff7a45",
};

const darkQuery =
  typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: dark)") : null;

function palette(): OverlayPalette {
  return darkQuery?.matches ? DARK_PALETTE : LIGHT_PALETTE;
}

// Fill-in-field glyph: a field outline with a text caret, 1.5px stroke
const FILL_ICON_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<rect x="1.75" y="4" width="12.5" height="8" rx="1.5"/><path d="M5.5 6.5v3"/></svg>';

interface InjectedButton {
  field: HTMLInputElement;
  btn: HTMLButtonElement;
}

const injected: InjectedButton[] = [];

function paintButton(btn: HTMLButtonElement, state: { hover: boolean; focus: boolean }): void {
  const p = palette();
  btn.style.background = state.hover ? p.bgHover : p.bg;
  btn.style.color = state.hover || state.focus ? p.accent : p.icon;
  btn.style.borderColor = state.focus ? p.accent : p.border;
}

function injectButton(passwordField: HTMLInputElement): void {
  if (passwordField.hasAttribute(ATTR)) return;
  passwordField.setAttribute(ATTR, "1");

  const btn = document.createElement("button");
  btn.type = "button";
  btn.title = "Fill with nopwd";
  btn.setAttribute("aria-label", "Fill with nopwd");
  btn.setAttribute("data-nopass-button", "1");
  btn.style.cssText = [
    // fixed + viewport coords: immune to a positioned <body> (common on
    // framework pages), which would shift an absolutely-positioned overlay
    "position:fixed",
    `width:${BTN_SIZE}px`,
    `height:${BTN_SIZE}px`,
    "box-sizing:border-box",
    "display:flex",
    "align-items:center",
    "justify-content:center",
    "padding:0",
    "margin:0",
    "border:1px solid transparent",
    "border-radius:4px",
    "cursor:pointer",
    "z-index:2147483647",
    "line-height:1",
    "transition:background-color 120ms ease-out,color 120ms ease-out",
  ].join(";");
  btn.innerHTML = FILL_ICON_SVG;

  const state = { hover: false, focus: false };
  const repaint = () => paintButton(btn, state);
  repaint();
  btn.addEventListener("mouseenter", () => { state.hover = true; repaint(); });
  btn.addEventListener("mouseleave", () => { state.hover = false; repaint(); });
  btn.addEventListener("focus", () => { state.focus = true; repaint(); });
  btn.addEventListener("blur", () => { state.focus = false; repaint(); });
  darkQuery?.addEventListener("change", repaint);

  btn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    openPopupForField(passwordField);
  });

  document.body.appendChild(btn);
  const entry: InjectedButton = { field: passwordField, btn };
  injected.push(entry);
  positionButton(entry);
}

function positionButton({ field, btn }: InjectedButton): void {
  const rect = field.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) {
    btn.style.display = "none";
    return;
  }
  btn.style.display = "flex";
  btn.style.top = `${rect.top + (rect.height - BTN_SIZE) / 2}px`;
  btn.style.left = `${rect.right - BTN_SIZE - 6}px`;
}

function repositionAll(): void {
  for (let i = injected.length - 1; i >= 0; i--) {
    const entry = injected[i]!;
    if (!entry.field.isConnected) {
      entry.btn.remove();
      injected.splice(i, 1);
      continue;
    }
    positionButton(entry);
  }
}

// Scroll fires many times per second; batching via rAF eliminates redundant
// getBoundingClientRect() calls that would otherwise force layout reflow on
// every event. Resize is infrequent enough to run synchronously.
let _rafId: number | null = null;
function scheduleReposition(): void {
  if (_rafId !== null) return;
  _rafId = requestAnimationFrame(() => {
    _rafId = null;
    repositionAll();
  });
}

window.addEventListener("scroll", scheduleReposition, { capture: true, passive: true });
window.addEventListener("resize", repositionAll, { passive: true });

let activePasswordField: HTMLInputElement | null = null;

function openPopupForField(field: HTMLInputElement): void {
  activePasswordField = field;
  reportFillTarget();
  // The actual credential selection happens in the popup; autofill is triggered
  // via AUTOFILL message → background → FILL_CREDENTIALS back to this frame.
}

/**
 * Marks this frame as the autofill target for its tab. The background reads
 * frame and origin from the browser-set sender, so the message carries nothing.
 */
function reportFillTarget(): void {
  chrome.runtime.sendMessage({ type: "FILL_TARGET" }).catch(() => {
    // Extension reloaded or SW unavailable — the background falls back to the top frame
  });
}

document.addEventListener(
  "focusin",
  (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (el.type === "password") {
      activePasswordField = el;
      reportFillTarget();
    } else if (el.form?.querySelector("input[type='password']")) {
      reportFillTarget();
    }
  },
  true,
);

// ─── Incoming messages from background ───────────────────────────────────────

chrome.runtime.onMessage.addListener((message: FillMessage, _sender, sendResponse?: (response: unknown) => void) => {
  if (message.type !== "FILL_CREDENTIALS") return;

  // Frames without a password field stay silent: the first response wins, so
  // answering { filled: false } would mask a fill that succeeded in another
  // frame. No answer from any frame reads as "nothing filled" to the caller.
  // The background targeted this frame for this origin; if the frame has
  // navigated since, the credentials are not for us
  if (message.origin !== window.location.origin) return;

  const pwField =
    (activePasswordField && isFillable(activePasswordField) ? activePasswordField : null) ??
    findPasswordFields().find(isFillable) ??
    null;
  if (!pwField) return;

  const userField = findUsernameField(pwField);

  if (userField) {
    setNativeValue(userField, message.username);
  }
  setNativeValue(pwField, message.password);
  activePasswordField = null;
  sendResponse?.({ filled: true });
});

/**
 * React-aware value setter — triggers onChange synthetic events.
 */
function setNativeValue(el: HTMLInputElement, value: string): void {
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  nativeInputValueSetter?.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// ─── Observe DOM for dynamically added fields ─────────────────────────────────

function scanAndInject(): void {
  for (const field of findPasswordFields()) {
    injectButton(field);
  }
  repositionAll();
}

// The script now runs at document_start (for the WebAuthn relay), so the
// body may not exist yet when field scanning initializes
function initFieldScanning(): void {
  const observer = new MutationObserver(() => scanAndInject());
  observer.observe(document.body, { childList: true, subtree: true });
  scanAndInject();
}

if (document.body) {
  initFieldScanning();
} else {
  document.addEventListener("DOMContentLoaded", initFieldScanning, { once: true });
}
