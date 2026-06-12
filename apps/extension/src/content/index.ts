/**
 * Content script — runs in the context of every web page.
 *
 * Responsibilities:
 * 1. Detect username/password input pairs and inject an autofill button
 * 2. Receive FILL_CREDENTIALS from the background SW and fill the fields
 */

import { initWebauthnRelay } from "../webauthn/relay";

interface FillMessage {
  type: "FILL_CREDENTIALS";
  username: string;
  password: string;
}

// Passkey relay must be listening before the page calls navigator.credentials
initWebauthnRelay();

// ─── Field detection ─────────────────────────────────────────────────────────

function findPasswordFields(): HTMLInputElement[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>("input[type='password']"));
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
    if (t === "text" || t === "email" || t === "tel" || t === "") return el;
  }
  return null;
}

// ─── Autofill button ──────────────────────────────────────────────────────────
//
// The button is an overlay appended to <body>, positioned over the field's
// right edge. Reparenting the field into a wrapper (the obvious alternative)
// breaks `width: 100%` sizing and detaches React refs on framework pages.

const ATTR = "data-nopass-injected";
const BTN_SIZE = 22;

const KEY_ICON_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="square">' +
  '<circle cx="5" cy="11" r="3"/><path d="M7.5 8.5 L13.5 2.5 M11 5 L13 7"/></svg>';

interface InjectedButton {
  field: HTMLInputElement;
  btn: HTMLButtonElement;
}

const injected: InjectedButton[] = [];

function injectButton(passwordField: HTMLInputElement): void {
  if (passwordField.hasAttribute(ATTR)) return;
  passwordField.setAttribute(ATTR, "1");

  const btn = document.createElement("button");
  btn.type = "button";
  btn.title = "Fill with nopwd";
  btn.setAttribute("data-nopass-button", "1");
  btn.style.cssText = [
    "position:absolute",
    `width:${BTN_SIZE}px`,
    `height:${BTN_SIZE}px`,
    "display:flex",
    "align-items:center",
    "justify-content:center",
    "padding:0",
    "border:none",
    "border-radius:0",
    "background:transparent",
    "color:#9C988D",
    "cursor:pointer",
    "z-index:2147483647",
    "line-height:1",
  ].join(";");
  btn.innerHTML = KEY_ICON_SVG;
  btn.addEventListener("mouseenter", () => { btn.style.color = "#D6FF3F"; });
  btn.addEventListener("mouseleave", () => { btn.style.color = "#9C988D"; });

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
  btn.style.top = `${window.scrollY + rect.top + (rect.height - BTN_SIZE) / 2}px`;
  btn.style.left = `${window.scrollX + rect.right - BTN_SIZE - 6}px`;
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

window.addEventListener("scroll", repositionAll, { capture: true, passive: true });
window.addEventListener("resize", repositionAll, { passive: true });

let activePasswordField: HTMLInputElement | null = null;

function openPopupForField(field: HTMLInputElement): void {
  activePasswordField = field;
  // The background SW will handle matching by URL; we just signal readiness.
  // The actual credential selection happens in the popup; autofill is triggered
  // via AUTOFILL message → background → FILL_CREDENTIALS back to this script.
}

// ─── Incoming messages from background ───────────────────────────────────────

chrome.runtime.onMessage.addListener((message: FillMessage) => {
  if (message.type !== "FILL_CREDENTIALS") return;

  const pwField = activePasswordField ?? findPasswordFields()[0] ?? null;
  if (!pwField) return;

  const userField = findUsernameField(pwField);

  if (userField) {
    setNativeValue(userField, message.username);
  }
  setNativeValue(pwField, message.password);
  activePasswordField = null;
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
