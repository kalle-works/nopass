/**
 * Content script — runs in the context of every web page.
 *
 * Responsibilities:
 * 1. Detect username/password input pairs and inject an autofill button
 * 2. Receive FILL_CREDENTIALS from the background SW and fill the fields
 */

interface FillMessage {
  type: "FILL_CREDENTIALS";
  username: string;
  password: string;
}

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

const ATTR = "data-nopass-injected";

function injectButton(passwordField: HTMLInputElement): void {
  if (passwordField.hasAttribute(ATTR)) return;
  passwordField.setAttribute(ATTR, "1");

  const btn = document.createElement("button");
  btn.type = "button";
  btn.title = "Fill with nopass";
  btn.style.cssText = [
    "position:absolute",
    "right:6px",
    "top:50%",
    "transform:translateY(-50%)",
    "width:22px",
    "height:22px",
    "padding:0",
    "border:none",
    "background:transparent",
    "cursor:pointer",
    "z-index:2147483647",
    "line-height:1",
    "font-size:14px",
  ].join(";");
  btn.textContent = "🔑";

  btn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    openPopupForField(passwordField);
  });

  // Wrap field in a positioned container so the button can be absolutely placed
  const parent = passwordField.parentElement;
  if (!parent) return;

  const wrapper = document.createElement("span");
  wrapper.style.cssText = "position:relative;display:inline-block";
  parent.insertBefore(wrapper, passwordField);
  wrapper.appendChild(passwordField);
  wrapper.appendChild(btn);
}

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
}

const observer = new MutationObserver(() => scanAndInject());
observer.observe(document.body, { childList: true, subtree: true });
scanAndInject();
