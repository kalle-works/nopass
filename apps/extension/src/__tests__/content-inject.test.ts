// @vitest-environment happy-dom
import { describe, it, expect, beforeAll, vi } from "vitest";

type MessageListener = (message: unknown) => void;
const messageListeners: MessageListener[] = [];

/**
 * happy-dom does no layout, so every element measures 0x0. Simulate it:
 * 100x20 at the element's inline left (default 10px), 0x0 for width:0px.
 */
function stubLayout() {
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    const left = parseFloat(this.style.left || "10");
    const width = this.style.width === "0px" ? 0 : 100;
    const height = this.style.width === "0px" ? 0 : 20;
    return { left, right: left + width, top: 10, bottom: 10 + height, width, height, x: left, y: 10 } as DOMRect;
  });
}

function fill(username: string, password: string, origin = window.location.origin) {
  for (const listener of messageListeners) {
    listener({ type: "FILL_CREDENTIALS", username, password, origin });
  }
}

beforeAll(async () => {
  stubLayout();
  vi.stubGlobal("chrome", {
    runtime: {
      sendMessage: vi.fn(async () => ({ ok: true })),
      onMessage: {
        addListener: (fn: MessageListener) => messageListeners.push(fn),
      },
    },
  });

  document.body.innerHTML = `
    <form id="login">
      <input id="user" type="email" style="width:100%">
      <input id="pass" type="password" style="width:100%">
    </form>
  `;

  await import("../content/index");
});

describe("content script field injection", () => {
  it("marks the password field without reparenting it", () => {
    const pass = document.getElementById("pass") as HTMLInputElement;
    expect(pass.getAttribute("data-nopass-injected")).toBe("1");
    // The pre-fix implementation wrapped the field in a <span>, which broke
    // width:100% sizing — the field must stay a direct child of the form.
    expect(pass.parentElement?.id).toBe("login");
  });

  it("appends the overlay button to <body>, not next to the field", () => {
    const btn = document.querySelector<HTMLButtonElement>("button[data-nopass-button]");
    expect(btn).not.toBeNull();
    expect(btn!.parentElement).toBe(document.body);
    expect(btn!.title).toBe("Fill with nopwd");
  });

  it("removes the overlay button when the field leaves the DOM", async () => {
    const pass = document.getElementById("pass") as HTMLInputElement;
    pass.remove();
    window.dispatchEvent(new Event("scroll"));
    // Scroll triggers a requestAnimationFrame-deferred repositionAll — flush it.
    await new Promise<void>((r) => requestAnimationFrame(() => r()));
    expect(document.querySelector("button[data-nopass-button]")).toBeNull();
  });

  it("fills username and password with framework-visible events", () => {
    document.body.innerHTML = `
      <form>
        <input id="u2" type="text">
        <input id="p2" type="password">
      </form>
    `;
    const u2 = document.getElementById("u2") as HTMLInputElement;
    const p2 = document.getElementById("p2") as HTMLInputElement;
    const inputEvents: string[] = [];
    u2.addEventListener("input", () => inputEvents.push("user"));
    p2.addEventListener("input", () => inputEvents.push("pass"));

    expect(messageListeners.length).toBeGreaterThan(0);
    fill("a@b.c", "s3cret");

    expect(u2.value).toBe("a@b.c");
    expect(p2.value).toBe("s3cret");
    expect(inputEvents).toContain("user");
    expect(inputEvents).toContain("pass");
  });

  it("never fills a field the user cannot see", () => {
    document.body.innerHTML = `
      <form>
        <input id="real-user" type="email">
        <input id="trap-user" type="text" style="display:none">
        <input id="trap-none" type="password" style="display:none">
        <input id="trap-opacity" type="password" style="opacity:0">
        <input id="trap-visibility" type="password" style="visibility:hidden">
        <input id="trap-zero" type="password" style="width:0px">
        <input id="trap-offscreen" type="password" style="position:absolute;left:-9999px">
        <div aria-hidden="true"><input id="trap-aria" type="password"></div>
        <input id="real-pass" type="password">
      </form>
    `;

    fill("alice", "s3cret");

    const value = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
    for (const trap of ["trap-user", "trap-none", "trap-opacity", "trap-visibility", "trap-zero", "trap-offscreen", "trap-aria"]) {
      expect(value(trap), trap).toBe("");
    }
    expect(value("real-user")).toBe("alice");
    expect(value("real-pass")).toBe("s3cret");
  });

  it("ignores credentials addressed to another origin (frame navigated after targeting)", () => {
    document.body.innerHTML = `<form><input id="u" type="email"><input id="p" type="password"></form>`;

    fill("alice", "s3cret", "https://previous-page.example");

    expect((document.getElementById("p") as HTMLInputElement).value).toBe("");
  });
});
