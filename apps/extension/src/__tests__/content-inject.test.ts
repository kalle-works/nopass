// @vitest-environment happy-dom
import { describe, it, expect, beforeAll, vi } from "vitest";

type MessageListener = (message: unknown) => void;
const messageListeners: MessageListener[] = [];

beforeAll(async () => {
  vi.stubGlobal("chrome", {
    runtime: {
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
    for (const listener of messageListeners) {
      listener({ type: "FILL_CREDENTIALS", username: "a@b.c", password: "s3cret" });
    }

    expect(u2.value).toBe("a@b.c");
    expect(p2.value).toBe("s3cret");
    expect(inputEvents).toContain("user");
    expect(inputEvents).toContain("pass");
  });
});
