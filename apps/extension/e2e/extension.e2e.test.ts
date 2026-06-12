// @vitest-environment node
/**
 * End-to-end test for the built extension in real Chromium.
 *
 * Covers: content-script button injection, unlocking through the real action
 * popup (argon2id + SRP against the live API), URL-matched entry listing,
 * autofill into a page, and the popup-only security guard.
 *
 * Prerequisites (skips cleanly when missing):
 * - API server on http://127.0.0.1:3001 (`cargo run -p nopass-api`)
 * - Built extension (`pnpm build`) — `pnpm test:e2e` builds first
 * - Playwright Chromium (`npx playwright install chromium`)
 *
 * The action popup is not exposed as a Playwright page, so it is driven over
 * raw CDP: `chrome.action.openPopup()` from the service worker, then
 * Runtime.evaluate against the popup target found via /json/list.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { chromium, type BrowserContext, type Page } from "playwright";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  computeEmailHash,
  deriveMasterKey,
  stretchMasterKey,
  stretchMasterKeyRaw,
  srpStep1,
  srpStep2,
  generateSrpRegistration,
  generateUserKeyPair,
  encryptBytes,
  encryptItem,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";

const API = "http://127.0.0.1:3001/v1";
const DIST = resolve(__dirname, "../dist");
const EMAIL = `ext-e2e-${Date.now()}@nopass.test`;
const PASSWORD = "ext-e2e-master-password-1";

const apiAvailable = await fetch(`${API}/health`).then((r) => r.ok).catch(() => false);
const distBuilt = existsSync(join(DIST, "manifest.json"));
const browserInstalled = (() => {
  try { return existsSync(chromium.executablePath()); } catch { return false; }
})();
const runnable = apiAvailable && distBuilt && browserInstalled;

const LOGIN_PAGE = `<!doctype html><html><body>
  <form id="login-form">
    <input id="email" type="email" autocomplete="username">
    <input id="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body></html>`;

async function apiPost(path: string, body: unknown, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const r = await fetch(`${API}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST ${path} -> ${r.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

/** Registers a fresh account and stores one login item pointing at siteUrl. */
async function seedAccount(siteUrl: string) {
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, DEFAULT_KDF_PARAMS);
  const keys = await stretchMasterKey(masterKey, EMAIL);
  const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, EMAIL);
  const { srpSalt, srpVerifier } = generateSrpRegistration(EMAIL, PASSWORD);
  const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
  const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);

  await apiPost("/auth/register", {
    emailHash: computeEmailHash(EMAIL),
    srpSalt,
    srpVerifier,
    kdfParams: DEFAULT_KDF_PARAMS,
    protectedSymmetricKey: protectedKey.blob,
    protectedSymmetricKeyIv: protectedKey.blobIv,
    publicKey: keyPair.publicKeyB64,
    protectedPrivateKey: keyPair.protectedPrivateKey,
    protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
  });

  const step1 = srpStep1();
  const initResp = await apiPost("/auth/srp/init", {
    emailHash: computeEmailHash(EMAIL),
    clientPublicA: step1.clientPublicA,
  });
  const step2 = srpStep2(EMAIL, PASSWORD, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
  const verifyResp = await apiPost("/auth/srp/verify", {
    sessionId: initResp.sessionId,
    clientProofM1: step2.clientProofM1,
  });
  step2.verifyServerProof(verifyResp.serverProofM2);

  const vaultEncKey = await crypto.subtle.importKey(
    "raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const vaultMacKey = await crypto.subtle.importKey(
    "raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
  );
  const blob = await encryptItem(
    {
      type: "login",
      name: "E2E Test Site",
      username: "e2e-user@example.com",
      password: "e2e-password-value",
      urls: [siteUrl],
      customFields: [],
    },
    vaultEncKey,
    vaultMacKey,
  );
  await apiPost(
    `/vaults/${verifyResp.defaultVaultId}/items`,
    { itemType: "login", blob: blob.blob, blobIv: blob.blobIv, blobMac: blob.blobMac },
    verifyResp.sessionToken,
  );
}

// ─── Raw-CDP driver for the action popup ─────────────────────────────────────

class PopupDriver {
  private ws!: WebSocket;
  private msgId = 0;
  private pending = new Map<number, (m: any) => void>();

  static async attach(cdpPort: number, extId: string): Promise<PopupDriver> {
    let target: any;
    for (let i = 0; i < 40 && !target; i++) {
      const list = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
      target = list.find(
        (t: any) => t.url.startsWith(`chrome-extension://${extId}`) && t.url.includes("popup"),
      );
      if (!target) await new Promise((r) => setTimeout(r, 250));
    }
    if (!target) throw new Error("popup CDP target not found");

    const driver = new PopupDriver();
    driver.ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((res, rej) => {
      driver.ws.onopen = res;
      driver.ws.onerror = rej;
    });
    driver.ws.onmessage = (ev) => {
      const m = JSON.parse(String(ev.data));
      if (m.id && driver.pending.has(m.id)) {
        driver.pending.get(m.id)!(m);
        driver.pending.delete(m.id);
      }
    };
    // Fail outstanding calls fast if the popup closes — otherwise they hang
    // until the suite timeout
    driver.ws.onclose = () => {
      for (const resolve of driver.pending.values()) {
        resolve({ error: { message: "popup CDP connection closed" } });
      }
      driver.pending.clear();
    };
    await driver.cdp("Runtime.enable");
    return driver;
  }

  private cdp(method: string, params: object = {}): Promise<any> {
    const id = ++this.msgId;
    return new Promise((res, rej) => {
      this.pending.set(id, (m) => (m.error ? rej(new Error(m.error.message)) : res(m.result)));
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async eval<T>(expression: string): Promise<T> {
    const r = await this.cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) {
      throw new Error("popup eval failed: " + (r.exceptionDetails.exception?.description ?? r.exceptionDetails.text));
    }
    return r.result.value as T;
  }

  /** Sets an input through the native setter so React sees the change. */
  setValue(selector: string, value: string): Promise<void> {
    return this.eval(`{
      const el = document.querySelector(${JSON.stringify(selector)});
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      setter.call(el, ${JSON.stringify(value)});
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }`);
  }

  /** Polls until expr returns truthy, or returns its last value on timeout. */
  waitFor<T>(expr: string, timeoutMs: number): Promise<T> {
    return this.eval(`(async () => {
      const deadline = Date.now() + ${timeoutMs};
      let last;
      while (Date.now() < deadline) {
        last = ${expr};
        if (last) return last;
        await new Promise(r => setTimeout(r, 100));
      }
      return last;
    })()`);
  }

  close(): void {
    this.ws.close();
  }
}

// ─── Suite ───────────────────────────────────────────────────────────────────

describe.skipIf(!runnable)("extension end-to-end", () => {
  let server: Server;
  let siteUrl: string;
  let context: BrowserContext;
  let profileDir: string;
  let extId: string;
  let cdpPort: number;
  let site: Page;
  let popup: PopupDriver;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(LOGIN_PAGE);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    siteUrl = `http://localhost:${port}/login.html`;

    await seedAccount(siteUrl);

    profileDir = mkdtempSync(join(tmpdir(), "nopwd-ext-e2e-"));
    context = await chromium.launchPersistentContext(profileDir, {
      headless: true,
      channel: "chromium",
      args: [
        `--disable-extensions-except=${DIST}`,
        `--load-extension=${DIST}`,
        "--remote-debugging-port=0",
      ],
    });
    cdpPort = Number(readFileSync(join(profileDir, "DevToolsActivePort"), "utf8").split("\n")[0]);

    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 15_000 });
    extId = new URL(sw.url()).host;

    site = await context.newPage();
    await site.goto(siteUrl);
  }, 120_000);

  afterAll(async () => {
    popup?.close();
    await context?.close();
    await new Promise<void>((r) => server?.close(() => r()));
    rmSync(profileDir, { recursive: true, force: true });
  });

  it("injects the fill button without resizing the password field", async () => {
    await site.waitForSelector("button[data-nopass-button]", { timeout: 10_000 });
    const { fieldParentId, emailWidth, passwordWidth } = await site.evaluate(() => {
      const pass = document.getElementById("password") as HTMLInputElement;
      return {
        fieldParentId: pass.parentElement?.id,
        emailWidth: document.getElementById("email")!.getBoundingClientRect().width,
        passwordWidth: pass.getBoundingClientRect().width,
      };
    });
    expect(fieldParentId).toBe("login-form");
    expect(passwordWidth).toBe(emailWidth);
  });

  it("rejects UNLOCK from a tab-hosted popup page", async () => {
    const tabPopup = await context.newPage();
    await tabPopup.goto(`chrome-extension://${extId}/src/popup/index.html`);
    const resp = await tabPopup.evaluate(
      () => new Promise((res) => {
        chrome.runtime.sendMessage(
          { type: "UNLOCK", sessionToken: "x", defaultVaultId: "x", vaultEncKeyB64: "", vaultMacKeyB64: "" },
          res,
        );
      }),
    );
    expect(resp).toEqual({ error: "unauthorized" });
    await tabPopup.close();
  });

  it("unlocks the vault through the real action popup", async () => {
    await site.bringToFront();
    const sw = context.serviceWorkers()[0]!;
    await sw.evaluate(() => chrome.action.openPopup());
    popup = await PopupDriver.attach(cdpPort, extId);

    await popup.waitFor(`document.querySelector("input[type=email]") !== null`, 10_000);
    await popup.setValue("input[type=email]", EMAIL);
    await popup.setValue("input[type=password]", PASSWORD);
    await popup.eval(`document.querySelector("form").requestSubmit()`);

    const result = await popup.waitFor<string>(
      `document.querySelector("input[type=search]") ? "unlocked"
        : document.querySelector("p.text-danger")?.textContent || ""`,
      90_000,
    );
    expect(result).toBe("unlocked");
  }, 100_000);

  it("lists the URL-matched entry for the active tab", async () => {
    const entryText = await popup.waitFor<string>(
      `document.querySelector("li")?.textContent || ""`,
      10_000,
    );
    expect(entryText).toContain("E2E Test Site");
    expect(entryText).toContain("e2e-user@example.com");
  });

  it("autofills credentials into the page", async () => {
    await popup.eval(`{
      const btn = [...document.querySelectorAll("button")].find(b => b.textContent === "Autofill");
      btn.click();
    }`);
    await site.waitForFunction(
      () => (document.getElementById("password") as HTMLInputElement).value.length > 0,
      undefined,
      { timeout: 10_000 },
    );
    const filled = await site.evaluate(() => ({
      email: (document.getElementById("email") as HTMLInputElement).value,
      password: (document.getElementById("password") as HTMLInputElement).value,
    }));
    expect(filled).toEqual({ email: "e2e-user@example.com", password: "e2e-password-value" });
  });

  it("stays unlocked after the service worker is killed", async () => {
    // Kill the SW the way Chrome does after ~30s idle (browser-level CDP)
    const { webSocketDebuggerUrl } = await (
      await fetch(`http://127.0.0.1:${cdpPort}/json/version`)
    ).json();
    const bws = new WebSocket(webSocketDebuggerUrl);
    await new Promise((res, rej) => { bws.onopen = res; bws.onerror = rej; });
    const browserCdp = (id: number, method: string, params: object = {}) =>
      new Promise<any>((resolve) => {
        const onMsg = (ev: MessageEvent) => {
          const m = JSON.parse(String(ev.data));
          if (m.id === id) {
            bws.removeEventListener("message", onMsg);
            resolve(m.result);
          }
        };
        bws.addEventListener("message", onMsg);
        bws.send(JSON.stringify({ id, method, params }));
      });
    const { targetInfos } = await browserCdp(1, "Target.getTargets");
    const swTarget = targetInfos.find(
      (t: any) => t.type === "service_worker" && t.url.includes(extId),
    );
    expect(swTarget).toBeTruthy();
    await browserCdp(2, "Target.closeTarget", { targetId: swTarget.targetId });
    bws.close();

    // Opening an extension page spawns a fresh SW, which must rehydrate the
    // unlocked session from chrome.storage.session — no master password
    const tabPopup = await context.newPage();
    await tabPopup.goto(`chrome-extension://${extId}/src/popup/index.html`);
    await tabPopup.waitForSelector("input[type=search]", { timeout: 15_000 });
    await tabPopup.fill("input[type=search]", "E2E");
    await tabPopup.waitForSelector("text=e2e-user@example.com", { timeout: 10_000 });
    await tabPopup.close();
  });

  it("prefills the remembered email after locking", async () => {
    await site.bringToFront();
    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 15_000 });
    await sw.evaluate(() => chrome.action.openPopup());
    const popup2 = await PopupDriver.attach(cdpPort, extId);

    await popup2.waitFor(`document.querySelector("input[type=search]") !== null`, 10_000);
    await popup2.eval(`{
      [...document.querySelectorAll("button")].find(b => b.textContent === "Lock").click();
    }`);
    const prefilled = await popup2.waitFor<string>(
      `document.querySelector("input[type=email]")?.value || ""`,
      10_000,
    );
    expect(prefilled).toBe(EMAIL);
    popup2.close();
  });
});

if (!runnable) {
  // eslint-disable-next-line no-console
  console.log(
    `[extension e2e] skipped — api=${apiAvailable} dist=${distBuilt} chromium=${browserInstalled}`,
  );
}
