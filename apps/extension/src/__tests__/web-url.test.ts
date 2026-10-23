import { describe, it, expect } from "vitest";
import { siteHostname, webVaultUrl } from "../lib/web-url";

describe("webVaultUrl", () => {
  it("drops the api. subdomain in production", () => {
    expect(webVaultUrl("https://api.nopwd.dev")).toBe("https://nopwd.dev/vault");
  });

  it("maps the local API to the local web dev server", () => {
    expect(webVaultUrl("http://localhost:3001")).toBe("http://localhost:4020/vault");
  });
});

describe("siteHostname", () => {
  it("returns the hostname for web pages only", () => {
    expect(siteHostname("https://github.com/login")).toBe("github.com");
    expect(siteHostname("chrome://extensions")).toBe("");
    expect(siteHostname("chrome-extension://abc/src/popup/index.html")).toBe("");
    expect(siteHostname("")).toBe("");
  });
});
