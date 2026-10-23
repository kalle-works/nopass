import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { buildCsp } from "@/lib/csp";
import { proxy } from "@/proxy";

function directive(csp: string, name: string): string[] {
  const entry = csp.split("; ").find((d) => d.startsWith(`${name} `));
  return entry ? entry.split(" ").slice(1) : [];
}

describe("buildCsp", () => {
  const csp = buildCsp({ nonce: "abc", isDev: false, apiOrigin: "https://api.nopwd.dev" });

  it("allows scripts only through the nonce, never unsafe-inline", () => {
    const scriptSrc = directive(csp, "script-src");
    expect(scriptSrc).toContain("'nonce-abc'");
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
    expect(directive(csp, "style-src")).not.toContain("'unsafe-inline'");
  });

  it("locks down framing, embeds, base URI and form targets", () => {
    expect(directive(csp, "base-uri")).toEqual(["'none'"]);
    expect(directive(csp, "frame-ancestors")).toEqual(["'none'"]);
    expect(directive(csp, "frame-src")).toEqual(["'none'"]);
    expect(directive(csp, "object-src")).toEqual(["'none'"]);
    expect(directive(csp, "form-action")).toEqual(["'self'"]);
  });
});

describe("proxy", () => {
  it("issues a fresh nonce per request and mirrors it into the CSP header", () => {
    const a = proxy(new NextRequest("http://localhost/login"));
    const b = proxy(new NextRequest("http://localhost/login"));
    const cspA = a.headers.get("content-security-policy") ?? "";
    const cspB = b.headers.get("content-security-policy") ?? "";
    const nonceA = /'nonce-([^']+)'/.exec(cspA)?.[1];
    const nonceB = /'nonce-([^']+)'/.exec(cspB)?.[1];
    expect(nonceA).toBeTruthy();
    expect(nonceA).not.toEqual(nonceB);
    expect(directive(cspA, "script-src")).not.toContain("'unsafe-inline'");
  });
});

describe("buildCsp trusted types", () => {
  it("enforces Trusted Types in production with only the default policy name", () => {
    const prod = buildCsp({ nonce: "abc", isDev: false, apiOrigin: "https://api.nopwd.dev" });
    expect(directive(prod, "require-trusted-types-for")).toEqual(["'script'"]);
    expect(directive(prod, "trusted-types")).toEqual(["default"]);
  });
});
