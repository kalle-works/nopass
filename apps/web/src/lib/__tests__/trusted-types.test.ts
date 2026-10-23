import { describe, expect, it } from "vitest";
import { installScriptUrlPolicy, TRUSTED_TYPES_BOOT_SCRIPT } from "@/lib/trusted-types";

const ORIGIN = "https://nopwd.dev";

function createScriptURL(): (input: string) => string {
  let rules: { createScriptURL(input: string): string } | undefined;
  installScriptUrlPolicy({ createPolicy: (_name, r) => (rules = r) }, ORIGIN);
  return rules!.createScriptURL;
}

describe("trusted types default policy", () => {
  it("only mints script URLs for same-origin Next.js static chunks", () => {
    const mint = createScriptURL();
    expect(mint("/_next/static/chunks/188-gg81tx1pd.js")).toBe("/_next/static/chunks/188-gg81tx1pd.js");
    expect(mint("/_next/static/chunks/13ps_s~i9kg6p.js?dpl=abc")).toBe("/_next/static/chunks/13ps_s~i9kg6p.js?dpl=abc");
    expect(mint(`${ORIGIN}/_next/static/chunks/a.js`)).toBe(`${ORIGIN}/_next/static/chunks/a.js`);

    for (const bad of [
      "https://evil.example/_next/static/chunks/a.js",
      "//evil.example/_next/static/chunks/a.js",
      "/_next/static/../../evil.js",
      "/uploads/a.js",
      "/_next/static/chunks/a.html",
      "data:text/javascript,alert(1)",
      "javascript:alert(1)",
    ]) {
      expect(() => mint(bad), bad).toThrow(TypeError);
    }
  });

  it("registers only the default policy, with no HTML or script factories", () => {
    const registered: Array<[string, object]> = [];
    installScriptUrlPolicy({ createPolicy: (name, rules) => registered.push([name, rules]) }, ORIGIN);
    expect(registered.map(([name]) => name)).toEqual(["default"]);
    expect(Object.keys(registered[0]![1])).toEqual(["createScriptURL"]);
  });

  it("serializes into a self-contained script", () => {
    const created: string[] = [];
    new Function("window", "location", TRUSTED_TYPES_BOOT_SCRIPT)(
      { trustedTypes: { createPolicy: (name: string) => created.push(name) } },
      { origin: ORIGIN },
    );
    expect(created).toEqual(["default"]);
  });
});
