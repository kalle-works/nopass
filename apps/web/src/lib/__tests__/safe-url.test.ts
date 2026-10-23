import { describe, expect, it } from "vitest";
import { safeHttpUrl } from "@/lib/safe-url";

describe("safeHttpUrl", () => {
  it("passes http and https URLs", () => {
    expect(safeHttpUrl("https://example.com/login")).toBe("https://example.com/login");
    expect(safeHttpUrl("http://example.com")).toBe("http://example.com/");
  });

  it("rejects script-capable and non-web schemes, including obfuscated ones", () => {
    for (const raw of [
      "javascript:alert(1)",
      "  JaVaScRiPt:alert(1)",
      "java\tscript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
    ]) {
      expect(safeHttpUrl(raw)).toBeNull();
    }
  });

  it("rejects scheme-less and empty values", () => {
    expect(safeHttpUrl("example.com")).toBeNull();
    expect(safeHttpUrl("")).toBeNull();
    expect(safeHttpUrl(undefined)).toBeNull();
  });
});
