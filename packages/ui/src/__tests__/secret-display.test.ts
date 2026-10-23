import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SecretText } from "../primitives/Secret";
import { glyphRuns } from "../primitives/secret-glyphs";
import { estimateStrength, MASTER_PASSWORD_MIN_LEVEL } from "../primitives/strength";

describe("secret display", () => {
  it("renders the same mask for secrets of any length so length never leaks", () => {
    const short = renderToStaticMarkup(createElement(SecretText, { value: "abc", masked: true }));
    const long = renderToStaticMarkup(createElement(SecretText, { value: "x".repeat(64), masked: true }));
    expect(short).toBe(long);
    expect(short).not.toContain("abc");
  });

  it("colored runs reassemble to exactly the original secret", () => {
    const secret = "aB3$x😀9--Z";
    expect(glyphRuns(secret).map((r) => r.text).join("")).toBe(secret);
  });

  it("separates look-alike digits from letters", () => {
    expect(glyphRuns("O0l1")).toEqual([
      { kind: "letter", text: "O" },
      { kind: "digit", text: "0" },
      { kind: "letter", text: "l" },
      { kind: "digit", text: "1" },
    ]);
  });
});

describe("master password strength gate", () => {
  it("rejects common passwords", () => {
    expect(estimateStrength("password123").level).toBeLessThan(MASTER_PASSWORD_MIN_LEVEL);
  });

  it("accepts a long random passphrase", () => {
    expect(estimateStrength("correct-orbit-Vellum-74-quietly-harbor").level).toBe(MASTER_PASSWORD_MIN_LEVEL);
  });

  it("an empty password fills no segments", () => {
    expect(estimateStrength("").level).toBe(0);
  });
});
