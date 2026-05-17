import { describe, it, expect, vi, beforeEach } from "vitest";
import { computeTotp } from "../lib/totp";

// RFC 6238 test vectors use SHA-1 with secret "12345678901234567890" encoded as ASCII bytes.
// Base32 of that secret = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
// Known TOTP values from the RFC test vector table (period=30, digits=8):
//   T=59          → counter=1  → TOTP=94287082
//   T=1111111109  → counter=37037036 → TOTP=07081804
//   T=1111111111  → counter=37037037 → TOTP=14050471

const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

function makeUri(secret: string, digits = 6, period = 30): string {
  return `otpauth://totp/Test?secret=${secret}&digits=${digits}&period=${period}`;
}

describe("computeTotp", () => {
  it("returns null for non-otpauth URIs", async () => {
    expect(await computeTotp("https://example.com")).toBeNull();
  });

  it("returns null for malformed URIs", async () => {
    expect(await computeTotp("not-a-uri")).toBeNull();
  });

  it("returns null when secret is missing", async () => {
    expect(await computeTotp("otpauth://totp/Test?digits=6")).toBeNull();
  });

  it("produces a 6-digit code with TOTP_SECRET test vector at T=59", async () => {
    vi.setSystemTime(59_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32, 8, 30));
    expect(result).not.toBeNull();
    expect(result!.code).toBe("94287082");
    vi.useRealTimers();
  });

  it("produces a 6-digit code with TOTP_SECRET test vector at T=1111111109", async () => {
    vi.setSystemTime(1_111_111_109_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32, 8, 30));
    expect(result).not.toBeNull();
    expect(result!.code).toBe("07081804");
    vi.useRealTimers();
  });

  it("produces a 6-digit code with TOTP_SECRET test vector at T=1111111111", async () => {
    vi.setSystemTime(1_111_111_111_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32, 8, 30));
    expect(result).not.toBeNull();
    expect(result!.code).toBe("14050471");
    vi.useRealTimers();
  });

  it("reports correct remainingSeconds within a period", async () => {
    // At T=45, period=30 → counter=1, remaining = 30 - (45 % 30) = 30 - 15 = 15
    vi.setSystemTime(45_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32, 6, 30));
    expect(result).not.toBeNull();
    expect(result!.remainingSeconds).toBe(15);
    vi.useRealTimers();
  });

  it("pads short codes with leading zeros", async () => {
    vi.setSystemTime(59_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32, 6, 30));
    expect(result).not.toBeNull();
    expect(result!.code).toHaveLength(6);
    vi.useRealTimers();
  });

  it("handles lowercase base32 secrets", async () => {
    vi.setSystemTime(59_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32.toLowerCase(), 8, 30));
    expect(result).not.toBeNull();
    expect(result!.code).toBe("94287082");
    vi.useRealTimers();
  });

  it("handles base32 secrets with padding", async () => {
    vi.setSystemTime(59_000);
    const result = await computeTotp(makeUri(RFC_SECRET_B32 + "==", 8, 30));
    expect(result).not.toBeNull();
    expect(result!.code).toBe("94287082");
    vi.useRealTimers();
  });
});
