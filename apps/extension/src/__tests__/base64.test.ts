import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64 } from "../lib/base64";

describe("base64ToBytes / bytesToBase64", () => {
  it("round-trips arbitrary bytes", () => {
    const original = new Uint8Array([0, 1, 2, 127, 128, 255]);
    const b64 = bytesToBase64(original);
    const decoded = base64ToBytes(b64);
    expect(decoded).toEqual(original);
  });

  it("round-trips 32-byte key material", () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i * 8;
    expect(base64ToBytes(bytesToBase64(key))).toEqual(key);
  });

  it("returns Uint8Array with ArrayBuffer backing", () => {
    const bytes = base64ToBytes(btoa("hello"));
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.buffer).toBeInstanceOf(ArrayBuffer);
  });

  it("produces standard base64 output", () => {
    // "hello" in ASCII is 104 101 108 108 111
    const bytes = new Uint8Array([104, 101, 108, 108, 111]);
    expect(bytesToBase64(bytes)).toBe(btoa("hello"));
  });

  it("handles empty input", () => {
    expect(base64ToBytes("")).toEqual(new Uint8Array(0));
    expect(bytesToBase64(new Uint8Array(0))).toBe("");
  });
});
