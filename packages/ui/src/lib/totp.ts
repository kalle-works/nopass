// RFC 6238 TOTP implementation using Web Crypto API — no external dependencies.

function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((cleaned.length * 5) / 8));
  for (const char of cleaned) {
    const charIndex = alphabet.indexOf(char);
    if (charIndex === -1) continue;
    value = (value << 5) | charIndex;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return output.slice(0, index);
}

async function hmacSha1(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const keyBuf = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer;
  const dataBuf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const cryptoKey = await crypto.subtle.importKey("raw", keyBuf, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, dataBuf);
  return new Uint8Array(signature);
}

function counterToBytes(counter: number): Uint8Array {
  const buf = new Uint8Array(8);
  let remaining = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = remaining & 0xff;
    remaining = Math.floor(remaining / 256);
  }
  return buf;
}

export interface TotpResult {
  code: string;
  remainingSeconds: number;
}

export async function computeTotp(uri: string): Promise<TotpResult | null> {
  try {
    const url = new URL(uri);
    if (url.protocol !== "otpauth:") return null;
    const params = url.searchParams;
    const secret = params.get("secret");
    if (!secret) return null;
    const period = parseInt(params.get("period") ?? "30", 10);
    const digits = parseInt(params.get("digits") ?? "6", 10);

    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / period);
    const remainingSeconds = period - (now % period);

    const key = base32Decode(secret);
    const mac = await hmacSha1(key, counterToBytes(counter));

    const offset = mac[mac.length - 1]! & 0x0f;
    const code =
      (((mac[offset]! & 0x7f) << 24) |
        ((mac[offset + 1]! & 0xff) << 16) |
        ((mac[offset + 2]! & 0xff) << 8) |
        (mac[offset + 3]! & 0xff)) %
      Math.pow(10, digits);

    return {
      code: code.toString().padStart(digits, "0"),
      remainingSeconds,
    };
  } catch {
    return null;
  }
}
