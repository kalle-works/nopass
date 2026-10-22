import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { LoginItem } from "@nopass/types";
import { adoptSecret } from "../adopt.js";
import { parseDotenv, resolveReference } from "../secret-refs.js";

function writeTemp(name: string, content: string): string {
  const path = join(mkdtempSync(join(tmpdir(), "nopwd-adopt-")), name);
  writeFileSync(path, content);
  return path;
}

const SECRET = "sk-proj-a1b2#c3 d4\"e5";
const DOTENV = [
  "# api keys",
  "PORT=3000",
  `export OPENAI_API_KEY="${SECRET.replace(/"/g, '\\"')}"`,
  "DEBUG=true",
  "",
].join("\r\n");

describe("adoptSecret", () => {
  it("leaves the file byte-for-byte unchanged when saving to the vault fails", async () => {
    const path = writeTemp(".env", DOTENV);
    await expect(
      adoptSecret({
        path,
        line: 3,
        existingNames: [],
        saveItem: async () => {
          throw new Error("API unreachable");
        },
      }),
    ).rejects.toThrow("API unreachable");
    expect(readFileSync(path, "utf-8")).toBe(DOTENV);
  });

  it("rewrites a .env line to a reference that resolves back to the original value", async () => {
    const path = writeTemp(".env", DOTENV);
    const saved: LoginItem[] = [];
    const result = await adoptSecret({
      path,
      line: 3,
      name: "My OpenAI key",
      existingNames: [],
      saveItem: async (item) => {
        saved.push(item);
      },
    });

    expect(result.rewritten).toBe(true);
    const after = readFileSync(path, "utf-8");
    // Every other line, and the CRLF line endings, survive
    const before = DOTENV.split("\r\n");
    const lines = after.split("\r\n");
    expect(lines).toHaveLength(before.length);
    lines.forEach((l, i) => i !== 2 && expect(l).toBe(before[i]));
    expect(after).not.toContain("sk-proj");

    const entry = parseDotenv(after).find((e) => e.key === "OPENAI_API_KEY")!;
    expect(resolveReference(saved, entry.value)).toEqual({ ok: true, value: SECRET });
  });

  it("never edits a source file, and stores the quoted literal", async () => {
    const source = `const client = new OpenAI({ apiKey: "sk-live-0123456789abcdef", timeout: "30s" });\n`;
    const path = writeTemp("client.ts", source);
    const saved: LoginItem[] = [];
    const result = await adoptSecret({
      path,
      line: 1,
      existingNames: [],
      saveItem: async (item) => {
        saved.push(item);
      },
    });

    expect(result.rewritten).toBe(false);
    expect(readFileSync(path, "utf-8")).toBe(source);
    expect(saved[0]!.password).toBe("sk-live-0123456789abcdef");
  });

  it("refuses a name that already exists without saving anything", async () => {
    const path = writeTemp(".env", DOTENV);
    let saves = 0;
    await expect(
      adoptSecret({
        path,
        line: 3,
        name: "stripe",
        existingNames: ["Stripe"],
        saveItem: async () => {
          saves++;
        },
      }),
    ).rejects.toThrow(/already exists/);
    expect(saves).toBe(0);
    expect(readFileSync(path, "utf-8")).toBe(DOTENV);
  });
});
