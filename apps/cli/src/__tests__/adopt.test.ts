import { mkdtempSync, readFileSync, readlinkSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { LoginItem, VaultItemPlaintext } from "@nopass/types";
import { adoptSecret } from "../adopt.js";
import { selectInjectedItems } from "../commands/run.js";
import { parseDotenv, resolveReference } from "../secret-refs.js";

function writeTemp(name: string, content: string): string {
  const path = join(mkdtempSync(join(tmpdir(), "nopwd-adopt-")), name);
  writeFileSync(path, content);
  return path;
}

const SECRET = "sk-proj-a1b2#c3 d4\"e5";
// BOM, mixed line endings and an inline comment: a rewrite must keep all of them
const DOTENV =
  "\uFEFF# api keys\r\n" +
  "PORT=3000\n" +
  `export OPENAI_API_KEY="${SECRET.replace(/"/g, '\\"')}" # rotated monthly\r\n` +
  "DEBUG=true\n";

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
    expect(after).toBe(DOTENV.replace(/export OPENAI_API_KEY=.*(?= # rotated)/, `export OPENAI_API_KEY='${result.reference}'`));

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

  it("refuses a multi-line value instead of saving the first line of it", async () => {
    const content = 'KEY="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"\n';
    const path = writeTemp(".env", content);
    let saves = 0;
    await expect(
      adoptSecret({ path, line: 1, existingNames: [], saveItem: async () => { saves++; } }),
    ).rejects.toThrow(/multi-line/);
    expect(saves).toBe(0);
    expect(readFileSync(path, "utf-8")).toBe(content);
  });

  it("rewrites the file a symlinked .env points at and keeps the link", async () => {
    const target = writeTemp(".env.shared", "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n");
    const link = join(dirname(target), ".env");
    symlinkSync(target, link);
    await adoptSecret({ path: link, line: 1, name: "gh", existingNames: [], saveItem: async () => {} });
    expect(readlinkSync(link)).toBe(target);
    expect(readFileSync(target, "utf-8")).toBe("TOKEN='nopwd://gh/password'\n");
  });

  it("refuses a source line with several candidate secrets unless --match picks one", async () => {
    const path = writeTemp("db.ts", `connect("postgres://db.internal/app", "s3cr3t-pa55word");\n`);
    const saved: LoginItem[] = [];
    const save = async (item: LoginItem) => { saved.push(item); };
    await expect(adoptSecret({ path, line: 1, existingNames: [], saveItem: save })).rejects.toThrow(/several/);
    expect(saved).toHaveLength(0);
    await adoptSecret({ path, line: 1, match: "s3cr", existingNames: [], saveItem: save });
    expect(saved[0]!.password).toBe("s3cr3t-pa55word");
  });
});

describe("selectInjectedItems", () => {
  const vault: VaultItemPlaintext[] = [
    { type: "login", name: "Bank", username: "me", password: "hunter2", urls: [], customFields: [] },
  ];

  it("hands no vault items to the app when --dotenv names what it needs", () => {
    expect(selectInjectedItems(vault, { dotenv: ".env" })).toEqual([]);
  });
});
