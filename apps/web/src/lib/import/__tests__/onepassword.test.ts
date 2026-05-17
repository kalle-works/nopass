import { describe, it, expect } from "vitest";
import { zipSync, strToU8 } from "fflate";
import { parseOnePux } from "../onepassword";

function makeOnePuxFile(data: object): File {
  const json = JSON.stringify(data);
  const zip = zipSync({ "export.data": strToU8(json) });
  return new File([zip], "export.1pux", { type: "application/zip" });
}

const baseExport = (items: object[]) => ({
  accounts: [
    {
      attrs: { name: "Test Account", email: "test@example.com", masterKeyUuid: "abc", type: "P" },
      vaults: [
        {
          attrs: { name: "Personal", type: "P" },
          items,
        },
      ],
    },
  ],
});

describe("parseOnePux", () => {
  it("rejects invalid (non-ZIP) data", async () => {
    const file = new File(["not a zip file"], "export.1pux");
    await expect(parseOnePux(file)).rejects.toThrow();
  });

  it("rejects ZIP without export.data", async () => {
    const zip = zipSync({ "other.json": strToU8("{}") });
    const file = new File([zip], "export.1pux");
    await expect(parseOnePux(file)).rejects.toThrow("export.data");
  });

  it("returns empty result for empty vaults", async () => {
    const file = makeOnePuxFile(baseExport([]));
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(0);
    expect(result.skipped).toBe(0);
    expect(result.vaultNames).toEqual(["Personal"]);
  });

  it("skips trashed items", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "1",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "Y",
          categoryUuid: "001",
          overview: { title: "Deleted Login" },
          details: { loginFields: [] },
        },
      ]),
    );
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });

  it("maps login items correctly", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "1",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "N",
          categoryUuid: "001",
          overview: { title: "My Bank", url: "https://bank.example.com" },
          details: {
            loginFields: [
              { value: "user@example.com", id: "username", name: "username", type: "T", designation: "username" },
              { value: "s3cr3t!", id: "password", name: "password", type: "P", designation: "password" },
            ],
            notesPlain: "Bank account notes",
          },
        },
      ]),
    );
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(1);
    const item = result.items[0];
    expect(item!.type).toBe("login");
    if (item!.type === "login") {
      expect(item.name).toBe("My Bank");
      expect(item.username).toBe("user@example.com");
      expect(item.password).toBe("s3cr3t!");
      expect(item.urls).toEqual(["https://bank.example.com"]);
      expect(item.notes).toBe("Bank account notes");
    }
  });

  it("maps secure note items correctly", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "2",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "N",
          categoryUuid: "003",
          overview: { title: "Wi-Fi Password" },
          details: { notesPlain: "SSID: HomeNet\nPassword: hunter2" },
        },
      ]),
    );
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(1);
    const item = result.items[0];
    expect(item!.type).toBe("note");
    if (item!.type === "note") {
      expect(item.name).toBe("Wi-Fi Password");
      expect(item.content).toContain("hunter2");
    }
  });

  it("maps credit card items correctly", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "3",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "N",
          categoryUuid: "002",
          overview: { title: "Visa" },
          details: {
            sections: [
              {
                title: "Card Details",
                fields: [
                  { title: "Card Number", id: "ccnum", kind: "string", value: "4111111111111111" },
                  { title: "Cardholder", id: "cardholder", kind: "string", value: "Jane Doe" },
                  { title: "Expiry Date", id: "expiry", kind: "monthYear", value: { monthYear: 202512 } },
                  { title: "CVV", id: "cvv", kind: "concealed", value: { concealed: "123" } },
                ],
              },
            ],
          },
        },
      ]),
    );
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(1);
    const item = result.items[0];
    expect(item!.type).toBe("card");
    if (item!.type === "card") {
      expect(item.name).toBe("Visa");
      expect(item.number).toBe("4111111111111111");
      expect(item.cardholderName).toBe("Jane Doe");
      expect(item.cvv).toBe("123");
      expect(item.expMonth).toBe("12");
      expect(item.expYear).toBe("2025");
    }
  });

  it("maps SSH key items correctly", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "4",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "N",
          categoryUuid: "115",
          overview: { title: "GitHub SSH Key" },
          details: {
            sections: [
              {
                title: "SSH Key",
                fields: [
                  {
                    title: "Private Key",
                    id: "private_key",
                    kind: "sshKey",
                    value: {
                      sshKey: {
                        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
                        publicKey: "ssh-ed25519 AAAA...",
                        fingerprint: "SHA256:abc",
                        keyType: "ed25519",
                      },
                    },
                  },
                ],
              },
            ],
          },
        },
      ]),
    );
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(1);
    const item = result.items[0];
    expect(item!.type).toBe("ssh_key");
    if (item!.type === "ssh_key") {
      expect(item.name).toBe("GitHub SSH Key");
      expect(item.privateKey).toContain("BEGIN OPENSSH");
      expect(item.publicKey).toContain("ssh-ed25519");
    }
  });

  it("maps unknown categories to notes", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "5",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "N",
          categoryUuid: "999",
          overview: { title: "Software License" },
          details: {
            notesPlain: "License key: XXXX-YYYY-ZZZZ",
            sections: [],
          },
        },
      ]),
    );
    const result = await parseOnePux(file);
    expect(result.items).toHaveLength(1);
    expect(result.items[0]!.type).toBe("note");
  });

  it("counts vault names correctly across multiple vaults", async () => {
    const data = {
      accounts: [
        {
          attrs: { name: "Work", email: "work@corp.com", masterKeyUuid: "x", type: "B" },
          vaults: [
            { attrs: { name: "Personal", type: "P" }, items: [] },
            { attrs: { name: "Work", type: "E" }, items: [] },
          ],
        },
      ],
    };
    const file = makeOnePuxFile(data);
    const result = await parseOnePux(file);
    expect(result.vaultNames).toEqual(["Personal", "Work"]);
  });

  it("extracts multiple URLs from overview.urls array", async () => {
    const file = makeOnePuxFile(
      baseExport([
        {
          uuid: "6",
          favIndex: 0,
          createdAt: 0,
          updatedAt: 0,
          trashed: "N",
          categoryUuid: "001",
          overview: {
            title: "Multi-URL",
            urls: [
              { label: "primary", url: "https://app.example.com" },
              { label: "secondary", url: "https://www.example.com" },
            ],
          },
          details: { loginFields: [] },
        },
      ]),
    );
    const result = await parseOnePux(file);
    const item = result.items[0];
    if (item!.type === "login") {
      expect(item.urls).toEqual(["https://app.example.com", "https://www.example.com"]);
    }
  });
});
