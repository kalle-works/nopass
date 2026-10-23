import { describe, expect, it } from "vitest";
import { generateUserKeyPair, stretchMasterKey, verifyKeyBundle } from "@nopass/crypto";
import type { PublicKeyResponse, SetIdentityRequest } from "@nopass/types";
import type { ApiClient } from "../lib/api-client";
import { OwnKeyMismatchError, ensureIdentityPublished } from "../lib/identity-migration";

const USER = "11111111-1111-4111-8111-111111111111";

async function setup(serverPublicKey?: string) {
  const { stretchedMasterKey } = await stretchMasterKey(new Uint8Array(32).fill(1), "u@example.com");
  const pair = await generateUserKeyPair(stretchedMasterKey);
  const published: PublicKeyResponse = {
    userId: USER,
    publicKey: serverPublicKey ?? pair.publicKeyB64,
    identityPublicKey: null,
    publicKeySignature: null,
  };
  const uploads: SetIdentityRequest[] = [];
  const api = {
    keys: {
      me: async () => published,
      setIdentity: async (req: SetIdentityRequest) => {
        uploads.push(req);
      },
    },
  } as unknown as ApiClient;
  const own = {
    userId: USER,
    protectedPrivateKey: pair.protectedPrivateKey,
    protectedPrivateKeyIv: pair.protectedPrivateKeyIv,
    stretchedMasterKey,
  };
  return { api, own, published, uploads };
}

describe("ensureIdentityPublished", () => {
  it("gives an account without an identity key a valid signed bundle", async () => {
    const { api, own, published, uploads } = await setup();
    await ensureIdentityPublished(api, "token", own);

    expect(uploads).toHaveLength(1);
    expect(verifyKeyBundle({ ...published, ...uploads[0]! })).toBe(true);
  });

  it("refuses to vouch for a public key the server substituted", async () => {
    const { stretchedMasterKey } = await stretchMasterKey(new Uint8Array(32).fill(2), "m@example.com");
    const mallory = await generateUserKeyPair(stretchedMasterKey);
    const { api, own, uploads } = await setup(mallory.publicKeyB64);

    await expect(ensureIdentityPublished(api, "token", own)).rejects.toBeInstanceOf(OwnKeyMismatchError);
    expect(uploads).toHaveLength(0);
  });
});
