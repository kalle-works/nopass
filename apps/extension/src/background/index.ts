/**
 * MV3 Service Worker — background script for nopass extension.
 *
 * Security model:
 * - Vault keys never touch persistent storage. The unlocked session lives in
 *   chrome.storage.session: RAM-only, cleared when the browser exits, and
 *   readable only from trusted extension contexts (never content scripts).
 *   Without it the ephemeral SW would re-lock the vault ~30s after idle and
 *   force a master-password prompt several times a minute.
 * - Explicit Lock wipes both the in-memory state and storage.session.
 * - Only extension pages (popup) may trigger UNLOCK/LOCK/AUTOFILL.
 *   Content scripts (running in web pages) are rejected for these operations.
 * - Raw key bytes are zeroed immediately after CryptoKey import.
 */

import {
  decryptItem,
  encryptItem,
  generateCredential,
  buildAuthenticatorData,
  buildAttestationObject,
  signAssertion,
  rpIdMatchesOrigin,
  bytesToB64u,
  b64uToBytes,
  FLAG_UP,
  FLAG_UV,
  SYNCED_FLAGS,
} from "@nopass/crypto";
import { createApiClient } from "@nopass/ui";
import { parse as parseDomain } from "tldts";
import type { EncryptedVaultItem, LoginItem } from "@nopass/types";
import { base64ToBytes } from "../lib/base64";
import { urlMatches, nameMatches } from "../lib/url-match";

// Configurable at build time via Vite define; falls back to dev server.
const API_BASE: string =
  typeof __API_BASE__ !== "undefined" ? __API_BASE__ : "http://localhost:3001";

const api = createApiClient(API_BASE);

// In-memory vault state — null means locked.
let vaultState: {
  sessionToken: string;
  defaultVaultId: string;
  vaultEncKey: CryptoKey;
  vaultMacKey: CryptoKey;
  items: EncryptedVaultItem[];
} | null = null;

const SESSION_KEY = "vaultSession";

interface PersistedSession {
  sessionToken: string;
  defaultVaultId: string;
  encKeyB64: string;
  macKeyB64: string;
}

async function importVaultKeys(encKeyB64: string, macKeyB64: string) {
  const encKeyBytes = base64ToBytes(encKeyB64);
  const macKeyBytes = base64ToBytes(macKeyB64);
  const [vaultEncKey, vaultMacKey] = await Promise.all([
    crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    crypto.subtle.importKey("raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]),
  ]);
  // Zero raw key bytes immediately after import — they must not linger in memory.
  encKeyBytes.fill(0);
  macKeyBytes.fill(0);
  return { vaultEncKey, vaultMacKey };
}

// Single in-flight restore so concurrent messages after an SW restart don't
// each refetch the vault.
let restoring: Promise<void> | null = null;

/** Rehydrates the unlocked session after an SW restart, if one was persisted. */
function restoreVaultState(): Promise<void> {
  restoring ??= (async () => {
    if (vaultState) return;
    const stored = (await chrome.storage.session.get(SESSION_KEY))[SESSION_KEY] as
      | PersistedSession
      | undefined;
    if (!stored) return;
    try {
      const { vaultEncKey, vaultMacKey } = await importVaultKeys(stored.encKeyB64, stored.macKeyB64);
      const items = await api.vault.items(stored.defaultVaultId, stored.sessionToken);
      vaultState = {
        sessionToken: stored.sessionToken,
        defaultVaultId: stored.defaultVaultId,
        vaultEncKey,
        vaultMacKey,
        items,
      };
    } catch {
      // Server rejected the session (expired/revoked) — drop it and stay locked
      await chrome.storage.session.remove(SESSION_KEY);
    }
  })().finally(() => {
    restoring = null;
  });
  return restoring;
}

type Message =
  | { type: "UNLOCK"; sessionToken: string; defaultVaultId: string; vaultEncKeyB64: string; vaultMacKeyB64: string }
  | { type: "LOCK" }
  | { type: "IS_UNLOCKED" }
  | { type: "GET_ITEMS" }
  | { type: "SEARCH_ITEMS"; query: string; url?: string }
  | { type: "GET_CREDENTIALS"; itemId: string }
  | { type: "AUTOFILL"; itemId: string; tabId: number }
  | { type: "WEBAUTHN_HAS_CREDENTIAL"; rpId: string; allowCredentialIdsB64u: string[] }
  | {
      type: "WEBAUTHN_CREATE";
      rpId: string;
      rpName: string;
      userName: string;
      userDisplayName: string;
      userHandleB64u: string;
      excludeCredentialIdsB64u: string[];
    }
  | {
      type: "WEBAUTHN_GET";
      rpId: string;
      clientDataJSONB64u: string;
      allowCredentialIdsB64u: string[];
    };

chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((err) => {
    sendResponse({ error: err instanceof Error ? err.message : "Unknown error" });
  });
  return true; // keep the message channel open for the async response
});

/** Returns true if the sender is an extension page (popup/options), not a content script. */
function isExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && sender.tab === undefined;
}

async function handleMessage(message: Message, sender: chrome.runtime.MessageSender): Promise<unknown> {
  // The SW may have been torn down since the vault was unlocked — rehydrate
  // from storage.session before treating any request as locked.
  if (!vaultState && message.type !== "UNLOCK" && message.type !== "LOCK") {
    await restoreVaultState();
  }

  switch (message.type) {
    case "UNLOCK": {
      if (!isExtensionPage(sender)) return { error: "unauthorized" };

      const { vaultEncKey, vaultMacKey } = await importVaultKeys(
        message.vaultEncKeyB64,
        message.vaultMacKeyB64,
      );

      const items = await api.vault.items(message.defaultVaultId, message.sessionToken);
      vaultState = { sessionToken: message.sessionToken, defaultVaultId: message.defaultVaultId, vaultEncKey, vaultMacKey, items };

      const persisted: PersistedSession = {
        sessionToken: message.sessionToken,
        defaultVaultId: message.defaultVaultId,
        encKeyB64: message.vaultEncKeyB64,
        macKeyB64: message.vaultMacKeyB64,
      };
      await chrome.storage.session.set({ [SESSION_KEY]: persisted });
      return { ok: true };
    }

    case "LOCK": {
      if (!isExtensionPage(sender)) return { error: "unauthorized" };
      vaultState = null;
      await chrome.storage.session.remove(SESSION_KEY);
      return { ok: true };
    }

    case "IS_UNLOCKED": {
      return { unlocked: vaultState !== null };
    }

    case "GET_ITEMS": {
      if (!vaultState) return { error: "locked" };
      return { items: vaultState.items };
    }

    case "SEARCH_ITEMS": {
      if (!vaultState) return { error: "locked" };
      const { query, url } = message;
      const { vaultEncKey, vaultMacKey, items } = vaultState;

      const results = await Promise.all(
        items
          .filter((i) => i.deletedAt === null && i.itemType === "login")
          .map(async (item) => {
            try {
              const plain = await decryptItem(item, vaultEncKey, vaultMacKey);
              if (plain.type !== "login") return null;
              if (nameMatches(plain.name, query) || (url ? urlMatches(plain.urls, url) : !query)) {
                return {
                  id: item.id,
                  name: plain.name,
                  username: plain.username,
                  urls: plain.urls,
                  hasPasskey: plain.passkey !== undefined,
                };
              }
              return null;
            } catch {
              return null;
            }
          }),
      );

      return { results: results.filter(Boolean) };
    }

    case "GET_CREDENTIALS": {
      if (!vaultState) return { error: "locked" };
      const item = vaultState.items.find((i) => i.id === message.itemId);
      if (!item) return { error: "item not found" };

      const plain = await decryptItem(item, vaultState.vaultEncKey, vaultState.vaultMacKey);
      if (plain.type !== "login") return { error: "not a login item" };

      return { username: plain.username, password: plain.password };
    }

    case "AUTOFILL": {
      // Only the popup (an extension page) may trigger autofill.
      // Content scripts running in web pages must not be able to initiate credential fills.
      if (!isExtensionPage(sender)) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };

      const item = vaultState.items.find((i) => i.id === message.itemId);
      if (!item) return { error: "item not found" };

      const plain = await decryptItem(item, vaultState.vaultEncKey, vaultState.vaultMacKey);
      if (plain.type !== "login") return { error: "not a login item" };

      await chrome.tabs.sendMessage(message.tabId, {
        type: "FILL_CREDENTIALS",
        username: plain.username,
        password: plain.password,
      });

      return { ok: true };
    }

    case "WEBAUTHN_HAS_CREDENTIAL": {
      if (!senderOrigin(sender) || !vaultState) return { matches: false };
      const matches = await findPasskeyLogins(message.rpId, message.allowCredentialIdsB64u);
      return { matches: matches.length > 0 };
    }

    case "WEBAUTHN_CREATE": {
      const origin = senderOrigin(sender);
      if (!origin) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };
      if (!rpIdMatchesOrigin(message.rpId, origin) || !isRegistrableRpId(message.rpId)) {
        return { error: "rpId does not match origin" };
      }

      // The RP excludes credentials it already knows — re-registering would
      // orphan the existing one
      const existing = await findPasskeyLogins(message.rpId, []);
      if (
        existing.some((e) =>
          message.excludeCredentialIdsB64u.includes(e.plain.passkey!.credentialIdB64u),
        )
      ) {
        return { error: "already registered" };
      }

      const cred = await generateCredential();
      const authData = await buildAuthenticatorData(
        message.rpId,
        FLAG_UP | FLAG_UV | SYNCED_FLAGS,
        0,
        { credentialId: cred.credentialId, cosePublicKey: cred.cosePublicKey },
      );
      const attestationObject = buildAttestationObject(authData);

      const item: LoginItem = {
        type: "login",
        name: message.rpName || message.rpId,
        username: message.userName || message.userDisplayName,
        password: "",
        urls: [`https://${message.rpId}`],
        customFields: [],
        passkey: {
          credentialIdB64u: bytesToB64u(cred.credentialId),
          rpId: message.rpId,
          userHandleB64u: message.userHandleB64u,
          userName: message.userName || message.userDisplayName,
          privateKeyPkcs8B64: btoa(String.fromCharCode(...cred.privateKeyPkcs8)),
          signCount: 0,
          createdAt: new Date().toISOString(),
        },
      };
      cred.privateKeyPkcs8.fill(0);

      const blob = await encryptItem(item, vaultState.vaultEncKey, vaultState.vaultMacKey);
      const created = await api.vault.create(
        vaultState.defaultVaultId,
        { itemType: "login", blob: blob.blob, blobIv: blob.blobIv, blobMac: blob.blobMac },
        vaultState.sessionToken,
      );
      vaultState.items.push(created);

      return {
        data: {
          credentialIdB64u: bytesToB64u(cred.credentialId),
          attestationObjectB64u: bytesToB64u(attestationObject),
          authDataB64u: bytesToB64u(authData),
          publicKeySpkiB64u: bytesToB64u(cred.publicKeySpki),
        },
      };
    }

    case "WEBAUTHN_GET": {
      const origin = senderOrigin(sender);
      if (!origin) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };
      if (!rpIdMatchesOrigin(message.rpId, origin) || !isRegistrableRpId(message.rpId)) {
        return { error: "rpId does not match origin" };
      }

      const candidates = await findPasskeyLogins(message.rpId, message.allowCredentialIdsB64u);
      if (candidates.length === 0) return { error: "no matching credential" };

      // Most recently created wins when the RP doesn't narrow it down
      candidates.sort((a, b) =>
        (b.plain.passkey!.createdAt ?? "").localeCompare(a.plain.passkey!.createdAt ?? ""),
      );
      const { item, plain } = candidates[0]!;
      const passkey = plain.passkey!;

      // Sign FIRST — persisting an incremented signCount before a failed
      // signature would make the RP see a counter jump and flag the
      // credential as cloned, bricking it permanently
      const newCount = passkey.signCount + 1;
      const authData = await buildAuthenticatorData(
        message.rpId,
        FLAG_UP | FLAG_UV | SYNCED_FLAGS,
        newCount,
      );
      const clientDataHash = new Uint8Array(
        await crypto.subtle.digest("SHA-256", b64uToBytes(message.clientDataJSONB64u)),
      );
      const pkcs8 = new Uint8Array(base64ToBytes(passkey.privateKeyPkcs8B64));
      const signature = await signAssertion(pkcs8, authData, clientDataHash);
      pkcs8.fill(0);

      const updatedPlain: LoginItem = {
        ...plain,
        passkey: { ...passkey, signCount: newCount },
      };
      const blob = await encryptItem(updatedPlain, vaultState.vaultEncKey, vaultState.vaultMacKey);
      const updated = await api.vault.update(
        item.vaultId,
        item.id,
        { blob: blob.blob, blobIv: blob.blobIv, blobMac: blob.blobMac, version: item.version },
        vaultState.sessionToken,
      );
      Object.assign(item, blob, { version: updated.version, updatedAt: updated.updatedAt });

      return {
        data: {
          credentialIdB64u: passkey.credentialIdB64u,
          authDataB64u: bytesToB64u(authData),
          signatureB64u: bytesToB64u(signature),
          userHandleB64u: passkey.userHandleB64u,
        },
      };
    }

    default:
      return { error: "unknown message type" };
  }
}

/** Origin of a content-script sender — undefined for anything else. */
function senderOrigin(sender: chrome.runtime.MessageSender): string | undefined {
  if (sender.id !== chrome.runtime.id || !sender.tab || !sender.url) return undefined;
  try {
    return new URL(sender.url).origin;
  } catch {
    return undefined;
  }
}

/**
 * rpIdMatchesOrigin checks label boundaries, but per WebAuthn §5.1.3 the rp.id
 * must also be a REGISTRABLE domain — "com", "co.uk", or "github.io" would
 * otherwise let one site mint credentials every sibling site can discover.
 */
function isRegistrableRpId(rpId: string): boolean {
  if (rpId === "localhost") return true; // dev convenience, matches browsers
  return parseDomain(rpId).domain !== null;
}

async function findPasskeyLogins(
  rpId: string,
  allowCredentialIdsB64u: string[],
): Promise<Array<{ item: EncryptedVaultItem; plain: LoginItem }>> {
  if (!vaultState) return [];
  const { vaultEncKey, vaultMacKey, items } = vaultState;

  const results = await Promise.all(
    items
      .filter((i) => i.deletedAt === null && i.itemType === "login")
      .map(async (item) => {
        try {
          const plain = await decryptItem(item, vaultEncKey, vaultMacKey);
          if (plain.type !== "login" || !plain.passkey) return null;
          if (plain.passkey.rpId !== rpId) return null;
          if (
            allowCredentialIdsB64u.length > 0 &&
            !allowCredentialIdsB64u.includes(plain.passkey.credentialIdB64u)
          ) {
            return null;
          }
          return { item, plain };
        } catch {
          return null;
        }
      }),
  );
  return results.filter((r): r is { item: EncryptedVaultItem; plain: LoginItem } => r !== null);
}
