/**
 * MV3 Service Worker — background script for nopass extension.
 *
 * Security model:
 * - Vault key (CryptoKey) lives in memory only; never persisted to storage
 * - Service workers are ephemeral — vault auto-locks when SW terminates
 * - Session token stored in session storage (cleared on browser close)
 */

import { decryptItem } from "@nopass/crypto";
import { createApiClient } from "@nopass/ui";
import type { EncryptedVaultItem } from "@nopass/types";

const API_BASE = "http://localhost:3001";
const api = createApiClient(API_BASE);

// In-memory vault state (lost when SW terminates = auto-lock)
let vaultState: {
  sessionToken: string;
  defaultVaultId: string;
  vaultEncKey: CryptoKey;
  vaultMacKey: CryptoKey;
  items: EncryptedVaultItem[];
} | null = null;

type Message =
  | { type: "UNLOCK"; sessionToken: string; defaultVaultId: string; vaultEncKeyB64: string; vaultMacKeyB64: string }
  | { type: "LOCK" }
  | { type: "IS_UNLOCKED" }
  | { type: "GET_ITEMS" }
  | { type: "SEARCH_ITEMS"; query: string; url?: string }
  | { type: "GET_CREDENTIALS"; itemId: string }
  | { type: "AUTOFILL"; itemId: string; tabId: number };

chrome.runtime.onMessage.addListener((message: Message, _sender, sendResponse) => {
  handleMessage(message).then(sendResponse).catch((err) => {
    sendResponse({ error: err instanceof Error ? err.message : "Unknown error" });
  });
  return true; // async response
});

async function handleMessage(message: Message): Promise<unknown> {
  switch (message.type) {
    case "UNLOCK": {
      const encKeyBytes = base64ToBytes(message.vaultEncKeyB64);
      const macKeyBytes = base64ToBytes(message.vaultMacKeyB64);
      const [vaultEncKey, vaultMacKey] = await Promise.all([
        crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
        crypto.subtle.importKey("raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]),
      ]);

      // Fetch items from API
      const items = await api.vault.items(message.defaultVaultId, message.sessionToken);

      vaultState = { sessionToken: message.sessionToken, defaultVaultId: message.defaultVaultId, vaultEncKey, vaultMacKey, items };
      return { ok: true };
    }

    case "LOCK": {
      vaultState = null;
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

              const nameMatch = plain.name.toLowerCase().includes(query.toLowerCase());
              const urlMatch = url
                ? plain.urls.some((u) => {
                    try {
                      return new URL(u).hostname === new URL(url).hostname;
                    } catch {
                      return false;
                    }
                  })
                : false;

              if (nameMatch || urlMatch || !query) {
                return { id: item.id, name: plain.name, username: plain.username, urls: plain.urls };
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

    default:
      return { error: "unknown message type" };
  }
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const buf = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
  return buf;
}
