/**
 * MV3 Service Worker — background script for nopass extension.
 *
 * Security model:
 * - Vault keys never touch persistent storage. The unlocked session lives in
 *   chrome.storage.session: RAM-only, cleared when the browser exits, and
 *   readable only from trusted extension contexts (never content scripts).
 *   Without it the ephemeral SW would re-lock the vault ~30s after idle and
 *   force a master-password prompt several times a minute.
 * - Explicit Lock wipes both the in-memory state and storage.session, and so
 *   does auto-lock: after the configured inactivity window (chrome.alarms),
 *   or as soon as the OS reports the machine idle or screen-locked.
 * - Autofill goes to exactly one frame (the one whose field the user last
 *   focused, else the top frame) and only when that frame's origin matches
 *   the item per lib/url-match. A mismatch needs explicit popup confirmation,
 *   which is never accepted for a subframe.
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
  SYNCED_FLAGS,
} from "@nopass/crypto";
import { createApiClient } from "@nopass/ui";
import type { EncryptedVaultItem, LoginItem } from "@nopass/types";
import { base64ToBytes } from "../lib/base64";
import { urlMatches, nameMatches, isFillableOrigin, registrableDomain } from "../lib/url-match";
import { log } from "../lib/logger";
import { AUTO_LOCK_SETTING, parseAutoLockMinutes } from "../lib/auto-lock";

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

// ─── Auto-lock ────────────────────────────────────────────────────────────────

const AUTO_LOCK_ALARM = "autoLock";

async function autoLockMinutes(): Promise<number> {
  return parseAutoLockMinutes((await chrome.storage.local.get(AUTO_LOCK_SETTING))[AUTO_LOCK_SETTING]);
}

/** (Re)starts the inactivity countdown. Called on unlock and on every vault use. */
async function armAutoLock(): Promise<void> {
  const minutes = await autoLockMinutes();
  chrome.idle.setDetectionInterval(minutes * 60);
  await chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: minutes });
}

/** Wipes keys and session token from memory and storage.session. */
async function lockVault(reason: string): Promise<void> {
  lockGeneration++; // a restore in flight must not resurrect the session
  vaultState = null;
  await chrome.storage.session.remove(SESSION_KEY);
  await chrome.alarms.clear(AUTO_LOCK_ALARM);
  log.info("vault locked", { reason });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) void lockVault("inactivity");
});

chrome.idle.onStateChanged.addListener((state) => {
  if (state === "idle" || state === "locked") void lockVault(`system ${state}`);
});

// A changed timeout takes effect immediately rather than after the next use
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && AUTO_LOCK_SETTING in changes && vaultState) void armAutoLock();
});

// Single in-flight restore so concurrent messages after an SW restart don't
// each refetch the vault. (vaultState is assigned before the promise resolves
// and `restoring` is cleared, so a later caller that misses the in-flight
// promise short-circuits on the vaultState check instead of refetching.)
let restoring: Promise<void> | null = null;

// Bumped by LOCK so a restore that was already in flight when the user locked
// cannot resurrect the session when its network call finally returns.
let lockGeneration = 0;

/** Rehydrates the unlocked session after an SW restart, if one was persisted. */
function restoreVaultState(): Promise<void> {
  restoring ??= (async () => {
    if (vaultState) return;
    const generation = lockGeneration;
    const stored = (await chrome.storage.session.get(SESSION_KEY))[SESSION_KEY] as
      | PersistedSession
      | undefined;
    if (!stored) return;
    try {
      const { vaultEncKey, vaultMacKey } = await importVaultKeys(stored.encKeyB64, stored.macKeyB64);
      const items = await api.vault.items(stored.defaultVaultId, stored.sessionToken);
      // A LOCK (or a fresh UNLOCK) that happened while we awaited wins
      if (lockGeneration !== generation || vaultState) return;
      vaultState = {
        sessionToken: stored.sessionToken,
        defaultVaultId: stored.defaultVaultId,
        vaultEncKey,
        vaultMacKey,
        items,
      };
      log.info("session restored after SW restart", { items: items.length });
    } catch (err) {
      // Server rejected the session (expired/revoked) — drop it and stay
      // locked, unless a newer session was persisted while we awaited
      if (lockGeneration === generation) {
        await chrome.storage.session.remove(SESSION_KEY);
        log.error("session restore failed, dropping session", { err: String(err) });
      } else {
        log.debug("session restore failed but superseded by newer generation, ignoring");
      }
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
  | { type: "AUTOFILL"; itemId: string; tabId: number; confirmedOrigin?: string }
  | { type: "FILL_TARGET" }
  | { type: "WEBAUTHN_AVAILABLE"; rpId: string }
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
  const t0 = performance.now();
  handleMessage(message, sender)
    .then((result) => {
      const ms = Math.round(performance.now() - t0);
      const hasError = result && typeof result === "object" && "error" in result;
      if (hasError) {
        log.warn(`${message.type} → error`, { ms, error: (result as { error: unknown }).error });
      } else {
        log.debug(`${message.type} → ok`, { ms });
      }
      sendResponse(result);
    })
    .catch((err) => {
      const ms = Math.round(performance.now() - t0);
      log.error(`${message.type} → throw`, { ms, err: String(err) });
      sendResponse({ error: err instanceof Error ? err.message : "Unknown error" });
    });
  return true; // keep the message channel open for the async response
});

/** Returns true if the sender is an extension page (popup/options), not a content script. */
function isExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && sender.tab === undefined;
}

/**
 * Returns true for any page served from this extension (popup, or an
 * extension page hosted in a tab) — but never for content scripts, whose
 * sender.url is the web page they run in. Vault reads use this; state
 * mutations (UNLOCK/LOCK/AUTOFILL) require the stricter isExtensionPage.
 */
function isExtensionContext(sender: chrome.runtime.MessageSender): boolean {
  return (
    sender.id === chrome.runtime.id &&
    (sender.url?.startsWith(`chrome-extension://${chrome.runtime.id}/`) ?? false)
  );
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
      lockGeneration++; // invalidate any restore still in flight
      vaultState = { sessionToken: message.sessionToken, defaultVaultId: message.defaultVaultId, vaultEncKey, vaultMacKey, items };
      log.info("vault unlocked", { items: items.length });
      await armAutoLock();

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
      await lockVault("user");
      return { ok: true };
    }

    case "IS_UNLOCKED": {
      // Web pages must not learn the lock state — report locked to them
      if (!isExtensionContext(sender)) return { unlocked: false };
      return { unlocked: vaultState !== null };
    }

    case "GET_ITEMS": {
      if (!isExtensionContext(sender)) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };
      await armAutoLock();
      return { items: vaultState.items };
    }

    case "SEARCH_ITEMS": {
      if (!isExtensionContext(sender)) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };
      await armAutoLock();
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
      // Plaintext credentials — only the popup may receive these, not
      // extension pages hosted in a tab (which have a sender.tab).
      if (!isExtensionPage(sender)) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };
      await armAutoLock();
      const item = vaultState.items.find((i) => i.id === message.itemId);
      if (!item) return { error: "item not found" };

      const plain = await decryptItem(item, vaultState.vaultEncKey, vaultState.vaultMacKey);
      if (plain.type !== "login") return { error: "not a login item" };

      return { username: plain.username, password: plain.password };
    }

    case "FILL_TARGET": {
      // A content script reports the frame whose login field the user is
      // interacting with. Everything recorded comes from the browser-set
      // sender, never from the message body.
      const target = senderFrame(sender);
      if (!target || sender.tab?.id === undefined) return { ok: false };
      await chrome.storage.session.set({ [fillTargetKey(sender.tab.id)]: target });
      return { ok: true };
    }

    case "AUTOFILL": {
      // Only the popup (an extension page) may trigger autofill.
      // Content scripts running in web pages must not be able to initiate credential fills.
      if (!isExtensionPage(sender)) return { error: "unauthorized" };
      if (!vaultState) return { error: "locked" };
      await armAutoLock();

      const item = vaultState.items.find((i) => i.id === message.itemId);
      if (!item) return { error: "item not found" };

      const plain = await decryptItem(item, vaultState.vaultEncKey, vaultState.vaultMacKey);
      if (plain.type !== "login") return { error: "not a login item" };

      const target = await resolveFillTarget(message.tabId);
      if (!target) return { error: "no_login_form" };

      if (!urlMatches(plain.urls, target.origin)) {
        // The user may knowingly fill a login saved for another site, but
        // only into the top frame of a secure page, and only after seeing
        // this exact origin. A subframe must match on its own.
        const confirmable = target.frameId === 0 && isFillableOrigin(target.origin);
        if (!confirmable || message.confirmedOrigin !== target.origin) {
          return { error: "origin_mismatch", origin: target.origin, confirmable };
        }
      }

      // The content script answers { filled: true } once it found a visible
      // password field. No receiver, or no answer, means there was no form.
      let filled = false;
      try {
        const result = await chrome.tabs.sendMessage<unknown, { filled?: boolean } | undefined>(
          message.tabId,
          {
            type: "FILL_CREDENTIALS",
            username: plain.username,
            password: plain.password,
            // The frame re-checks its own origin: a navigation between
            // resolving the target and delivery must not receive the fill
            origin: target.origin,
          },
          target.documentId !== undefined
            ? { frameId: target.frameId, documentId: target.documentId }
            : { frameId: target.frameId },
        );
        filled = result?.filled === true;
      } catch {
        filled = false;
      }

      // A stale recorded frame (navigated away) falls back to the top frame
      // on the next attempt
      if (!filled) await chrome.storage.session.remove(fillTargetKey(message.tabId));
      return filled ? { ok: true } : { error: "no_login_form" };
    }

    case "WEBAUTHN_AVAILABLE": {
      // The relay's pre-check before offering to save a passkey. IS_UNLOCKED
      // answers "locked" to every web page by design, so the relay asks this
      // instead: only for an rpId the asking page owns, and it reveals no
      // more than whether a CREATE for that rpId would proceed.
      const origin = senderOrigin(sender);
      if (!origin || !vaultState) return { available: false };
      return { available: rpIdMatchesOrigin(message.rpId, origin) && isRegistrableRpId(message.rpId) };
    }

    case "WEBAUTHN_HAS_CREDENTIAL": {
      // Same gate as CREATE/GET: otherwise any page could probe which
      // sites the user holds passkeys for by asking about foreign rpIds
      const origin = senderOrigin(sender);
      if (!origin || !vaultState) return { matches: false };
      if (!rpIdMatchesOrigin(message.rpId, origin) || !isRegistrableRpId(message.rpId)) {
        return { matches: false };
      }
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

      await armAutoLock();
      const cred = await generateCredential();
      const authData = await buildAuthenticatorData(
        message.rpId,
        AUTHENTICATOR_FLAGS,
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
      await armAutoLock();

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
        AUTHENTICATOR_FLAGS,
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

/**
 * User presence only. The consent overlay proves a human clicked, but nothing
 * re-verifies who they are at ceremony time (the vault may have been unlocked
 * minutes ago by someone else), so asserting UV would be a lie the RP relies
 * on. The MAIN-world interceptor hands userVerification: "required" requests
 * to the native authenticator instead.
 */
const AUTHENTICATOR_FLAGS = FLAG_UP | SYNCED_FLAGS;

interface FillTarget {
  frameId: number;
  documentId?: string | undefined;
  origin: string;
}

function fillTargetKey(tabId: number): string {
  return `fillTarget:${tabId}`;
}

/** Frame identity of a content-script sender, from browser-set fields only. */
function senderFrame(sender: chrome.runtime.MessageSender): FillTarget | undefined {
  const origin = senderOrigin(sender);
  if (!origin || sender.frameId === undefined) return undefined;
  return { frameId: sender.frameId, documentId: sender.documentId, origin };
}

/**
 * The frame an autofill goes to: the one whose field the user last focused
 * in this tab, else the top frame.
 */
async function resolveFillTarget(tabId: number): Promise<FillTarget | undefined> {
  const key = fillTargetKey(tabId);
  const recorded = (await chrome.storage.session.get(key))[key] as FillTarget | undefined;
  if (recorded) return recorded;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url) return undefined;
    return { frameId: 0, origin: new URL(tab.url).origin };
  } catch {
    return undefined;
  }
}

/** Origin of a content-script sender — undefined for anything else. */
function senderOrigin(sender: chrome.runtime.MessageSender): string | undefined {
  if (sender.id !== chrome.runtime.id || !sender.tab || !sender.url) return undefined;
  if (sender.origin) return sender.origin;
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
 * Private PSL suffixes count (github.io), as they do for cookies.
 */
function isRegistrableRpId(rpId: string): boolean {
  if (rpId === "localhost") return true; // dev convenience, matches browsers
  return registrableDomain(rpId) !== null;
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
