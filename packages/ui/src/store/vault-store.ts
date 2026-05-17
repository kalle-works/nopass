/**
 * Central Zustand vault store — shared by web app, desktop, and extension.
 *
 * Security invariants:
 * - vaultEncKey and vaultMacKey are CryptoKey objects (non-extractable)
 * - plaintext VaultItemPlaintext values are NOT stored here — they live in
 *   per-component state only, decrypted on demand
 * - on lock(), all key material is explicitly discarded
 */
import { create } from "zustand";
import type {
  EncryptedVaultItem,
  KdfParams,
  SrpVerifyResponse,
  VaultItemPlaintext,
  VaultItemType,
} from "@nopass/types";
import type { DerivedKeys } from "@nopass/crypto";

interface AuthState {
  sessionToken: string | null;
  userId: string | null;
  defaultVaultId: string | null;
}

interface CryptoState {
  /** Non-extractable AES-256-GCM key — null when vault is locked */
  vaultEncKey: CryptoKey | null;
  /** Non-extractable HMAC-SHA256 key — null when vault is locked */
  vaultMacKey: CryptoKey | null;
  /** The user's email (needed to re-derive keys after biometric unlock) */
  email: string | null;
  kdfParams: KdfParams | null;
  /** stretchedMasterKey is kept in memory to decrypt org private keys on demand */
  stretchedMasterKey: CryptoKey | null;
  /** RSA private key (encrypted) — needed to decrypt org vault keys */
  protectedPrivateKey: string | null;
  protectedPrivateKeyIv: string | null;
}

interface VaultState {
  items: EncryptedVaultItem[];
  isLoading: boolean;
  lastSyncAt: string | null;
}

interface NopassStore extends AuthState, CryptoState, VaultState {
  // Auth actions
  setSession: (auth: SrpVerifyResponse, email: string, keys: DerivedKeys) => void;
  lock: () => void;
  setKeyPair: (protectedPrivateKey: string, protectedPrivateKeyIv: string) => void;

  // Vault actions
  setItems: (items: EncryptedVaultItem[]) => void;
  upsertItem: (item: EncryptedVaultItem) => void;
  markDeleted: (itemId: string) => void;
  setLoading: (loading: boolean) => void;
  setLastSyncAt: (ts: string) => void;
  setDefaultVaultId: (id: string) => void;

  // Derived helpers
  isUnlocked: () => boolean;
  activeItems: () => EncryptedVaultItem[];
  itemsByType: (type: VaultItemType) => EncryptedVaultItem[];
}

export const useNopassStore = create<NopassStore>((set, get) => ({
  // Auth
  sessionToken: null,
  userId: null,
  defaultVaultId: null,

  // Crypto (null = locked)
  vaultEncKey: null,
  vaultMacKey: null,
  email: null,
  kdfParams: null,
  stretchedMasterKey: null,
  protectedPrivateKey: null,
  protectedPrivateKeyIv: null,

  // Vault
  items: [],
  isLoading: false,
  lastSyncAt: null,

  setSession: (auth, email, keys) =>
    set({
      sessionToken: auth.sessionToken,
      userId: auth.userId,
      defaultVaultId: auth.defaultVaultId,
      email,
      vaultEncKey: keys.vaultEncKey,
      vaultMacKey: keys.vaultMacKey,
      stretchedMasterKey: keys.stretchedMasterKey,
      kdfParams: null,
      protectedPrivateKey: auth.protectedPrivateKey ?? null,
      protectedPrivateKeyIv: auth.protectedPrivateKeyIv ?? null,
    }),

  lock: () =>
    set({
      vaultEncKey: null,
      vaultMacKey: null,
      stretchedMasterKey: null,
      protectedPrivateKey: null,
      protectedPrivateKeyIv: null,
      items: [],
      lastSyncAt: null,
    }),

  setKeyPair: (protectedPrivateKey, protectedPrivateKeyIv) =>
    set({ protectedPrivateKey, protectedPrivateKeyIv }),

  setItems: (items) => set({ items }),
  upsertItem: (item) =>
    set((state) => ({
      items: state.items.some((i) => i.id === item.id)
        ? state.items.map((i) => (i.id === item.id ? item : i))
        : [...state.items, item],
    })),
  markDeleted: (itemId) =>
    set((state) => ({
      items: state.items.map((i) =>
        i.id === itemId ? { ...i, deletedAt: new Date().toISOString() } : i,
      ),
    })),
  setLoading: (isLoading) => set({ isLoading }),
  setLastSyncAt: (lastSyncAt) => set({ lastSyncAt }),
  setDefaultVaultId: (defaultVaultId) => set({ defaultVaultId }),

  isUnlocked: () => get().vaultEncKey !== null,
  activeItems: () => get().items.filter((i) => i.deletedAt === null),
  itemsByType: (type) => get().activeItems().filter((i) => i.itemType === type),
}));
