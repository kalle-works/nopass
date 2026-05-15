import Database from "@tauri-apps/plugin-sql";
import type { EncryptedVaultItem } from "@nopass/types";

let dbInstance: Database | null = null;

async function getDb(): Promise<Database> {
  if (!dbInstance) {
    dbInstance = await Database.load("sqlite:nopass.db");
    await dbInstance.execute(`
      CREATE TABLE IF NOT EXISTS vault_items (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        item_type TEXT NOT NULL,
        blob TEXT NOT NULL,
        blob_iv TEXT NOT NULL,
        blob_mac TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        deleted_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sync_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }
  return dbInstance;
}

export async function loadLocalItems(): Promise<EncryptedVaultItem[]> {
  const db = await getDb();
  return db.select<EncryptedVaultItem[]>("SELECT * FROM vault_items ORDER BY updated_at");
}

export async function upsertLocalItem(item: EncryptedVaultItem): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT INTO vault_items (id, vault_id, user_id, item_type, blob, blob_iv, blob_mac, version, deleted_at, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     ON CONFLICT(id) DO UPDATE SET
       blob = excluded.blob, blob_iv = excluded.blob_iv, blob_mac = excluded.blob_mac,
       version = excluded.version, deleted_at = excluded.deleted_at, updated_at = excluded.updated_at`,
    [item.id, item.vaultId, item.userId, item.itemType, item.blob, item.blobIv, item.blobMac,
     item.version, item.deletedAt, item.createdAt, item.updatedAt],
  );
}

export async function clearLocalItems(): Promise<void> {
  const db = await getDb();
  await db.execute("DELETE FROM vault_items");
}

export async function getSyncState(key: string): Promise<string | null> {
  const db = await getDb();
  const rows = await db.select<Array<{ value: string }>>(
    "SELECT value FROM sync_state WHERE key = $1",
    [key],
  );
  return rows[0]?.value ?? null;
}

export async function setSyncState(key: string, value: string): Promise<void> {
  const db = await getDb();
  await db.execute(
    "INSERT INTO sync_state (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    [key, value],
  );
}
