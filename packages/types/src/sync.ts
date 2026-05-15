/** Lamport vector clock: device_id → last sequence number observed */
export type VectorClock = Record<string, number>;

export type SyncEventType = "upsert" | "delete";

export interface SyncEvent {
  id: string;
  userId: string;
  deviceId: string;
  sequenceNumber: number;
  eventType: SyncEventType;
  itemId: string;
  /** base64 AES-GCM encrypted field-level delta (for partial updates) */
  encryptedDelta: string | null;
  deltaIv: string | null;
  createdAt: string;
}

export interface SyncCheckpoint {
  deviceId: string;
  lastSyncedSequence: number;
}

export interface SyncRequest {
  knownCheckpoints: SyncCheckpoint[];
}

export interface SyncResponse {
  events: SyncEvent[];
  serverClock: VectorClock;
}
