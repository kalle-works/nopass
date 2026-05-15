use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncEventType {
    Upsert,
    Delete,
}

/// A single CRDT event in the append-only event log
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    /// Monotonically increasing per-device Lamport clock
    pub sequence_number: i64,
    pub event_type: SyncEventType,
    pub item_id: Uuid,
    /// Optional AES-GCM encrypted field-level delta (base64)
    pub encrypted_delta: Option<String>,
    pub delta_iv: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Lamport vector clock: device_id → last sequence number seen
pub type VectorClock = HashMap<String, i64>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCheckpoint {
    pub device_id: Uuid,
    pub last_synced_sequence: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequest {
    pub known_checkpoints: Vec<SyncCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub events: Vec<SyncEvent>,
    pub server_clock: VectorClock,
}
