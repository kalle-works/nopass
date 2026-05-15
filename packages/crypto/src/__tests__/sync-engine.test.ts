import { describe, expect, it } from "vitest";
import { applySyncEvents, buildSyncCheckpoints } from "../sync-engine";
import type { EncryptedVaultItem, SyncEvent } from "@nopass/types";

function makeItem(id: string, version = 1): EncryptedVaultItem {
  return {
    id,
    vaultId: "vault-1",
    userId: "user-1",
    itemType: "login",
    blob: "abc",
    blobIv: "iv",
    blobMac: "mac",
    version,
    deletedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

function makeEvent(
  itemId: string,
  deviceId: string,
  seq: number,
  type: "upsert" | "delete" = "upsert",
): SyncEvent {
  return {
    id: `${deviceId}-${seq}`,
    userId: "user-1",
    deviceId,
    sequenceNumber: seq,
    eventType: type,
    itemId,
    encryptedDelta: null,
    deltaIv: null,
    createdAt: new Date().toISOString(),
  };
}

describe("applySyncEvents", () => {
  it("updates vector clock from events", () => {
    const events = [
      makeEvent("item-1", "device-a", 5),
      makeEvent("item-2", "device-b", 3),
    ];
    const { newClock } = applySyncEvents([], events, {});
    expect(newClock["device-a"]).toBe(5);
    expect(newClock["device-b"]).toBe(3);
  });

  it("tombstone from delete event wins over upsert at same seq", () => {
    const local = [makeItem("item-1")];
    const events = [
      makeEvent("item-1", "device-a", 1, "upsert"),
      makeEvent("item-1", "device-b", 1, "delete"),
    ];
    const { items } = applySyncEvents(local, events, {});
    const item = items.find((i) => i.id === "item-1")!;
    expect(item.deletedAt).not.toBeNull();
  });

  it("higher sequence wins", () => {
    const local = [makeItem("item-1")];
    const deleteEvent = makeEvent("item-1", "device-a", 10, "delete");
    const upsertEvent = makeEvent("item-1", "device-b", 5, "upsert");
    const { items } = applySyncEvents(local, [deleteEvent, upsertEvent], {});
    // delete at seq 10 should win over upsert at seq 5
    const item = items.find((i) => i.id === "item-1")!;
    expect(item.deletedAt).not.toBeNull();
  });

  it("keeps existing clock values when new events are lower", () => {
    const { newClock } = applySyncEvents(
      [],
      [makeEvent("x", "device-a", 3)],
      { "device-a": 10 },
    );
    expect(newClock["device-a"]).toBe(10); // kept higher existing value
  });
});

describe("buildSyncCheckpoints", () => {
  it("converts clock to checkpoints array", () => {
    const checkpoints = buildSyncCheckpoints({ "device-a": 5, "device-b": 3 });
    expect(checkpoints).toHaveLength(2);
    expect(checkpoints).toContainEqual({ deviceId: "device-a", lastSyncedSequence: 5 });
  });
});
