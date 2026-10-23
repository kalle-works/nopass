-- Revoking a device must end its sessions. The original FK was ON DELETE SET
-- NULL, which left the session valid for its full 30 days, merely detached.
ALTER TABLE sessions DROP CONSTRAINT sessions_device_id_fk;
ALTER TABLE sessions ADD CONSTRAINT sessions_device_id_fk
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;
CREATE INDEX sessions_device_id ON sessions(device_id);
