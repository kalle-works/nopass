-- Revoking a device must end its sessions. The original FK was ON DELETE SET
-- NULL, which left the session valid for its full 30 days, merely detached.
-- The new FK is added NOT VALID so it takes only a brief lock; existing rows
-- are checked by a separate VALIDATE (018), which does not block writes. The
-- supporting index is built CONCURRENTLY in 019.
ALTER TABLE sessions DROP CONSTRAINT sessions_device_id_fk;
ALTER TABLE sessions ADD CONSTRAINT sessions_device_id_fk
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE NOT VALID;
