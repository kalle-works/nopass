-- Check existing rows against the constraints added NOT VALID in 014, 015 and
-- 017. VALIDATE takes only SHARE UPDATE EXCLUSIVE, so reads and writes continue.
ALTER TABLE sessions VALIDATE CONSTRAINT sessions_device_id_fk;
ALTER TABLE users VALIDATE CONSTRAINT users_srp_pair;
ALTER TABLE users VALIDATE CONSTRAINT users_has_credential;
ALTER TABLE users VALIDATE CONSTRAINT users_account_key_pair;
