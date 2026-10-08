CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY,
  root_id TEXT NOT NULL,
  parent_id TEXT,
  secret_hash TEXT UNIQUE NOT NULL,
  label TEXT,
  profile_name TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoked_by TEXT
);
CREATE INDEX IF NOT EXISTS enrollments_root_idx ON enrollments(root_id);
CREATE INDEX IF NOT EXISTS enrollments_active_secret_idx ON enrollments(secret_hash, expires_at, revoked_at);
ALTER TABLE agents ADD COLUMN enrollment_id TEXT;
ALTER TABLE agents ADD COLUMN root_enrollment_id TEXT;
ALTER TABLE agents ADD COLUMN profile_name TEXT;
ALTER TABLE agents ADD COLUMN renewal_hash TEXT;
ALTER TABLE agents ADD COLUMN renewal_expires_at INTEGER;
CREATE INDEX IF NOT EXISTS agents_root_enrollment_idx ON agents(root_enrollment_id);
CREATE INDEX IF NOT EXISTS agents_renewal_idx ON agents(id, renewal_hash, renewal_expires_at, revoked_at);
