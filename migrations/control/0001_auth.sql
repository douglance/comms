CREATE TABLE IF NOT EXISTS owners (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  device_hash TEXT PRIMARY KEY,
  user_code TEXT UNIQUE NOT NULL,
  expires_at INTEGER NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0,
  consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS invitations (
  token_hash TEXT PRIMARY KEY,
  label TEXT,
  expires_at INTEGER NOT NULL,
  ttl_seconds INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  label TEXT,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS downloads (
  token_hash TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  blob_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
