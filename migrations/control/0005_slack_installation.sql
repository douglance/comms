CREATE TABLE IF NOT EXISTS slack_oauth_states (state_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS slack_installations (team_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, sealed_json TEXT NOT NULL, updated_at INTEGER NOT NULL);
