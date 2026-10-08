CREATE TABLE IF NOT EXISTS linear_apps (
  agent_id TEXT PRIMARY KEY REFERENCES agents(id),
  profile_name TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL,
  workspace_slug TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  app_user_id TEXT UNIQUE NOT NULL,
  client_id TEXT UNIQUE NOT NULL,
  sealed_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS linear_oauth_states (
  state_hash TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES linear_apps(agent_id),
  client_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS linear_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL REFERENCES linear_apps(agent_id),
  event_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE(agent_id,event_hash)
);
CREATE INDEX IF NOT EXISTS linear_events_agent_cursor ON linear_events(agent_id,sequence);
