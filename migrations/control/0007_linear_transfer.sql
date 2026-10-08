CREATE TABLE linear_oauth_states_transfer (
  state_hash TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES linear_apps(agent_id) ON UPDATE CASCADE,
  client_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
INSERT INTO linear_oauth_states_transfer SELECT * FROM linear_oauth_states;
DROP TABLE linear_oauth_states;
ALTER TABLE linear_oauth_states_transfer RENAME TO linear_oauth_states;

CREATE TABLE linear_events_transfer (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL REFERENCES linear_apps(agent_id) ON UPDATE CASCADE,
  event_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE(agent_id,event_hash)
);
INSERT INTO linear_events_transfer SELECT * FROM linear_events;
DROP TABLE linear_events;
ALTER TABLE linear_events_transfer RENAME TO linear_events;
CREATE INDEX linear_events_agent_cursor ON linear_events(agent_id,sequence);
