CREATE TABLE IF NOT EXISTS slack_credentials (
  workspace_id TEXT NOT NULL,
  token_class TEXT NOT NULL,
  encrypted_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, token_class)
);

CREATE TABLE IF NOT EXISTS slack_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  delivery_key TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  method TEXT NOT NULL,
  body TEXT NOT NULL,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  result TEXT,
  error TEXT,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (workspace_id, delivery_key)
);

CREATE TABLE IF NOT EXISTS slack_method_clock (
  workspace_id TEXT NOT NULL,
  method TEXT NOT NULL,
  next_at INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, method)
);

CREATE TABLE IF NOT EXISTS slack_questions (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  thread_ts TEXT,
  prompt TEXT NOT NULL,
  blocks TEXT,
  state TEXT NOT NULL,
  answer TEXT,
  deadline_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
