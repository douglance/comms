CREATE TABLE IF NOT EXISTS questions (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  idempotency_key TEXT,
  request_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending_delivery', 'waiting', 'answered', 'expired', 'cancelled')),
  deadline_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  record_json TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_questions_agent_idempotency ON questions(agent_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_questions_agent_status ON questions(agent_id, status, updated_at);
CREATE INDEX IF NOT EXISTS idx_questions_deadline ON questions(status, deadline_at) WHERE deadline_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS question_callbacks (
  callback_id TEXT PRIMARY KEY,
  question_id TEXT NOT NULL REFERENCES questions(id),
  owner_user_id TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_question_callbacks_question ON question_callbacks(question_id, received_at);
