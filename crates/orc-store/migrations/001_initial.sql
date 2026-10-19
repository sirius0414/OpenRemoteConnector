PRAGMA user_version = 1;
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT OR IGNORE INTO metadata VALUES ('security_sequence', 0);
CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, device_id TEXT NOT NULL, revision INTEGER NOT NULL, status TEXT NOT NULL, expires_at INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS submissions (principal_id TEXT NOT NULL, device_id TEXT NOT NULL, submission_id TEXT NOT NULL, request_digest TEXT NOT NULL, task_id TEXT NOT NULL UNIQUE, body TEXT NOT NULL, PRIMARY KEY(principal_id,device_id,submission_id));
CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, device_id TEXT NOT NULL, grant_id TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, principal_id TEXT, device_id TEXT, task_id TEXT, action TEXT NOT NULL, outcome TEXT NOT NULL);

CREATE INDEX IF NOT EXISTS audit_timestamp ON audit_events(timestamp);
INSERT OR IGNORE INTO metadata SELECT 'audit_bytes',COALESCE(SUM(64+length(CAST(COALESCE(principal_id,'') AS BLOB))+length(CAST(COALESCE(device_id,'') AS BLOB))+length(CAST(COALESCE(task_id,'') AS BLOB))+length(CAST(action AS BLOB))+length(CAST(outcome AS BLOB))),0) FROM audit_events;
CREATE TRIGGER IF NOT EXISTS audit_bytes_insert AFTER INSERT ON audit_events BEGIN UPDATE metadata SET value=value + (64+length(CAST(COALESCE(NEW.principal_id,'') AS BLOB))+length(CAST(COALESCE(NEW.device_id,'') AS BLOB))+length(CAST(COALESCE(NEW.task_id,'') AS BLOB))+length(CAST(NEW.action AS BLOB))+length(CAST(NEW.outcome AS BLOB))) WHERE key='audit_bytes'; END;
CREATE TRIGGER IF NOT EXISTS audit_bytes_delete AFTER DELETE ON audit_events BEGIN UPDATE metadata SET value=value - (64+length(CAST(COALESCE(OLD.principal_id,'') AS BLOB))+length(CAST(COALESCE(OLD.device_id,'') AS BLOB))+length(CAST(COALESCE(OLD.task_id,'') AS BLOB))+length(CAST(OLD.action AS BLOB))+length(CAST(OLD.outcome AS BLOB))) WHERE key='audit_bytes'; END;
