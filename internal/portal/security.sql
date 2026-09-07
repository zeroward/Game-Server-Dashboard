ALTER TABLE users ADD COLUMN enrollment_locked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN email_notifications INTEGER NOT NULL DEFAULT 1;
CREATE TABLE account_security(user_id INTEGER PRIMARY KEY REFERENCES users(id), handle BLOB NOT NULL UNIQUE, totp BLOB, last_step INTEGER NOT NULL DEFAULT -1);
CREATE TABLE passkeys(id BLOB PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), rp_id TEXT NOT NULL, credential BLOB NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL, used TEXT);
CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE auth_challenges(id TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id), generation INTEGER NOT NULL, purpose TEXT NOT NULL, payload BLOB, expires TEXT NOT NULL);
CREATE TABLE email_tokens(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), email TEXT NOT NULL, kind TEXT NOT NULL, expires TEXT NOT NULL);
CREATE TABLE mail_settings(id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0, host TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 587, mode TEXT NOT NULL DEFAULT 'starttls', username TEXT NOT NULL DEFAULT '', password BLOB, sender TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT 'Waypoint');
INSERT INTO mail_settings(id) VALUES(1);
CREATE TABLE mail_outbox(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), notification_id INTEGER UNIQUE REFERENCES notifications(id), kind TEXT NOT NULL, recipient TEXT NOT NULL, payload BLOB, token_hash TEXT, state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0, available TEXT NOT NULL, created TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Queued', lease TEXT);
CREATE INDEX mail_pending ON mail_outbox(state,available);
CREATE TRIGGER notification_email AFTER INSERT ON notifications BEGIN
 INSERT INTO mail_outbox(user_id,notification_id,kind,recipient,available,created)
 SELECT u.id,NEW.id,'notification',u.email,NEW.created,NEW.created FROM users u,mail_settings m
 WHERE u.id=NEW.user_id AND u.enabled=1 AND u.email_verified=1 AND u.email_notifications=1 AND m.enabled=1;
END;
DELETE FROM sessions;
UPDATE users SET generation=generation+1;

CREATE TRIGGER account_security_email AFTER UPDATE OF generation ON users
WHEN NEW.generation != OLD.generation BEGIN
 INSERT INTO mail_outbox(user_id,kind,recipient,available,created)
 SELECT NEW.id,'security',NEW.email,strftime('%Y-%m-%dT%H:%M:%SZ','now'),strftime('%Y-%m-%dT%H:%M:%SZ','now') FROM mail_settings
 WHERE enabled=1 AND NEW.enabled=1 AND NEW.email_verified=1;
END;
