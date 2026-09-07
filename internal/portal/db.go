package portal

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	_ "modernc.org/sqlite"
	"time"
)

//go:embed schema.sql
var schema string

//go:embed vpn.sql
var vpnSchema string

//go:embed packs.sql
var packsSchema string

//go:embed security.sql
var securitySchema string

type Store struct{ DB *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000"} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{db}, nil
}

// The ordered embedded migrations are the single source of the supported version.
var schemaMigrations = [...]string{schema, vpnSchema, packsSchema, securitySchema}

func (s *Store) Migrate() error {
	ctx := context.Background()
	conn, e := s.DB.Conn(ctx)
	if e != nil {
		return fmt.Errorf("open migration connection: %w", e)
	}
	defer conn.Close()
	// Acquire the write lock BEFORE reading the ledger. Separate processes then
	// observe the preceding migrator's committed version instead of racing DDL.
	if _, e = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return fmt.Errorf("acquire database migration lock: %w", e)
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	if _, e = conn.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY)"); e != nil {
		return e
	}
	var version int
	if e = conn.QueryRowContext(ctx, "SELECT coalesce(max(version),0) FROM migrations").Scan(&version); e != nil {
		return e
	}
	if version > len(schemaMigrations) {
		return fmt.Errorf("database schema %d is newer than supported version %d; restore a matching backup to downgrade", version, len(schemaMigrations))
	}
	if version < 0 {
		return fmt.Errorf("invalid database migration version")
	}
	for i := version; i < len(schemaMigrations); i++ {
		if _, e = conn.ExecContext(ctx, schemaMigrations[i]); e != nil {
			return fmt.Errorf("apply database migration %d: %w", i+1, e)
		}
		if _, e = conn.ExecContext(ctx, "INSERT INTO migrations(version) VALUES(?)", i+1); e != nil {
			return fmt.Errorf("record database migration %d: %w", i+1, e)
		}
	}
	if _, e = conn.ExecContext(ctx, "COMMIT"); e != nil {
		return fmt.Errorf("commit database migrations: %w", e)
	}
	committed = true
	return nil
}

func now() string              { return time.Now().UTC().Format(time.RFC3339) }
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
func audit(tx *sql.Tx, actor int, action, target string) error {
	var who any = actor
	if actor == 0 {
		who = nil
	}
	_, e := tx.Exec("INSERT INTO audit(actor_id,action,target,created) VALUES(?,?,?,?)", who, action, target, now())
	return e
}
func (s *Store) Write(fn func(*sql.Tx) error) error {
	tx, e := s.DB.BeginTx(context.Background(), nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Commit(token string, b []byte, expiry time.Time) error {
	_, e := s.DB.Exec("INSERT INTO sessions(token,data,expiry) VALUES(?,?,?) ON CONFLICT(token) DO UPDATE SET data=excluded.data,expiry=excluded.expiry", token, b, expiry.Unix())
	return e
}
func (s *Store) Find(token string) ([]byte, bool, error) {
	var b []byte
	e := s.DB.QueryRow("SELECT data FROM sessions WHERE token=? AND expiry>?", token, time.Now().Unix()).Scan(&b)
	if e == sql.ErrNoRows {
		return nil, false, nil
	}
	return b, e == nil, e
}
func (s *Store) Delete(token string) error {
	_, e := s.DB.Exec("DELETE FROM sessions WHERE token=?", token)
	return e
}
func idTarget(kind string, id int) string { return fmt.Sprintf("%s:%d", kind, id) }
