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
func (s *Store) Migrate() error {
	return s.Write(func(tx *sql.Tx) error {
		if _, e := tx.Exec("CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY)"); e != nil {
			return e
		}
		var version int
		if e := tx.QueryRow("SELECT coalesce(max(version),0) FROM migrations").Scan(&version); e != nil {
			return e
		}
		if version > 3 {
			return fmt.Errorf("database schema is newer than this binary")
		}
		if version == 0 {
			if _, e := tx.Exec(schema); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT INTO migrations(version) VALUES(1)"); e != nil {
				return e
			}
		}
		if version < 2 {
			if _, e := tx.Exec(vpnSchema); e != nil {
				return e
			}
			if _, e := tx.Exec("INSERT INTO migrations(version) VALUES(2)"); e != nil {
				return e
			}
		}
		if version < 3 {
			if _, e := tx.Exec(packsSchema); e != nil {
				return e
			}
			_, e := tx.Exec("INSERT INTO migrations(version) VALUES(3)")
			return e
		}
		return nil
	})
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
