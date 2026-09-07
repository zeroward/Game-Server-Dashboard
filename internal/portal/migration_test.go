package portal

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func migrationStore(t *testing.T, path string) *Store {
	t.Helper()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}
func TestMigrationConcurrentConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup.db")
	a := migrationStore(t, path)
	b := migrationStore(t, path)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, s := range []*Store{a, b} {
		wg.Add(1)
		go func(s *Store) { defer wg.Done(); results <- s.Migrate() }(s)
	}
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Fatal(e)
		}
	}
	if count(t, a, "SELECT count(*) FROM migrations") != len(schemaMigrations) {
		t.Fatal("duplicate or missing migrations")
	}
	if e := a.CreateAdmin("persisted-owner", "a long migration test password"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if e := b.Migrate(); e != nil {
			t.Fatal(e)
		}
	}
	if count(t, a, "SELECT count(*) FROM users WHERE username='persisted-owner'") != 1 {
		t.Fatal("restart reset membership")
	}
}
func TestMigrationRollbackPreservesOldDatabase(t *testing.T) {
	s := migrationStore(t, filepath.Join(t.TempDir(), "old.db"))
	if e := s.Write(func(tx *sql.Tx) error {
		for _, q := range []string{schema, "CREATE TABLE migrations(version INTEGER PRIMARY KEY)", "INSERT INTO migrations VALUES(1)", "CREATE TABLE vpn_grants(legacy TEXT)", "INSERT INTO vpn_grants VALUES('keep existing content')"} {
			if _, e := tx.Exec(q); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.CreateAdmin("old-owner", "a long migration test password"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(); e == nil || !strings.Contains(e.Error(), "migration 2") {
		t.Fatal("expected migration failure", e)
	}
	if count(t, s, "SELECT max(version) FROM migrations") != 1 || count(t, s, "SELECT count(*) FROM sqlite_master WHERE name='vpn_devices'") != 0 {
		t.Fatal("partial schema survived rollback")
	}
	if count(t, s, "SELECT count(*) FROM vpn_grants WHERE legacy='keep existing content'") != 1 || count(t, s, "SELECT count(*) FROM users WHERE username='old-owner'") != 1 {
		t.Fatal("existing data lost")
	}
	if _, e := s.DB.Exec("ALTER TABLE vpn_grants RENAME TO retained_legacy"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(); e != nil {
		t.Fatal("retry after repairing conflict failed", e)
	}
}
func TestMigrationNewerVersionRefused(t *testing.T) {
	s := migrationStore(t, filepath.Join(t.TempDir(), "newer.db"))
	if e := s.Migrate(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("INSERT INTO migrations VALUES(?)", len(schemaMigrations)+1); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(); e == nil || !strings.Contains(e.Error(), "newer") {
		t.Fatal("newer database accepted", e)
	}
	if count(t, s, "SELECT max(version) FROM migrations") != len(schemaMigrations)+1 {
		t.Fatal("newer ledger changed")
	}
}
func TestMigrationLockTimeoutAndRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.db")
	a := migrationStore(t, path)
	b := migrationStore(t, path)
	if e := a.Migrate(); e != nil {
		t.Fatal(e)
	}
	if _, e := b.DB.Exec("PRAGMA busy_timeout=50"); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	conn, e := a.DB.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	if e = b.Migrate(); e == nil || !strings.Contains(e.Error(), "migration lock") {
		t.Fatal("lock error missing", e)
	}
	if _, e = conn.ExecContext(ctx, "ROLLBACK"); e != nil {
		t.Fatal(e)
	}
	if e = b.Migrate(); e != nil {
		t.Fatal("lock release retry failed", e)
	}
}
