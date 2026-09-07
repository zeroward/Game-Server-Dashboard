//go:build e2e

// A disposable browser-test fixture. This command is excluded from production builds.
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"waypoint/internal/portal"
	"waypoint/web"
)

func main() {
	dir := os.Getenv("E2E_DATA_DIR")
	password := os.Getenv("E2E_PASSWORD")
	if dir == "" || password == "" {
		log.Fatal("browser test environment is required")
	}
	os.MkdirAll(filepath.Join(dir, "uploads"), 0700)
	s, e := portal.Open(filepath.Join(dir, "waypoint.db"))
	if e != nil {
		log.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Migrate(); e != nil {
		log.Fatal(e)
	}
	if e = s.CreateAdmin("test-owner", password); e != nil {
		log.Fatal(e)
	}
	if e = s.SeedDemo(); e != nil {
		log.Fatal(e)
	}
	a, e := portal.New(s, portal.Config{VPNEnabled: true, VPNDeliveryDir: filepath.Join(dir, "delivery"), VPNEndpoint: "vpn.example.invalid:51820", DataDir: dir, BaseURL: "http://127.0.0.1:8088"}, web.Assets)
	if e != nil {
		log.Fatal(e)
	}
	// Test-only acknowledgment simulator for browser UI. Actual WireGuard application
	// is verified separately by container-smoke.py --vpn and vpn-network.py.
	go func() {
		for range time.Tick(100 * time.Millisecond) {
			snapshot, e := s.VPNSnapshot()
			if e != nil {
				continue
			}
			s.Write(func(tx *sql.Tx) error {
				_, e := tx.Exec("UPDATE vpn_status SET revision=?,public_key=?,seen=? WHERE id=1", snapshot.Revision, "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=", time.Now().UTC().Format(time.RFC3339))
				return e
			})
		}
	}()
	log.Fatal(http.ListenAndServe("127.0.0.1:8088", a.Handler()))
}
