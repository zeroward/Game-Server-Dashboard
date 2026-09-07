package main

import (
	"context"
	"fmt"
	"golang.org/x/term"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"waypoint/internal/portal"
	"waypoint/web"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		client := http.Client{Timeout: 3 * time.Second}
		resp, e := client.Get("http://127.0.0.1:8080/healthz")
		if e != nil {
			return e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("unhealthy")
		}
		return nil
	}
	data := env("DATA_DIR", "./data")
	if e := os.MkdirAll(filepath.Join(data, "uploads"), 0700); e != nil {
		return e
	}
	s, e := portal.Open(filepath.Join(data, "waypoint.db"))
	if e != nil {
		return e
	}
	defer s.DB.Close()
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "migrate":
		return s.Migrate()
	case "seed-demo":
		return s.SeedDemo()
	case "admin":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: waypoint admin create | admin recover --username NAME")
		}
		action := os.Args[2]
		username := ""
		if action == "recover" {
			if len(os.Args) != 5 || os.Args[3] != "--username" {
				return fmt.Errorf("usage: waypoint admin recover --username NAME")
			}
			username = os.Args[4]
		} else if action == "create" {
			fmt.Print("Administrator username: ")
			fmt.Scanln(&username)
		} else {
			return fmt.Errorf("unknown admin command")
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("bootstrap/recovery requires an interactive terminal; passwords are never accepted as arguments")
		}
		fmt.Print("Password (12+ characters): ")
		password, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if e != nil {
			return e
		}
		fmt.Print("Repeat password: ")
		repeat, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if e != nil {
			return e
		}
		if string(password) != string(repeat) {
			return fmt.Errorf("passwords do not match")
		}
		if action == "create" {
			return s.CreateAdmin(username, string(password))
		}
		fmt.Print("Reset lost passkeys and authenticators too? Type RESET to confirm, or press Enter to keep them: ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm == "RESET" {
			return s.RecoverFactors(username, string(password))
		}
		return s.Recover(username, string(password))
	case "serve":
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	if e = s.Migrate(); e != nil {
		return fmt.Errorf("startup migration failed: %w", e)
	}
	var admins int
	if e = s.DB.QueryRow("SELECT count(*) FROM users WHERE role='admin'").Scan(&admins); e != nil {
		return e
	}
	if admins == 0 {
		log.Print("First-time setup: create your administrator with docker compose exec portal /waypoint admin create (native: waypoint admin create)")
	}
	prod := env("APP_ENV", "development") == "production"
	base := strings.TrimRight(env("BASE_URL", "http://localhost:8080"), "/")
	if prod && !strings.HasPrefix(base, "https://") {
		return fmt.Errorf("production requires an https:// BASE_URL")
	}
	cfg := portal.Config{SecretsDir: os.Getenv("ACCOUNT_SECRETS_DIR"), VPNDeliveryDir: os.Getenv("VPN_DELIVERY_DIR"), VPNEnabled: os.Getenv("VPN_ENABLED") == "true", VPNControlDir: os.Getenv("VPN_CONTROL_DIR"), VPNEndpoint: os.Getenv("VPN_ENDPOINT"), DataDir: data, BaseURL: base, Addr: env("LISTEN_ADDR", "127.0.0.1:8080"), Production: prod, TrustedProxies: strings.Split(os.Getenv("TRUSTED_PROXIES"), ",")}
	app, e := portal.New(s, cfg, web.Assets)
	if e != nil {
		return e
	}
	server := &http.Server{Addr: cfg.Addr, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	app.StartMail(ctx)
	if e = app.StartVPNControl(ctx); e != nil {
		return e
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				server.Shutdown(shutdown)
				return
			case <-ticker.C:
				if e := s.Reconcile(); e != nil {
					log.Print("maintenance task failed")
				}
			}
		}
	}()
	if e = s.Reconcile(); e != nil {
		return e
	}
	log.Printf("Waypoint listening on %s", cfg.Addr)
	e = server.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
