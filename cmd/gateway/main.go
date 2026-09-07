// gateway is an opt-in WireGuard gateway. It must run in its own network namespace.
package main

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"waypoint/internal/vpn"
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
	dir := env("GATEWAY_DATA_DIR", "/gateway")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fmt.Errorf("another gateway agent owns this storage")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	port, e := strconv.Atoi(env("WG_PORT", "51820"))
	if e != nil {
		return e
	}
	g := vpn.Gateway{Dir: dir, ControlDir: env("VPN_CONTROL_DIR", "/control"), Port: port}
	if e = g.Init(ctx); e != nil {
		return e
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastError := ""
	for {
		if e = g.Tick(ctx); e != nil {
			if e.Error() != lastError {
				log.Print(e)
				lastError = e.Error()
			}
		} else if lastError != "" {
			log.Print("Gateway policy synchronized")
			lastError = ""
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
