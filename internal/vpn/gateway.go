package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner never accepts shell fragments; generated configs go through stdin or private files.
type Runner func(context.Context, string, []string, []byte) ([]byte, error)

func Exec(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = bytes.NewReader(input)
	out, e := c.Output()
	if e != nil {
		return nil, fmt.Errorf("%s failed", name)
	}
	return out, nil
}

type Gateway struct {
	Dir, ControlDir string
	Port            int
	Run             Runner
	Client          *http.Client
	PublicKey       string
	desired         Snapshot
	applied         string
	appliedUntil    time.Time
	hasPolicy       bool
}

func (g *Gateway) command(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return g.Run(call, name, args, input)
}
func atomicFile(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (g *Gateway) deny(ctx context.Context) error {
	_, e := g.command(ctx, "nft", []string{"-f", "-"}, []byte(Ruleset(Snapshot{}, time.Now())))
	g.applied = ""
	return e
}
func (g *Gateway) Init(ctx context.Context) error {
	if g.Run == nil {
		g.Run = Exec
	}
	if g.Port < 1 || g.Port > 65535 {
		return errors.New("invalid WireGuard port")
	}
	if e := os.MkdirAll(g.Dir, 0700); e != nil {
		return e
	}
	if _, e := g.command(ctx, "nft", []string{"list", "table", "inet", "waypoint"}, nil); e != nil {
		if _, e = g.command(ctx, "nft", []string{"add", "table", "inet", "waypoint"}, nil); e != nil {
			return e
		}
	}
	if e := g.deny(ctx); e != nil {
		return e
	}
	keyPath := filepath.Join(g.Dir, "server.key")
	private, e := os.ReadFile(keyPath)
	if os.IsNotExist(e) {
		private, e = g.command(ctx, "wg", []string{"genkey"}, nil)
		if e == nil {
			e = atomicFile(keyPath, private)
		}
	}
	if e != nil {
		return e
	}
	pub, e := g.command(ctx, "wg", []string{"pubkey"}, private)
	if e != nil {
		return e
	}
	g.PublicKey = strings.TrimSpace(string(pub))
	if !Key(g.PublicKey) {
		return errors.New("invalid gateway public key")
	}
	if _, e = g.command(ctx, "ip", []string{"link", "show", "dev", "wg0"}, nil); e != nil {
		if _, e = g.command(ctx, "ip", []string{"link", "add", "dev", "wg0", "type", "wireguard"}, nil); e != nil {
			return e
		}
	}
	for _, args := range [][]string{{"address", "replace", Server, "dev", "wg0"}, {"link", "set", "dev", "wg0", "mtu", "1280", "up"}} {
		if _, e = g.command(ctx, "ip", args, nil); e != nil {
			return e
		}
	}
	if g.Client == nil {
		g.Client = &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(g.ControlDir, "control.sock"))
		}}}
	}
	saved, e := os.ReadFile(filepath.Join(g.Dir, "policy.json"))
	if e == nil {
		if e = json.Unmarshal(saved, &g.desired); e != nil {
			return errors.New("invalid saved gateway policy; forwarding remains blocked")
		}
		if e = g.desired.Validate(); e != nil {
			return e
		}
		g.hasPolicy = true
		return g.Apply(ctx)
	}
	if !os.IsNotExist(e) {
		return e
	}
	return nil
}
func (g *Gateway) Apply(ctx context.Context) error {
	if !g.hasPolicy {
		return g.deny(ctx)
	}
	if e := g.desired.Validate(); e != nil {
		return e
	}
	// Persist intent BEFORE enabling anything. A restart can never resurrect a policy
	// superseded by a received revocation, even if a later kernel operation fails.
	b, _ := json.Marshal(g.desired)
	if e := atomicFile(filepath.Join(g.Dir, "policy.json"), b); e != nil {
		_ = g.deny(ctx)
		return e
	}
	if e := g.deny(ctx); e != nil {
		return e
	}
	active := Active(g.desired, time.Now())
	key, e := os.ReadFile(filepath.Join(g.Dir, "server.key"))
	if e != nil {
		return e
	}
	var conf strings.Builder
	fmt.Fprintf(&conf, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", strings.TrimSpace(string(key)), g.Port)
	for _, p := range active.Peers {
		fmt.Fprintf(&conf, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", p.PublicKey, p.Address)
	}
	config := filepath.Join(g.Dir, "apply.conf")
	if e = atomicFile(config, []byte(conf.String())); e != nil {
		return e
	}
	defer os.Remove(config)
	if _, e = g.command(ctx, "wg", []string{"syncconf", "wg0", config}, nil); e != nil {
		return e
	}
	at := time.Now()
	if _, e = g.command(ctx, "nft", []string{"-f", "-"}, []byte(Ruleset(active, at))); e != nil {
		return e
	}
	g.applied = g.desired.Revision
	g.appliedUntil = time.Time{}
	for _, p := range active.Peers {
		for _, r := range p.Rules {
			t, _ := time.Parse(time.RFC3339, r.Expires)
			if g.appliedUntil.IsZero() || t.Before(g.appliedUntil) {
				g.appliedUntil = t
			}
		}
	}
	return nil
}
func (g *Gateway) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	token, e := os.ReadFile(filepath.Join(g.ControlDir, "token"))
	if e != nil {
		return nil, e
	}
	if len(token) != 64 {
		return nil, errors.New("invalid control token")
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://control"+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/json")
	return g.Client.Do(req)
}

// Tick also removes expired peers while disconnected. nftables timeouts enforce
// packet expiry independently if this process crashes or stops being scheduled.
func (g *Gateway) Tick(ctx context.Context) error {
	if g.hasPolicy && (g.applied == "" || !g.appliedUntil.IsZero() && !time.Now().Before(g.appliedUntil)) {
		if e := g.Apply(ctx); e != nil {
			return e
		}
	}
	resp, e := g.request(ctx, "GET", "/v1/policy", nil)
	if e != nil {
		return errors.New("portal unavailable; existing policy retains its expiry")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("portal did not provide a policy")
	}
	var next Snapshot
	dec := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&next); e != nil {
		return errors.New("invalid policy response")
	}
	if e = next.Validate(); e != nil {
		return e
	}
	if !g.hasPolicy || next.Revision != g.applied {
		g.desired = next
		g.hasPolicy = true
		if e = g.Apply(ctx); e != nil {
			return e
		}
	}
	ack, _ := json.Marshal(Ack{Revision: g.applied, PublicKey: g.PublicKey})
	res, e := g.request(ctx, "POST", "/v1/applied", ack)
	if e != nil {
		return errors.New("gateway applied policy; acknowledgment pending")
	}
	defer res.Body.Close()
	if res.StatusCode != 204 {
		return errors.New("gateway acknowledgment rejected")
	}
	return nil
}
