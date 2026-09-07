package vpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample() Snapshot {
	s := Snapshot{Peers: []Peer{{ID: 1, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Address: "10.77.0.2/32", Rules: []Rule{{ID: 1, CIDR: "192.0.2.10/32", Protocol: "tcp", Ports: "443,8000-8002", Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}}}}
	s.Revision = s.Hash()
	return s
}
func TestValidationAndUntrustedPolicy(t *testing.T) {
	for _, v := range [][3]string{{"0.0.0.0/0", "tcp", "443"}, {"127.0.0.1/32", "tcp", "443"}, {"10.77.0.1/32", "tcp", "443"}, {"::/0", "tcp", "443"}, {"192.0.2.2/24", "tcp", "443"}, {"192.0.2.2/32", "tcp", "443; flush ruleset"}, {"192.0.2.2/32", "tcp", "900-100"}, {"192.0.2.2/32", "icmp", "1"}, {"169.254.169.254/32", "tcp", "80"}} {
		if Destination(v[0], v[1], v[2]) == nil {
			t.Errorf("accepted unsafe destination: %v", v)
		}
	}
	s := sample()
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	s.Peers[0].Address = "10.77.0.0/24"
	s.Revision = s.Hash()
	if s.Validate() == nil {
		t.Fatal("accepted spoofable peer subnet")
	}
	s = sample()
	s.Peers = append(s.Peers, s.Peers[0])
	s.Revision = s.Hash()
	if s.Validate() == nil {
		t.Fatal("duplicate peer")
	}
	s = sample()
	s.Peers[0].Rules[0].CIDR = "192.0.2.11/32"
	if s.Validate() == nil {
		t.Fatal("accepted tampered revision")
	}
	if Endpoint("example.invalid:51820\nPostUp=x") || Endpoint("https://host:51820") || !Endpoint("vpn.example.invalid:51820") {
		t.Fatal("endpoint validation")
	}
}
func TestKernelTimeoutAndBothDirections(t *testing.T) {
	s := sample()
	at := time.Now()
	r := Ruleset(s, at)
	for _, need := range []string{"flags timeout", "timeout ", "iifname \"wg0\" oifname \"eth0\" ip saddr @g1 ip daddr 192.0.2.10/32", "ip daddr @g1 ip saddr 192.0.2.10/32", "meta nfproto ipv6 drop", "iifname \"wg0\" drop", "policy drop"} {
		if !strings.Contains(r, need) {
			t.Fatalf("missing restriction %s", need)
		}
	}
	if strings.Contains(r, "ct state established accept;\n") {
		t.Fatal("unconditional established bypass")
	}
	expired := Active(s, at.Add(2*time.Hour))
	if len(expired.Peers) != 0 {
		t.Fatal("expired peer retained")
	}
	if strings.Contains(Ruleset(s, at.Add(2*time.Hour)), "set g1") {
		t.Fatal("expired rule emitted")
	}
}
func TestGatewayOrderingRestartAndFailedApply(t *testing.T) {
	s := sample()
	var calls []string
	failWG := false
	g := Gateway{Dir: t.TempDir(), Port: 51820, Run: func(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+" "+string(input))
		if name == "wg" && args[0] == "pubkey" {
			return []byte(s.Peers[0].PublicKey), nil
		}
		if failWG && name == "wg" && args[0] == "syncconf" {
			return nil, errors.New("failed")
		}
		return nil, nil
	}}
	os.WriteFile(filepath.Join(g.Dir, "server.key"), []byte(s.Peers[0].PublicKey), 0600)
	if e := g.Init(context.Background()); e != nil {
		t.Fatal(e)
	}
	calls = nil
	g.desired = s
	g.hasPolicy = true
	if e := g.Apply(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(calls) != 3 || !strings.HasPrefix(calls[0], "nft") || strings.Contains(calls[0], "set g1") || !strings.HasPrefix(calls[1], "wg syncconf") || !strings.Contains(calls[2], "set g1") {
		t.Fatalf("unsafe apply ordering: %v", calls)
	}
	revoked := Snapshot{}
	revoked.Revision = revoked.Hash()
	g.desired = revoked
	failWG = true
	if g.Apply(context.Background()) == nil || g.applied != "" {
		t.Fatal("failed apply acknowledged")
	}
	b, _ := os.ReadFile(filepath.Join(g.Dir, "policy.json"))
	var saved Snapshot
	json.Unmarshal(b, &saved)
	if saved.Revision != revoked.Revision {
		t.Fatal("revocation not persisted before kernel change")
	}
	failWG = false
	g2 := Gateway{Dir: g.Dir, Port: 51820, Run: g.Run}
	if e := g2.Init(context.Background()); e != nil {
		t.Fatal(e)
	}
	if g2.applied != revoked.Revision {
		t.Fatal("restart resurrected old grant")
	}
}
func TestGatewayOfflineExpiryAndAuthentication(t *testing.T) {
	s := sample()
	dir := t.TempDir()
	token := strings.Repeat("b", 64)
	os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0600)
	var ack Ack
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing authentication")
		}
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(s)
		} else {
			json.NewDecoder(r.Body).Decode(&ack)
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	g := Gateway{Dir: t.TempDir(), ControlDir: dir, Port: 51820, PublicKey: s.Peers[0].PublicKey, Run: func(context.Context, string, []string, []byte) ([]byte, error) { return nil, nil }, Client: &http.Client{Transport: redirectTransport{server.URL}}}
	os.WriteFile(filepath.Join(g.Dir, "server.key"), []byte(s.Peers[0].PublicKey), 0600)
	if e := g.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	if ack.Revision != s.Revision {
		t.Fatal("no applied acknowledgment")
	}
	server.Close()
	g.desired.Peers[0].Rules[0].Expires = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	g.desired.Revision = g.desired.Hash()
	g.appliedUntil = time.Now().Add(-time.Second)
	if g.Tick(context.Background()) == nil {
		t.Fatal("expected offline status")
	}
	if g.appliedUntil != (time.Time{}) {
		t.Fatal("expired peers not reconciled offline")
	}
}

type redirectTransport struct{ base string }

func (t redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(r.Context(), r.Method, t.base+r.URL.Path, r.Body)
	req.Header = r.Header
	return http.DefaultTransport.RoundTrip(req)
}
