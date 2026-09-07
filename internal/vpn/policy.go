// Package vpn defines the deliberately small portal/gateway protocol.
package vpn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Rule struct {
	ID       int    `json:"id"`
	CIDR     string `json:"cidr"`
	Protocol string `json:"protocol"`
	Ports    string `json:"ports"`
	Expires  string `json:"expires"`
}
type Peer struct {
	ID        int    `json:"id"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	Rules     []Rule `json:"rules"`
}
type Snapshot struct {
	Revision string `json:"revision"`
	Peers    []Peer `json:"peers"`
}
type Ack struct {
	Revision  string `json:"revision"`
	PublicKey string `json:"public_key"`
}

const Pool = "10.77.0.0/24"
const Server = "10.77.0.1/24"

func Key(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && s == base64.StdEncoding.EncodeToString(b) && s != strings.Repeat("A", 43)+"="
}
func Endpoint(s string) bool {
	h, p, e := net.SplitHostPort(s)
	n, err := strconv.Atoi(p)
	if e != nil || err != nil || n < 1 || n > 65535 || h == "" {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:", c)) {
			return false
		}
	}
	return true
}
func Destination(cidr, protocol, ports string) error {
	p, e := netip.ParsePrefix(cidr)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
		return fmt.Errorf("use a canonical IPv4 network or host /32; default routes are forbidden")
	}
	for _, reserved := range []string{Pool, "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"} {
		q := netip.MustParsePrefix(reserved)
		if p.Overlaps(q) {
			return fmt.Errorf("destination overlaps a reserved or VPN network")
		}
	}
	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("choose TCP or UDP")
	}
	parts := strings.Split(ports, ",")
	if len(parts) > 32 {
		return fmt.Errorf("at most 32 ports or ranges")
	}
	for _, part := range parts {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return fmt.Errorf("invalid port range")
		}
		last := 0
		for _, s := range bounds {
			n, e := strconv.Atoi(s)
			if e != nil || n < 1 || n > 65535 || n < last || strconv.Itoa(n) != s {
				return fmt.Errorf("use comma-separated ports or ascending ranges, without spaces")
			}
			last = n
		}
	}
	return nil
}
func (s Snapshot) Hash() string {
	s.Revision = ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s Snapshot) Validate() error {
	if s.Revision != s.Hash() || len(s.Peers) > 253 {
		return fmt.Errorf("invalid policy revision or peer count")
	}
	keys := map[string]bool{}
	addresses := map[string]bool{}
	ids := map[int]bool{}
	rules := map[int]bool{}
	total := 0
	for _, p := range s.Peers {
		addr, e := netip.ParsePrefix(p.Address)
		if e != nil || addr.Bits() != 32 || !netip.MustParsePrefix(Pool).Contains(addr.Addr()) || addr.Addr() == netip.MustParseAddr("10.77.0.1") || addr.Addr() == netip.MustParseAddr("10.77.0.0") || addr.Addr() == netip.MustParseAddr("10.77.0.255") || !Key(p.PublicKey) || keys[p.PublicKey] || addresses[p.Address] || p.ID < 1 || ids[p.ID] {
			return fmt.Errorf("invalid or duplicate peer")
		}
		keys[p.PublicKey] = true
		addresses[p.Address] = true
		ids[p.ID] = true
		for _, r := range p.Rules {
			total++
			if total > 1024 || r.ID < 1 || rules[r.ID] {
				return fmt.Errorf("invalid rule count or identifier")
			}
			rules[r.ID] = true
			if e := Destination(r.CIDR, r.Protocol, r.Ports); e != nil {
				return e
			}
			t, e := time.Parse(time.RFC3339, r.Expires)
			if e != nil || t.Year() > 9999 {
				return fmt.Errorf("invalid rule expiry")
			}
		}
	}
	return nil
}
func Active(s Snapshot, at time.Time) Snapshot {
	out := Snapshot{}
	for _, p := range s.Peers {
		peer := p
		peer.Rules = nil
		for _, r := range p.Rules {
			t, e := time.Parse(time.RFC3339, r.Expires)
			if e == nil && t.After(at) {
				peer.Rules = append(peer.Rules, r)
			}
		}
		if len(peer.Rules) > 0 {
			out.Peers = append(out.Peers, peer)
		}
	}
	out.Revision = out.Hash()
	return out
}

// Ruleset owns only this gateway namespace. No unconditional established-flow bypass.
// Expiring source/destination sets are evaluated for every packet in BOTH directions.
func Ruleset(s Snapshot, at time.Time) string {
	var b strings.Builder
	b.WriteString("delete table inet waypoint\ntable inet waypoint {\n")
	active := Active(s, at)
	for _, p := range active.Peers {
		for _, r := range p.Rules {
			t, _ := time.Parse(time.RFC3339, r.Expires)
			seconds := int64(t.Sub(at).Seconds())
			if seconds < 1 {
				continue
			}
			if seconds > 31536000 {
				seconds = 31536000
			}
			fmt.Fprintf(&b, "set g%d { type ipv4_addr; flags timeout; elements = { %s timeout %ds }; }\n", r.ID, strings.TrimSuffix(p.Address, "/32"), seconds)
		}
	}
	b.WriteString("chain input { type filter hook input priority -10; policy accept; iifname \"wg0\" drop; }\nchain forward { type filter hook forward priority -10; policy drop; meta nfproto ipv6 drop; ct state invalid drop;\n")
	for _, p := range active.Peers {
		for _, r := range p.Rules {
			t, _ := time.Parse(time.RFC3339, r.Expires)
			if int64(t.Sub(at).Seconds()) < 1 {
				continue
			}
			fmt.Fprintf(&b, "iifname \"wg0\" oifname \"eth0\" ip saddr @g%d ip daddr %s %s dport { %s } accept\n", r.ID, r.CIDR, r.Protocol, r.Ports)
			fmt.Fprintf(&b, "iifname \"eth0\" oifname \"wg0\" ip daddr @g%d ip saddr %s %s sport { %s } ct state established accept\n", r.ID, r.CIDR, r.Protocol, r.Ports)
		}
	}
	b.WriteString("}\nchain nat { type nat hook postrouting priority srcnat; policy accept; oifname \"eth0\" ip saddr " + Pool + " masquerade; }\n}\n")
	return b.String()
}
func Routes(p Peer) string {
	m := map[string]bool{}
	for _, r := range p.Rules {
		m[r.CIDR] = true
	}
	var v []string
	for s := range m {
		v = append(v, s)
	}
	sort.Strings(v)
	return strings.Join(v, ", ")
}
