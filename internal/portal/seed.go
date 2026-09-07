package portal

import (
	"database/sql"
	"encoding/json"
)

func (s *Store) SeedDemo() error {
	return s.Write(func(tx *sql.Tx) error {
		for i, name := range []string{"Games", "Media", "Development", "Utilities"} {
			if _, e := tx.Exec("INSERT OR IGNORE INTO categories(name,position) VALUES(?,?)", name, i); e != nil {
				return e
			}
		}
		type sample struct {
			slug, name, category, mode, details string
			c                                   ServiceConfig
		}
		samples := []sample{
			{"world-of-warcraft", "World of Warcraft", "Games", "external", "member", ServiceConfig{Type: "game", Game: "World of Warcraft", Summary: "A familiar world. A new adventure with friends.", Description: "Our AzerothCore realm. Account creation and realm workflows live in the separately managed WoW portal.\n\n**Demo configuration:** an administrator must configure the deployed Waygate URL.", Tags: "MMORPG, Co-op", FocalX: 50, FocalY: 50, Version: "3.3.5a (demo example)", Guide: "Open the configured WoW portal for account and realm setup. Portal membership does not create a WoW account."}},
			{"plex", "Plex", "Media", "request", "access", ServiceConfig{Type: "application", Summary: "Something good to watch, together or on your own.", Description: "A shared movie and television library. Request library access here; use Seerr for movie and show requests once the administrator configures its link.", Tags: "Movies, TV", FocalX: 50, FocalY: 50, Fields: []Field{{Key: "f0", Label: "Plex account email", Type: "email", Required: true}}, Guide: "Sign into your own Plex account and accept the library invitation sent separately by the administrator. No password is needed in this portal."}},
			{"development-network", "Development Network", "Development", "request", "access", ServiceConfig{Type: "network", Summary: "A little room to build, experiment, and learn.", Description: "Request access to a specific development resource. An administrator will review the intended use and arrange setup externally. Membership does not grant general LAN access.", Tags: "Development, Private", FocalX: 50, FocalY: 50, Fields: []Field{{Key: "f0", Label: "Device name", Type: "short", Required: true}, {Key: "f1", Label: "Intended use", Type: "long", Required: true}}, Duration: true, Guide: "Wait for the administrator's separate enrollment instructions. Do not post VPN configurations, passwords, or private keys here. This service request does not provision network access. If My Devices is enabled, each device needs a separate network approval."}},
			{"campfire", "Campfire", "Games", "info", "member", ServiceConfig{Type: "game", Game: "Generic cooperative game", Summary: "An open seat for the next co-op evening.", Description: "A configurable game-service example. Replace the instructions with those appropriate for your game.\n\n**Demo only:** the connection address is reserved example data.", Tags: "Co-op, Casual", FocalX: 50, FocalY: 50, Host: "game.example.invalid", Port: "25565", Version: "Demo version", Connection: "game.example.invalid:25565", Guide: "1. Install the administrator-specified client and version.\n2. Use the configured connection address in that client's multiplayer menu.\n3. If connection fails, consult the status board or create a support request.\n\nThese are example instructions, not a performed diagnostic."}},
		}
		for i, d := range samples {
			var cat int
			tx.QueryRow("SELECT id FROM categories WHERE name=?", d.category).Scan(&cat)
			b, _ := json.Marshal(d.c)
			if _, e := tx.Exec("INSERT OR IGNORE INTO services(slug,name,category_id,published,audience,details_audience,mode,position,featured,config) VALUES(?,?,?,1,'member',?,?,?,?,?)", d.slug, d.name, cat, d.details, d.mode, i, i == 0, string(b)); e != nil {
				return e
			}
		}
		links := []struct{ label, slug, audience, style string }{{"Open WoW Portal", "world-of-warcraft", "member", "primary"}, {"Open Plex", "plex", "access", "primary"}, {"Request Movies & Shows", "plex", "access", "secondary"}}
		for _, l := range links {
			var sid int
			tx.QueryRow("SELECT id FROM services WHERE slug=?", l.slug).Scan(&sid)
			if _, e := tx.Exec("INSERT INTO links(label,url,placement,parent_id,access_service,audience,style,enabled) SELECT ?,'','service',?,?,?,?,0 WHERE NOT EXISTS(SELECT 1 FROM links WHERE label=? AND placement='service' AND parent_id=?)", l.label, sid, sid, l.audience, l.style, l.label, sid); e != nil {
				return e
			}
		}
		if _, e := tx.Exec("INSERT INTO links(label,url,placement,audience,enabled,icon) SELECT 'Status','','global','member',0,'status' WHERE NOT EXISTS(SELECT 1 FROM links WHERE label='Status' AND placement='global')"); e != nil {
			return e
		}
		return audit(tx, 0, "opt-in demo seed", "catalog")
	})
}
