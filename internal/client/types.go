package client

import (
	"encoding/json"
	"time"
)

// Info is the discovery document served at /.well-known/dns-gate.
type Info struct {
	Version  string   `json:"version"`
	Features []string `json:"features"`
}

// HasFeature reports whether the gate advertises a feature.
func (i *Info) HasFeature(f string) bool {
	if i == nil {
		return false
	}
	for _, x := range i.Features {
		if x == f {
			return true
		}
	}
	return false
}

// Zone is one entry of GET /api/v1/zones.
type Zone struct {
	Zone         string     `json:"zone"`
	Provider     string     `json:"provider"`
	Unmanaged    bool       `json:"unmanaged,omitempty"`
	RRsets       int        `json:"rrsets"`
	Managed      int        `json:"managed"`
	Tainted      int        `json:"tainted"`
	Pending      int        `json:"pending"`
	Foreign      int        `json:"foreign"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
	LastWriteAt  *time.Time `json:"last_write_at,omitempty"`
}

// Alias is a provider alias target (Route53 alias records).
type Alias struct {
	Target               string `json:"target"`
	HostedZoneID         string `json:"hosted_zone_id"`
	EvaluateTargetHealth bool   `json:"evaluate_target_health"`
}

// RRset statuses.
const (
	StatusManaged = "managed"
	StatusTainted = "tainted"
	StatusPending = "pending"
	StatusForeign = "foreign"
	StatusMissing = "missing"
)

// RRset is one RRset with its ownership, as the gate returns it.
type RRset struct {
	Host      string     `json:"host"`
	Type      string     `json:"type"`
	TTL       int        `json:"ttl"`
	Values    []string   `json:"values"`
	Alias     *Alias     `json:"alias,omitempty"`
	ReadOnly  string     `json:"read_only,omitempty"`
	Hash      string     `json:"hash"`
	Status    string     `json:"status"`
	Protected bool       `json:"protected"`
	Owner     string     `json:"owner,omitempty"`
	CreatedBy *Actor     `json:"created_by,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedBy *Actor     `json:"updated_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Adopted   bool       `json:"adopted"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Actor is who did something. It decodes both the object form
// ({"subject","name","category"}) and a plain string.
type Actor struct {
	Subject  string `json:"subject"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// UnmarshalJSON accepts an object or a string.
func (a *Actor) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = Actor{Subject: s, Name: s}
		return nil
	}
	type plain Actor
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*a = Actor(p)
	return nil
}

// Display is the most readable form of the actor.
func (a *Actor) Display() string {
	if a == nil {
		return ""
	}
	if a.Name != "" {
		return a.Name
	}
	return a.Subject
}

// Inventory is GET /api/v1/zones/{zone}/rrsets.
type Inventory struct {
	Zone         string     `json:"zone"`
	Unmanaged    bool       `json:"unmanaged,omitempty"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
	RRsets       []RRset    `json:"rrsets"`
	// ETag is the inventory version ("v<n>").
	ETag string `json:"-"`
}

// Find returns the RRset of host and type, nil if absent.
func (i *Inventory) Find(host, typ string) *RRset {
	for k := range i.RRsets {
		if i.RRsets[k].Host == host && i.RRsets[k].Type == typ {
			return &i.RRsets[k]
		}
	}
	return nil
}

// RRsetBody is the body of PUT /api/v1/zones/{zone}/rrsets/{host}/{type}:
// TTL and values, or an alias.
type RRsetBody struct {
	TTL    int      `json:"ttl,omitempty"`
	Values []string `json:"values,omitempty"`
	Alias  *Alias   `json:"alias,omitempty"`
}

// Condition is the precondition of a write.
type Condition struct {
	// IfNoneMatch sends If-None-Match: * (create only).
	IfNoneMatch bool
	// IfMatch, when set, is the content hash the RRset must still have.
	IfMatch string
}

// Me is GET /api/v1/me.
type Me struct {
	Subject  string   `json:"subject"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Roles    []string `json:"roles"`
	Teams    []string `json:"teams"`
	Groups   []string `json:"groups"`
}
