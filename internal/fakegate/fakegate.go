// Package fakegate is an in-memory dns-gate implementing the REST contract
// used by the provider: discovery, zones, inventory, per-RRset GET/PUT/DELETE
// with ETag/If-Match/If-None-Match, ownership (foreign, tainted, other
// teams), teams (X-DNS-Gate-Team, GET /api/v1/teams[/{team}]), the
// delegation API, and fault injection. Values are canonicalized
// like the gate's Route53 adapter (github.com/miekg/dns presentation format:
// absolute names, quoted TXT split into 255-byte strings), alias targets are
// lowercased with a trailing dot.
package fakegate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// Options configure the fake.
type Options struct {
	// Token is the only bearer token accepted.
	Token string
	// Teams of the caller; the first one owns the RRsets it creates.
	Teams []string
	// Features of the discovery document. Default: policy-delegation, rrset-api.
	Features []string
	// OldGate answers 404 not_found "unknown API endpoint" on per-RRset
	// routes, like a gate without the RRset API.
	OldGate bool
	// NoTeams behaves like a gate before first-class teams: no default_team
	// in /api/v1/me, X-DNS-Gate-Team ignored, no /api/v1/teams routes.
	NoTeams bool
}

// Fault makes matching requests fail.
type Fault struct {
	Method     string // "" for any
	Path       string // substring of the escaped path, "" for any
	Status     int
	Reason     string
	RetryAfter string
	Times      int // number of requests to fail
	// AfterWrite applies the write before answering the error (a lost answer).
	AfterWrite bool
}

type zone struct {
	provider string
	sets     map[string]*client.RRset // "host/TYPE"
	version  int
}

// Server is the fake gate.
type Server struct {
	*httptest.Server
	Mu       sync.Mutex
	opts     Options
	zones    map[string]*zone
	faults   []*Fault
	Requests map[string]int // "METHOD escaped-path"
	// Writes counts successful PUT/DELETE on RRsets; IfNoneMatch and
	// IfMatch count the preconditions received.
	Writes, IfNoneMatch, IfMatch int
	Policy                       *Policy
	// TeamHeaders counts the X-DNS-Gate-Team values received on writes.
	TeamHeaders map[string]int
	// TeamInfos are the teams of GET /api/v1/teams; nil: the caller's teams
	// as declared teams. Strict is the strict flag of the list.
	TeamInfos []client.TeamInfo
	Strict    bool
}

// New starts a fake gate.
func New(o Options) *Server {
	if o.Features == nil {
		o.Features = []string{client.FeaturePolicyDelegation, "rrset-api"}
	}
	if len(o.Teams) == 0 {
		o.Teams = []string{"team-a"}
	}
	s := &Server{opts: o, zones: map[string]*zone{}, Requests: map[string]int{}, Policy: NewPolicy(), TeamHeaders: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Seed adds a zone and RRsets as they are upstream. Seeded RRsets keep their
// Owner and Status; Status defaults to managed when Owner is set, foreign
// otherwise.
func (s *Server) Seed(zoneName, provider string, sets ...client.RRset) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	z := s.zones[zoneName]
	if z == nil {
		z = &zone{provider: provider, sets: map[string]*client.RRset{}}
		s.zones[zoneName] = z
	}
	for _, rs := range sets {
		rs := rs
		rs.Type = strings.ToUpper(rs.Type)
		rs.Values = canonicalValues(rs.Type, rs.Values)
		rs.Alias = canonicalAlias(rs.Alias)
		if rs.Status == "" {
			rs.Status = client.StatusForeign
			if rs.Owner != "" {
				rs.Status = client.StatusManaged
			}
		}
		rs.Hash = contentHash(rs)
		z.sets[rs.Host+"/"+rs.Type] = &rs
	}
	z.version++
}

// Get returns a copy of an RRset, nil if absent.
func (s *Server) Get(zoneName, host, typ string) *client.RRset {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	z := s.zones[zoneName]
	if z == nil || z.sets[host+"/"+typ] == nil {
		return nil
	}
	c := *z.sets[host+"/"+typ]
	return &c
}

// Mutate changes an RRset in place (drift outside Terraform) and recomputes its hash.
func (s *Server) Mutate(zoneName, host, typ string, f func(*client.RRset)) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	rs := s.zones[zoneName].sets[host+"/"+typ]
	f(rs)
	rs.Values = canonicalValues(rs.Type, rs.Values)
	rs.Alias = canonicalAlias(rs.Alias)
	rs.Hash = contentHash(*rs)
	s.zones[zoneName].version++
}

// Remove deletes an RRset upstream.
func (s *Server) Remove(zoneName, host, typ string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	delete(s.zones[zoneName].sets, host+"/"+typ)
	s.zones[zoneName].version++
}

// Count returns the number of RRsets of a zone.
func (s *Server) Count(zoneName string) int {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if z := s.zones[zoneName]; z != nil {
		return len(z.sets)
	}
	return 0
}

// AddFault queues a fault.
func (s *Server) AddFault(f Fault) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if f.Times == 0 {
		f.Times = 1
	}
	s.faults = append(s.faults, &f)
}

func (s *Server) takeFault(r *http.Request) *Fault {
	for _, f := range s.faults {
		if f.Times > 0 && (f.Method == "" || f.Method == r.Method) && strings.Contains(r.URL.EscapedPath(), f.Path) {
			f.Times--
			return f
		}
	}
	return nil
}

func canonicalValues(typ string, vals []string) []string {
	if len(vals) == 0 {
		return nil
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, canonicalValue(typ, v))
	}
	sort.Strings(out)
	return out
}

func canonicalValue(typ, v string) string {
	vv := strings.TrimSpace(v)
	if (typ == "TXT" || typ == "SPF") && !strings.HasPrefix(vv, `"`) {
		vv = `"` + vv + `"`
	}
	rr, err := dns.NewRR("x.invalid. 300 IN " + typ + " " + vv)
	if err != nil || rr == nil {
		return v
	}
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}

func parses(typ, v string) bool {
	vv := strings.TrimSpace(v)
	if (typ == "TXT" || typ == "SPF") && !strings.HasPrefix(vv, `"`) {
		vv = `"` + vv + `"`
	}
	rr, err := dns.NewRR("x.invalid. 300 IN " + typ + " " + vv)
	return err == nil && rr != nil
}

func canonicalAlias(a *client.Alias) *client.Alias {
	if a == nil {
		return nil
	}
	c := *a
	c.Target = strings.ToLower(strings.TrimSuffix(c.Target, ".")) + "."
	return &c
}

func contentHash(rs client.RRset) string {
	vals := append([]string(nil), rs.Values...)
	if rs.Alias != nil {
		vals = []string{fmt.Sprintf("alias %s %s %t", strings.ToLower(rs.Alias.HostedZoneID),
			strings.TrimSuffix(strings.ToLower(rs.Alias.Target), "."), rs.Alias.EvaluateTargetHealth)}
	}
	sort.Strings(vals)
	h := sha256.New()
	fmt.Fprintf(h, "ttl=%d\n", rs.TTL)
	for _, v := range vals {
		fmt.Fprintf(h, "%d:%s\n", len(v), v)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes a gate error answer.
func Error(w http.ResponseWriter, status int, reason, msg string) {
	writeJSON(w, status, map[string]string{"reason": reason, "message": msg})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.Requests[r.Method+" "+r.URL.EscapedPath()]++

	if r.URL.Path == client.InfoPath {
		writeJSON(w, http.StatusOK, client.Info{Version: "0.0.0-fake", Features: s.opts.Features})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.opts.Token {
		Error(w, http.StatusUnauthorized, "unauthenticated", "missing or invalid token")
		return
	}
	var fault *Fault
	if f := s.takeFault(r); f != nil {
		if !f.AfterWrite {
			if f.RetryAfter != "" {
				w.Header().Set("Retry-After", f.RetryAfter)
			}
			Error(w, f.Status, f.Reason, "injected fault")
			return
		}
		fault = f
	}
	if fault != nil {
		w = &swallow{ResponseWriter: w, fault: fault}
	}
	defer func() {
		if sw, ok := w.(*swallow); ok {
			sw.flush()
		}
	}()

	if team := r.Header.Get(client.TeamHeader); team != "" && !s.opts.NoTeams && r.URL.Path != "/api/v1/me" && !contains(s.opts.Teams, team) {
		Error(w, http.StatusForbidden, client.ReasonNotTeamMember, "team "+team+" is not one of your teams")
		return
	}
	switch p := r.URL.Path; {
	case p == "/api/v1/me":
		me := client.Me{Subject: "fake:terraform", Name: "terraform", Category: "pipeline", Teams: s.opts.Teams}
		if !s.opts.NoTeams {
			me.DefaultTeam = s.opts.Teams[0]
		}
		writeJSON(w, http.StatusOK, me)
	case (p == "/api/v1/teams" || strings.HasPrefix(p, "/api/v1/teams/")) && !s.opts.NoTeams && r.Method == http.MethodGet:
		s.teams(w, strings.TrimPrefix(strings.TrimPrefix(p, "/api/v1/teams"), "/"))
	case p == "/api/v1/zones":
		s.listZones(w)
	case strings.HasPrefix(p, client.DelegatedPath+"/"):
		s.Policy.serve(w, r)
	case strings.HasPrefix(p, "/api/v1/zones/"):
		s.zoneRoutes(w, r)
	default:
		Error(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	}
}

// swallow applies a write, then replaces its answer with the fault.
type swallow struct {
	http.ResponseWriter
	fault  *Fault
	status int
}

func (s *swallow) WriteHeader(code int) { s.status = code }
func (s *swallow) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return len(b), nil
}
func (s *swallow) flush() {
	Error(s.ResponseWriter, s.fault.Status, s.fault.Reason, "injected fault after write")
}

func (s *Server) listZones(w http.ResponseWriter) {
	names := make([]string, 0, len(s.zones))
	for n := range s.zones {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []client.Zone{}
	for _, n := range names {
		z := s.zones[n]
		zs := client.Zone{Zone: n, Provider: z.provider, RRsets: len(z.sets)}
		for _, rs := range z.sets {
			switch rs.Status {
			case client.StatusManaged:
				zs.Managed++
			case client.StatusTainted:
				zs.Tainted++
			case client.StatusForeign:
				zs.Foreign++
			case client.StatusPending:
				zs.Pending++
			}
		}
		out = append(out, zs)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) zoneRoutes(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/zones/"), "/")
	for i := range parts {
		u, err := url.PathUnescape(parts[i])
		if err != nil {
			Error(w, http.StatusBadRequest, "invalid", "bad path")
			return
		}
		parts[i] = u
	}
	z := s.zones[parts[0]]
	switch {
	case len(parts) == 2 && parts[1] == "rrsets" && r.Method == http.MethodGet:
		if z == nil {
			Error(w, http.StatusNotFound, "not_found", "no zone "+parts[0])
			return
		}
		inv := client.Inventory{Zone: parts[0], RRsets: []client.RRset{}}
		for _, rs := range z.sets {
			inv.RRsets = append(inv.RRsets, *rs)
		}
		sort.Slice(inv.RRsets, func(i, j int) bool {
			a, b := inv.RRsets[i], inv.RRsets[j]
			return a.Host < b.Host || a.Host == b.Host && a.Type < b.Type
		})
		w.Header().Set("ETag", fmt.Sprintf(`"v%d"`, z.version))
		writeJSON(w, http.StatusOK, inv)
	case len(parts) == 4 && parts[1] == "rrsets" && !s.opts.OldGate:
		if z == nil {
			Error(w, http.StatusNotFound, "not_found", "no zone "+parts[0])
			return
		}
		s.rrset(w, r, z, parts[2], strings.ToUpper(parts[3]))
	default:
		Error(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	}
}

func etagMatches(header, hash string) bool {
	for _, v := range strings.Split(header, ",") {
		v = strings.TrimPrefix(strings.TrimSpace(v), "W/")
		if v == "*" {
			return true
		}
		if u, err := strconv.Unquote(v); err == nil && u == hash {
			return true
		}
	}
	return false
}

func (s *Server) rrset(w http.ResponseWriter, r *http.Request, z *zone, host, typ string) {
	key := host + "/" + typ
	cur := z.sets[key]
	team, acting := s.opts.Teams[0], s.opts.Teams
	if h := r.Header.Get(client.TeamHeader); h != "" && r.Method != http.MethodGet {
		s.TeamHeaders[h]++
		if !s.opts.NoTeams {
			team, acting = h, []string{h}
		}
	}
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			Error(w, http.StatusNotFound, "not_found", "no RRset "+key)
			return
		}
		w.Header().Set("ETag", strconv.Quote(cur.Hash))
		writeJSON(w, http.StatusOK, cur)
		return
	case http.MethodPut, http.MethodDelete:
	default:
		Error(w, http.StatusMethodNotAllowed, "method_not_allowed", r.Method)
		return
	}

	if inm := r.Header.Get("If-None-Match"); inm != "" {
		s.IfNoneMatch++
		if strings.TrimSpace(inm) != "*" {
			Error(w, http.StatusBadRequest, "invalid", "only If-None-Match: * is supported")
			return
		}
		if cur != nil {
			Error(w, http.StatusPreconditionFailed, "precondition", key+" already exists")
			return
		}
	}
	if im := r.Header.Get("If-Match"); im != "" {
		if cur == nil || !etagMatches(im, cur.Hash) {
			Error(w, http.StatusPreconditionFailed, "precondition", key+" changed since it was read")
			return
		}
		s.IfMatch++
	}
	if cur != nil {
		switch {
		case cur.Status == client.StatusForeign:
			Error(w, http.StatusConflict, "foreign_rrset", key+" was not created or adopted through the gate")
			return
		case cur.Status == client.StatusTainted:
			Error(w, http.StatusConflict, "tainted", key+" was modified outside the gate")
			return
		case cur.Protected:
			Error(w, http.StatusForbidden, "forbidden", key+" is protected")
			return
		case !contains(acting, cur.Owner):
			Error(w, http.StatusForbidden, "not_owner", key+" is owned by team "+cur.Owner)
			return
		}
	}

	if r.Method == http.MethodDelete {
		if cur == nil {
			Error(w, http.StatusNotFound, "not_found", "no RRset "+key)
			return
		}
		delete(z.sets, key)
		z.version++
		s.Writes++
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var body client.RRsetBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	switch {
	case body.Alias != nil && (len(body.Values) > 0 || body.TTL != 0):
		Error(w, http.StatusBadRequest, "invalid", "alias excludes ttl and values")
		return
	case body.Alias == nil && (len(body.Values) == 0 || body.TTL <= 0):
		Error(w, http.StatusBadRequest, "invalid", "ttl and values are required")
		return
	}
	for _, v := range body.Values {
		if !parses(typ, v) {
			Error(w, http.StatusBadRequest, "invalid", fmt.Sprintf("invalid %s value %q", typ, v))
			return
		}
	}
	now := time.Now().UTC()
	actor := &client.Actor{Subject: "fake:terraform", Name: "terraform", Category: "pipeline"}
	next := client.RRset{Host: host, Type: typ, TTL: body.TTL, Values: canonicalValues(typ, body.Values),
		Alias: canonicalAlias(body.Alias), Status: client.StatusManaged, Owner: team, CreatedBy: actor, CreatedAt: &now,
		UpdatedBy: actor, UpdatedAt: &now}
	if cur != nil {
		next.Owner, next.CreatedBy, next.CreatedAt, next.Adopted = cur.Owner, cur.CreatedBy, cur.CreatedAt, cur.Adopted
	}
	next.Hash = contentHash(next)
	z.sets[key] = &next
	z.version++
	s.Writes++
	w.Header().Set("ETag", strconv.Quote(next.Hash))
	writeJSON(w, http.StatusOK, next)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// teams serves GET /api/v1/teams and GET /api/v1/teams/{team}.
func (s *Server) teams(w http.ResponseWriter, name string) {
	infos := s.TeamInfos
	if infos == nil {
		for _, t := range s.opts.Teams {
			infos = append(infos, client.TeamInfo{Name: t, Kind: client.TeamKindDeclared, Layer: "base", Roles: []string{"writer"}})
		}
	}
	owned := map[string][]client.TeamZone{}
	names := make([]string, 0, len(s.zones))
	for n := range s.zones {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		count := map[string]int{}
		for _, rs := range s.zones[n].sets {
			if rs.Owner != "" {
				count[rs.Owner]++
			}
		}
		for t, c := range count {
			owned[t] = append(owned[t], client.TeamZone{Zone: n, RRsets: c})
		}
	}
	known := map[string]bool{}
	for _, t := range infos {
		known[t.Name] = true
	}
	owners := make([]string, 0, len(owned))
	for t := range owned {
		if !known[t] {
			owners = append(owners, t)
		}
	}
	sort.Strings(owners)
	for _, t := range owners {
		infos = append(infos, client.TeamInfo{Name: t, Kind: client.TeamKindStore, Roles: []string{}})
	}
	if name == "" {
		writeJSON(w, http.StatusOK, client.TeamList{Strict: s.Strict, Teams: infos})
		return
	}
	for _, t := range infos {
		if t.Name == name {
			d := client.TeamDetail{TeamInfo: t, Owned: owned[name], Transfers: []client.Transfer{}}
			if d.Owned == nil {
				d.Owned = []client.TeamZone{}
			}
			writeJSON(w, http.StatusOK, d)
			return
		}
	}
	Error(w, http.StatusNotFound, "not_found", "unknown team "+name)
}
