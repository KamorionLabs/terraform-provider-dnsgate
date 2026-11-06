// Package fakegate is an in-memory dns-gate implementing the REST contract
// used by the provider: discovery, zones, inventory, per-RRset GET/PUT/DELETE
// with ETag/If-Match/If-None-Match, ownership (foreign, tainted, other
// teams), teams (X-DNS-Gate-Team, GET /api/v1/teams[/{team}]), URL
// forwards (/api/v1/zones/{zone}/forwards, stored as RRsets of type URLFWD),
// the delegation API, and fault injection. Values are canonicalized
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
	"unicode"
	"unicode/utf8"
)

// Options configure the fake.
type Options struct {
	// Token is the only bearer token accepted.
	Token string
	// Teams of the caller; the first one owns the RRsets it creates.
	Teams []string
	// Features of the discovery document. Default: policy-delegation,
	// rrset-api, forwards. Without forwards, the forward routes answer like a
	// gate that does not serve them.
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
	// forwards tells whether the DNS provider of the zone has URL forwards;
	// https is the HTTPS status of its forwards.
	forwards bool
	https    string
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
		o.Features = []string{client.FeaturePolicyDelegation, "rrset-api", client.FeatureForwards}
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
// otherwise. A forward is seeded as an RRset of type URLFWD with Forward set.
// A new "eurodns" zone has URL forwards answering plain HTTP only (HTTPS
// inactive); other providers have none (see SetForwards).
func (s *Server) Seed(zoneName, provider string, sets ...client.RRset) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	z := s.zones[zoneName]
	if z == nil {
		z = &zone{provider: provider, sets: map[string]*client.RRset{}, https: client.HTTPSUnsupported}
		if provider == "eurodns" {
			z.forwards, z.https = true, client.HTTPSInactive
		}
		s.zones[zoneName] = z
	}
	for _, rs := range sets {
		rs := rs
		rs.Type = strings.ToUpper(rs.Type)
		rs.Values = canonicalValues(rs.Type, rs.Values)
		rs.Alias = canonicalAlias(rs.Alias)
		if rs.Forward != nil {
			f := canonicalForward(*rs.Forward)
			rs.Forward, rs.TTL = &f, 0
		}
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

// SetForwards sets whether the DNS provider of a zone has URL forwards, and
// the HTTPS status of its forwards (client.HTTPSActive, HTTPSInactive...).
func (s *Server) SetForwards(zoneName string, enabled bool, https string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	z := s.zones[zoneName]
	z.forwards, z.https = enabled, https
}

// Get returns a copy of an RRset, nil if absent. The forward of a host is
// the RRset of type URLFWD.
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

func canonicalForward(f client.Forward) client.Forward {
	return client.Forward{Type: strings.ToLower(strings.TrimSpace(f.Type)), URL: strings.TrimSpace(f.URL),
		Title: strings.TrimSpace(f.Title), Keywords: strings.TrimSpace(f.Keywords), Description: strings.TrimSpace(f.Description)}
}

func contentHash(rs client.RRset) string {
	if rs.Forward != nil {
		return client.ForwardHash(*rs.Forward)
	}
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
	case (len(parts) == 2 || len(parts) == 3) && parts[1] == "forwards" && contains(s.opts.Features, client.FeatureForwards):
		if z == nil {
			Error(w, http.StatusNotFound, "not_found", "no zone "+parts[0])
			return
		}
		if len(parts) == 2 {
			if r.Method != http.MethodGet {
				Error(w, http.StatusMethodNotAllowed, "method_not_allowed", r.Method)
				return
			}
			s.listForwards(w, parts[0], z)
			return
		}
		s.forward(w, r, z, strings.ToLower(parts[2]))
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
	team, acting := s.actingTeams(r)
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
	if typ == client.TypeURLForward {
		Error(w, http.StatusBadRequest, "invalid", "URL forwards are written at /api/v1/zones/{zone}/forwards/{host}")
		return
	}
	if !s.writeChecks(w, r, key, cur, acting, false) {
		return
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

// writeChecks applies the preconditions and the ownership checks of a write,
// and answers the refusal. With foreignConflict, If-None-Match on an RRset
// the gate does not own is 409 foreign_rrset instead of 412.
func (s *Server) writeChecks(w http.ResponseWriter, r *http.Request, key string, cur *client.RRset, acting []string, foreignConflict bool) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		s.IfNoneMatch++
		if strings.TrimSpace(inm) != "*" {
			Error(w, http.StatusBadRequest, "invalid", "only If-None-Match: * is supported")
			return false
		}
		if cur != nil {
			if foreignConflict && cur.Status == client.StatusForeign {
				Error(w, http.StatusConflict, "foreign_rrset", key+" exists and is not managed by the gate")
				return false
			}
			Error(w, http.StatusPreconditionFailed, "precondition", key+" already exists")
			return false
		}
	}
	if im := r.Header.Get("If-Match"); im != "" {
		if cur == nil || !etagMatches(im, cur.Hash) {
			Error(w, http.StatusPreconditionFailed, "precondition", key+" changed since it was read")
			return false
		}
		s.IfMatch++
	}
	if cur != nil {
		switch {
		case cur.Status == client.StatusForeign:
			Error(w, http.StatusConflict, "foreign_rrset", key+" was not created or adopted through the gate")
			return false
		case cur.Status == client.StatusTainted:
			Error(w, http.StatusConflict, "tainted", key+" was modified outside the gate")
			return false
		case cur.Protected:
			Error(w, http.StatusForbidden, "forbidden", key+" is protected")
			return false
		case !contains(acting, cur.Owner):
			Error(w, http.StatusForbidden, "not_owner", key+" is owned by team "+cur.Owner)
			return false
		}
	}
	return true
}

// actingTeams returns the team a write creates for and the teams whose
// RRsets it may change, from X-DNS-Gate-Team.
func (s *Server) actingTeams(r *http.Request) (string, []string) {
	team, acting := s.opts.Teams[0], s.opts.Teams
	if h := r.Header.Get(client.TeamHeader); h != "" && r.Method != http.MethodGet {
		s.TeamHeaders[h]++
		if !s.opts.NoTeams {
			team, acting = h, []string{h}
		}
	}
	return team, acting
}

func (z *zone) httpsView() *client.HTTPSRedirect {
	h := &client.HTTPSRedirect{Status: z.https}
	if !z.forwards {
		h.Message = "provider " + z.provider + " has no URL forwards"
	}
	return h
}

func forwardRRset(rs client.RRset) client.RRset {
	if rs.Values == nil {
		rs.Values = []string{}
	}
	return rs
}

// listForwards serves GET /api/v1/zones/{zone}/forwards.
func (s *Server) listForwards(w http.ResponseWriter, name string, z *zone) {
	out := client.ForwardList{Zone: name, HTTPS: z.httpsView(), Forwards: []client.RRset{}}
	for _, rs := range z.sets {
		if rs.Type == client.TypeURLForward {
			out.Forwards = append(out.Forwards, forwardRRset(*rs))
		}
	}
	sort.Slice(out.Forwards, func(i, j int) bool { return out.Forwards[i].Host < out.Forwards[j].Host })
	writeJSON(w, http.StatusOK, out)
}

type forwardPut struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	Title        string `json:"title,omitempty"`
	Keywords     string `json:"keywords,omitempty"`
	Description  string `json:"description,omitempty"`
	RequireHTTPS bool   `json:"require_https,omitempty"`
}

// validForward is the gate's check of a desired forward (EuroDNS adapter).
func validForward(f client.Forward) string {
	if !contains(client.ForwardTypes, f.Type) {
		return fmt.Sprintf("type %q is not one of %s", f.Type, strings.Join(client.ForwardTypes, ", "))
	}
	u, err := url.Parse(f.URL)
	switch {
	case len(f.URL) > 2048 || strings.IndexFunc(f.URL, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 ||
		strings.ContainsAny(f.URL, "<>\"'`\\{}|^"):
		return fmt.Sprintf("url %q has spaces, control characters or characters to percent-encode, or is too long", f.URL)
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" || u.User != nil || u.String() != f.URL:
		return fmt.Sprintf("url %q must be an absolute http:// or https:// URL in canonical form, without user information", f.URL)
	}
	if f.Type != client.ForwardFrame && (f.Title != "" || f.Keywords != "" || f.Description != "") {
		return "title, keywords and description only apply to frame forwards"
	}
	for _, fld := range []struct {
		v   string
		max int
	}{{f.Title, 200}, {f.Keywords, 500}, {f.Description, 1000}} {
		if utf8.RuneCountInString(fld.v) > fld.max || strings.IndexFunc(fld.v, unicode.IsControl) >= 0 || strings.ContainsAny(fld.v, "<>\"'`") {
			return "title, keywords and description are plain text of at most 200, 500 and 1000 characters"
		}
	}
	return ""
}

// forward serves /api/v1/zones/{zone}/forwards/{host}.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, z *zone, host string) {
	key := host + "/" + client.TypeURLForward
	cur := z.sets[key]
	team, acting := s.actingTeams(r)
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			Error(w, http.StatusNotFound, "not_found", "no forward "+host)
			return
		}
		w.Header().Set("ETag", strconv.Quote(cur.Hash))
		writeJSON(w, http.StatusOK, client.ForwardView{RRset: forwardRRset(*cur), HTTPS: z.httpsView()})
		return
	case http.MethodPut, http.MethodDelete:
	default:
		Error(w, http.StatusMethodNotAllowed, "method_not_allowed", r.Method)
		return
	}
	if r.Method == http.MethodDelete && cur == nil && r.Header.Get("If-Match") == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.writeChecks(w, r, key, cur, acting, true) {
		return
	}
	if r.Method == http.MethodDelete {
		delete(z.sets, key)
		z.version++
		s.Writes++
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body forwardPut
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	f := canonicalForward(client.Forward{Type: body.Type, URL: body.URL, Title: body.Title, Keywords: body.Keywords, Description: body.Description})
	switch {
	case f.Type == "" || f.URL == "":
		Error(w, http.StatusBadRequest, "invalid", "type (301, 302, frame) and url are required (DELETE removes a forward)")
		return
	case body.RequireHTTPS && !z.httpsView().AnswersHTTPS():
		Error(w, http.StatusConflict, client.ReasonHTTPSUnavailable, key+": require_https: the forwards of the zone do not answer HTTPS ("+z.https+
			"); an HTTPS redirect subscription is ordered at the provider, not through the gate")
		return
	case !z.forwards:
		Error(w, http.StatusBadRequest, "invalid", key+": provider "+z.provider+" has no URL forwards")
		return
	}
	if msg := validForward(f); msg != "" {
		Error(w, http.StatusBadRequest, client.ReasonInvalidForward, key+": "+msg)
		return
	}
	now := time.Now().UTC()
	actor := &client.Actor{Subject: "fake:terraform", Name: "terraform", Category: "pipeline"}
	next := client.RRset{Host: host, Type: client.TypeURLForward, Forward: &f, Status: client.StatusManaged, Owner: team,
		CreatedBy: actor, CreatedAt: &now, UpdatedBy: actor, UpdatedAt: &now}
	if cur != nil {
		next.Owner, next.CreatedBy, next.CreatedAt, next.Adopted = cur.Owner, cur.CreatedBy, cur.CreatedAt, cur.Adopted
	}
	next.Hash = contentHash(next)
	z.sets[key] = &next
	z.version++
	s.Writes++
	w.Header().Set("ETag", strconv.Quote(next.Hash))
	writeJSON(w, http.StatusOK, client.ForwardView{RRset: forwardRRset(next), HTTPS: z.httpsView()})
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
