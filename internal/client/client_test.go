package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/auth"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

const zone = "example.com"

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

func newClient(t *testing.T, url string, sl *sleeps) *client.Client {
	t.Helper()
	c, err := client.New(client.Options{BaseURL: url, Tokens: auth.Static("tok"), MaxRetries: 3, Sleep: sl.sleep, UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func gate(t *testing.T) *fakegate.Server {
	t.Helper()
	g := fakegate.New(fakegate.Options{Token: "tok", Teams: []string{"team-a"}})
	t.Cleanup(g.Close)
	g.Seed(zone, "route53",
		client.RRset{Host: "legacy", Type: "TXT", TTL: 300, Values: []string{"keep-me"}},
		client.RRset{Host: "other", Type: "A", TTL: 300, Values: []string{"192.0.2.9"}, Owner: "team-b"},
	)
	return g
}

func TestInfo(t *testing.T) {
	g := gate(t)
	c := newClient(t, g.URL, &sleeps{})
	info, err := c.Info(context.Background())
	if err != nil || !info.HasFeature(client.FeaturePolicyDelegation) {
		t.Fatalf("info %+v, err %v", info, err)
	}
	notGate := httptest.NewServer(http.NotFoundHandler())
	defer notGate.Close()
	if _, err := newClient(t, notGate.URL, &sleeps{}).Info(context.Background()); err != client.ErrNotGate {
		t.Fatalf("expected ErrNotGate, got %v", err)
	}
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer html.Close()
	if _, err := newClient(t, html.URL, &sleeps{}).Info(context.Background()); err != client.ErrNotGate {
		t.Fatalf("expected ErrNotGate for HTML, got %v", err)
	}
}

func TestRRsetLifecycle(t *testing.T) {
	ctx := context.Background()
	g := gate(t)
	c := newClient(t, g.URL, &sleeps{})

	created, err := c.PutRRset(ctx, zone, "www", "cname", client.RRsetBody{TTL: 300, Values: []string{"Target.Example.net"}}, client.Condition{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	if created.Hash == "" || created.Owner != "team-a" || created.Values[0] != "Target.Example.net." {
		t.Fatalf("created %+v", created)
	}
	if _, err := c.PutRRset(ctx, zone, "www", "CNAME", client.RRsetBody{TTL: 300, Values: []string{"x.example.net."}}, client.Condition{IfNoneMatch: true}); !client.IsPrecondition(err) {
		t.Fatalf("second create: expected 412, got %v", err)
	}
	got, err := c.GetRRset(ctx, zone, "www", "CNAME")
	if err != nil || got.Hash != created.Hash {
		t.Fatalf("get %+v, err %v", got, err)
	}
	if _, err := c.PutRRset(ctx, zone, "www", "CNAME", client.RRsetBody{TTL: 600, Values: []string{"x.example.net."}}, client.Condition{IfMatch: "stale"}); !client.IsPrecondition(err) {
		t.Fatalf("stale If-Match: expected 412, got %v", err)
	}
	updated, err := c.PutRRset(ctx, zone, "www", "CNAME", client.RRsetBody{TTL: 600, Values: []string{"x.example.net."}}, client.Condition{IfMatch: created.Hash})
	if err != nil || updated.Hash == created.Hash || updated.TTL != 600 {
		t.Fatalf("update %+v, err %v", updated, err)
	}
	if err := c.DeleteRRset(ctx, zone, "www", "CNAME", client.Condition{IfMatch: created.Hash}); !client.IsPrecondition(err) {
		t.Fatalf("delete with stale hash: expected 412, got %v", err)
	}
	if err := c.DeleteRRset(ctx, zone, "www", "CNAME", client.Condition{IfMatch: updated.Hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRRset(ctx, zone, "www", "CNAME"); !client.Is(err, 404, client.ReasonNotFound) {
		t.Fatalf("expected 404 not_found, got %v", err)
	}
}

func TestOwnershipRefusals(t *testing.T) {
	ctx := context.Background()
	g := gate(t)
	c := newClient(t, g.URL, &sleeps{})
	_, err := c.PutRRset(ctx, zone, "legacy", "TXT", client.RRsetBody{TTL: 300, Values: []string{"x"}}, client.Condition{})
	if e, ok := client.AsAPIError(err); !ok || e.Status != 409 || e.Reason != client.ReasonForeignRRset {
		t.Fatalf("expected 409 foreign_rrset, got %v", err)
	}
	if err := c.DeleteRRset(ctx, zone, "other", "A", client.Condition{}); !client.Is(err, 403, client.ReasonNotOwner) {
		t.Fatalf("expected 403 not_owner, got %v", err)
	}
}

func TestEscapingApexAndWildcard(t *testing.T) {
	ctx := context.Background()
	g := gate(t)
	c := newClient(t, g.URL, &sleeps{})
	for _, host := range []string{"@", "*", "*.apps", "_dmarc"} {
		if _, err := c.PutRRset(ctx, zone, host, "TXT", client.RRsetBody{TTL: 300, Values: []string{"v=" + host}}, client.Condition{IfNoneMatch: true}); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if g.Get(zone, host, "TXT") == nil {
			t.Fatalf("%s not stored under its own name", host)
		}
	}
	if client.RRsetPath(zone, "*.apps", "txt") != "/api/v1/zones/example.com/rrsets/%2A.apps/TXT" {
		t.Fatalf("path %s", client.RRsetPath(zone, "*.apps", "txt"))
	}
	inv, err := c.Inventory(ctx, zone)
	if err != nil || inv.ETag == "" || inv.Find("*.apps", "TXT") == nil {
		t.Fatalf("inventory %+v, err %v", inv, err)
	}
}

func TestRetriesZoneLockedWithRetryAfter(t *testing.T) {
	ctx := context.Background()
	g := gate(t)
	sl := &sleeps{}
	c := newClient(t, g.URL, sl)
	g.AddFault(fakegate.Fault{Method: "PUT", Status: 423, Reason: client.ReasonZoneLocked, RetryAfter: "7", Times: 1})
	g.AddFault(fakegate.Fault{Method: "PUT", Status: 429, Reason: "rate_limited", Times: 1})
	g.AddFault(fakegate.Fault{Method: "PUT", Status: 503, Reason: client.ReasonZoneLocked, Times: 1})
	if _, err := c.PutRRset(ctx, zone, "a", "A", client.RRsetBody{TTL: 60, Values: []string{"192.0.2.1"}}, client.Condition{IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if len(sl.d) != 3 || sl.d[0] != 7*time.Second {
		t.Fatalf("waits %v", sl.d)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	ctx := context.Background()
	g := gate(t)
	sl := &sleeps{}
	c := newClient(t, g.URL, sl)
	g.AddFault(fakegate.Fault{Method: "GET", Status: 502, Reason: client.ReasonUpstream, Times: 10})
	_, err := c.GetRRset(ctx, zone, "legacy", "TXT")
	e, ok := client.AsAPIError(err)
	if !ok || e.Status != 502 || e.Attempts != 4 || len(sl.d) != 3 {
		t.Fatalf("err %v, waits %v", err, sl.d)
	}
	for i, d := range sl.d {
		if max := time.Second << i; d < max/2 || d > max*3/2 {
			t.Fatalf("wait %d = %v, outside the jittered backoff", i, d)
		}
	}
}

func TestNoRetryOnClientErrors(t *testing.T) {
	g := gate(t)
	sl := &sleeps{}
	c := newClient(t, g.URL, sl)
	for _, f := range []fakegate.Fault{
		{Status: 400, Reason: client.ReasonInvalid}, {Status: 403, Reason: client.ReasonForbidden},
		{Status: 409, Reason: client.ReasonTainted}, {Status: 412, Reason: client.ReasonPrecondition},
	} {
		g.AddFault(f)
		if _, err := c.GetRRset(context.Background(), zone, "legacy", "TXT"); !client.Is(err, f.Status, f.Reason) {
			t.Fatalf("expected %d %s, got %v", f.Status, f.Reason, err)
		}
	}
	if len(sl.d) != 0 {
		t.Fatalf("unexpected retries %v", sl.d)
	}
}

func TestRetriesTransportErrorsAndStopsOnCancel(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		_ = json.NewEncoder(w).Encode([]client.Zone{{Zone: zone}})
	}))
	defer srv.Close()
	sl := &sleeps{}
	zs, err := newClient(t, srv.URL, sl).Zones(context.Background())
	if err != nil || len(zs) != 1 || calls != 2 {
		t.Fatalf("zones %v, err %v, calls %d", zs, err, calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	locked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fakegate.Error(w, 423, client.ReasonZoneLocked, "locked")
	}))
	defer locked.Close()
	c, _ := client.New(client.Options{BaseURL: locked.URL, Tokens: auth.Static("tok"), MaxRetries: 5,
		Sleep: func(context.Context, time.Duration) error { cancel(); return context.Canceled }})
	if _, err := c.Zones(ctx); err == nil || !strings.Contains(err.Error(), "stopped retrying") || !client.Is(err, 423, client.ReasonZoneLocked) {
		t.Fatalf("expected a stopped zone_locked error, got %v", err)
	}
}

func TestRequestTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	c, _ := client.New(client.Options{BaseURL: srv.URL, Tokens: auth.Static("tok"), MaxRetries: -1, RequestTimeout: 50 * time.Millisecond})
	start := time.Now()
	if _, err := c.Zones(context.Background()); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("expected a timeout, got %v after %v", err, time.Since(start))
	}
}

func TestErrorDetailsAndActorForms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/A") {
			w.Header().Set("ETag", `"abc"`)
			_, _ = w.Write([]byte(`{"host":"www","type":"A","ttl":60,"values":["192.0.2.1"],"hash":"ignored","created_by":"oidc:pipeline","updated_by":{"subject":"s","name":"n","category":"human"}}`))
			return
		}
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"reason":"foreign_rrset","message":"m","details":{"owner":null}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, &sleeps{})
	rs, err := c.GetRRset(context.Background(), zone, "www", "A")
	if err != nil || rs.Hash != "abc" || rs.CreatedBy.Display() != "oidc:pipeline" || rs.UpdatedBy.Display() != "n" {
		t.Fatalf("rrset %+v, err %v", rs, err)
	}
	_, err = c.GetRRset(context.Background(), zone, "www", "TXT")
	e, ok := client.AsAPIError(err)
	if !ok || e.Reason != "foreign_rrset" || string(e.Details) != `{"owner":null}` {
		t.Fatalf("error %+v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	g := gate(t)
	c := newClient(t, g.URL, &sleeps{})
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "h" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26))
			if _, err := c.PutRRset(ctx, zone, host, "A", client.RRsetBody{TTL: 60, Values: []string{"192.0.2.1"}}, client.Condition{IfNoneMatch: true}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := g.Count(zone); n != 42 {
		t.Fatalf("%d RRsets", n)
	}
}
