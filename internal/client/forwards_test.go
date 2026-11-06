package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

const fwdZone = "example.org"

func forwardsGate(t *testing.T, teams ...string) *fakegate.Server {
	t.Helper()
	if len(teams) == 0 {
		teams = []string{"team-a"}
	}
	g := fakegate.New(fakegate.Options{Token: "tok", Teams: teams})
	t.Cleanup(g.Close)
	g.Seed(fwdZone, "eurodns",
		client.RRset{Host: "legacy", Type: client.TypeURLForward, Forward: &client.Forward{Type: "302", URL: "https://old.example.net/"}},
		client.RRset{Host: "other", Type: client.TypeURLForward, Forward: &client.Forward{Type: "301", URL: "https://b.example.net/"}, Owner: "team-c"},
	)
	g.Seed(zone, "route53")
	return g
}

func TestForwardHash(t *testing.T) {
	for _, c := range []struct {
		f    client.Forward
		want string
	}{
		{client.Forward{Type: "301", URL: "https://example.net/"}, "a5df29b0fe2e36e66de490cd3dd44e3997fa76fa19194790e245bbd9eac2a796"},
		{client.Forward{Type: "FRAME", URL: "https://example.net/", Title: "T"}, client.ForwardHash(client.Forward{Type: "frame", URL: "https://example.net/", Title: "T"})},
	} {
		if got := client.ForwardHash(c.f); got != c.want {
			t.Fatalf("hash of %+v: %s, want %s", c.f, got, c.want)
		}
	}
	if client.ForwardHash(client.Forward{Type: "frame", URL: "u", Title: "ab"}) == client.ForwardHash(client.Forward{Type: "frame", URL: "u", Keywords: "ab"}) {
		t.Fatal("title and keywords hash the same")
	}
}

func TestForwardLifecycle(t *testing.T) {
	ctx := context.Background()
	g := forwardsGate(t)
	c := newClient(t, g.URL, &sleeps{})

	body := client.ForwardBody{Type: "301", URL: "https://example.net/"}
	created, err := c.PutForward(ctx, fwdZone, "go", body, client.Condition{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	if created.Hash != client.ForwardHash(body.Forward()) || created.Owner != "team-a" || created.Type != client.TypeURLForward ||
		created.Forward == nil || created.Forward.URL != body.URL || created.HTTPS == nil || created.HTTPS.Status != client.HTTPSInactive {
		t.Fatalf("created %+v (https %+v)", created, created.HTTPS)
	}
	if _, err := c.PutForward(ctx, fwdZone, "go", body, client.Condition{IfNoneMatch: true}); !client.IsPrecondition(err) {
		t.Fatalf("second create: expected 412, got %v", err)
	}
	got, err := c.GetForward(ctx, fwdZone, "go")
	if err != nil || got.Hash != created.Hash || got.Forward.Type != "301" {
		t.Fatalf("get %+v, err %v", got, err)
	}
	frame := client.ForwardBody{Type: "frame", URL: "https://shop.example.net/", Title: "Shop", Keywords: "a, b", Description: "d"}
	if _, err := c.PutForward(ctx, fwdZone, "go", frame, client.Condition{IfMatch: "stale"}); !client.IsPrecondition(err) {
		t.Fatalf("stale If-Match: expected 412, got %v", err)
	}
	updated, err := c.PutForward(ctx, fwdZone, "go", frame, client.Condition{IfMatch: created.Hash})
	if err != nil || updated.Hash != client.ForwardHash(frame.Forward()) || updated.Forward.Title != "Shop" {
		t.Fatalf("update %+v, err %v", updated, err)
	}
	l, err := c.ListForwards(ctx, fwdZone)
	if err != nil || l.Zone != fwdZone || len(l.Forwards) != 3 || l.Forwards[0].Host != "go" || l.HTTPS.Status != client.HTTPSInactive {
		t.Fatalf("list %+v, err %v", l, err)
	}
	inv, err := c.Inventory(ctx, fwdZone)
	if err != nil || inv.Find("go", client.TypeURLForward) == nil {
		t.Fatalf("forward not in the inventory: %+v, err %v", inv, err)
	}
	if err := c.DeleteForward(ctx, fwdZone, "go", client.Condition{IfMatch: created.Hash}); !client.IsPrecondition(err) {
		t.Fatalf("delete with stale hash: expected 412, got %v", err)
	}
	if err := c.DeleteForward(ctx, fwdZone, "go", client.Condition{IfMatch: updated.Hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetForward(ctx, fwdZone, "go"); !client.Is(err, 404, client.ReasonNotFound) {
		t.Fatalf("expected 404 not_found, got %v", err)
	}
	if err := c.DeleteForward(ctx, fwdZone, "go", client.Condition{}); err != nil {
		t.Fatalf("delete of an absent forward: %v", err)
	}
}

func TestForwardRefusals(t *testing.T) {
	ctx := context.Background()
	g := forwardsGate(t, "team-a", "team-b")
	c := newClient(t, g.URL, &sleeps{})
	redirect := client.ForwardBody{Type: "301", URL: "https://example.net/"}
	for _, x := range []struct {
		name   string
		zone   string
		host   string
		body   client.ForwardBody
		cond   client.Condition
		status int
		reason string
	}{
		{"foreign create", fwdZone, "legacy", redirect, client.Condition{IfNoneMatch: true}, 409, client.ReasonForeignRRset},
		{"foreign update", fwdZone, "legacy", redirect, client.Condition{}, 409, client.ReasonForeignRRset},
		{"other team", fwdZone, "other", redirect, client.Condition{}, 403, client.ReasonNotOwner},
		{"not a member", fwdZone, "z", redirect, client.Condition{IfNoneMatch: true, Team: "team-z"}, 403, client.ReasonNotTeamMember},
		{"frame fields", fwdZone, "x", client.ForwardBody{Type: "302", URL: "https://example.net/", Title: "t"}, client.Condition{}, 400, client.ReasonInvalidForward},
		{"bad type", fwdZone, "x", client.ForwardBody{Type: "303", URL: "https://example.net/"}, client.Condition{}, 400, client.ReasonInvalidForward},
		{"relative url", fwdZone, "x", client.ForwardBody{Type: "301", URL: "/path"}, client.Condition{}, 400, client.ReasonInvalidForward},
		{"https", fwdZone, "x", client.ForwardBody{Type: "301", URL: "https://example.net/", RequireHTTPS: true}, client.Condition{}, 409, client.ReasonHTTPSUnavailable},
		{"no forwards", zone, "x", redirect, client.Condition{}, 400, client.ReasonInvalid},
	} {
		_, err := c.PutForward(ctx, x.zone, x.host, x.body, x.cond)
		if !client.Is(err, x.status, x.reason) {
			t.Fatalf("%s: expected %d %s, got %v", x.name, x.status, x.reason, err)
		}
	}
	g.SetForwards(fwdZone, true, client.HTTPSActive)
	v, err := c.PutForward(ctx, fwdZone, "x", client.ForwardBody{Type: "301", URL: "https://example.net/", RequireHTTPS: true}, client.Condition{IfNoneMatch: true, Team: "team-b"})
	if err != nil || v.Owner != "team-b" || !v.HTTPS.AnswersHTTPS() || g.TeamHeaders["team-b"] != 1 {
		t.Fatalf("require_https on an active zone: %+v, err %v", v, err)
	}
	if err := c.DeleteForward(ctx, fwdZone, "x", client.Condition{IfMatch: v.Hash, Team: "team-a"}); !client.Is(err, 403, client.ReasonNotOwner) {
		t.Fatalf("delete for another team: expected 403 not_owner, got %v", err)
	}
}

func TestForwardRequest(t *testing.T) {
	var got struct {
		method, path, ifNoneMatch, ifMatch, team string
		body                                     map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path = r.Method, r.URL.EscapedPath()
		got.ifNoneMatch, got.ifMatch, got.team = r.Header.Get("If-None-Match"), r.Header.Get("If-Match"), r.Header.Get(client.TeamHeader)
		b, _ := io.ReadAll(r.Body)
		got.body = nil
		_ = json.Unmarshal(b, &got.body)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("ETag", `"h2"`)
		_, _ = w.Write([]byte(`{"host":"@","type":"URLFWD","ttl":0,"values":[],"forward":{"type":"301","url":"https://example.net/"},` +
			`"hash":"h1","status":"managed","protected":false,"owner":"team-a","adopted":false,` +
			`"https":{"status":"active","subscription":"12","expires_at":"2027-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, &sleeps{})
	v, err := c.PutForward(context.Background(), zone, "@", client.ForwardBody{Type: "301", URL: "https://example.net/"}, client.Condition{IfNoneMatch: true, Team: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPut || got.path != "/api/v1/zones/example.com/forwards/@" || got.ifNoneMatch != "*" || got.team != "team-a" {
		t.Fatalf("request %+v", got)
	}
	if got.body["require_https"] != false || got.body["type"] != "301" {
		t.Fatalf("body %v: require_https must always be sent", got.body)
	}
	if _, ok := got.body["title"]; ok {
		t.Fatalf("body %v: empty frame fields must be omitted", got.body)
	}
	if v.Hash != "h2" || v.HTTPS.Subscription != "12" || v.HTTPS.ExpiresAt == "" || v.Forward.URL != "https://example.net/" {
		t.Fatalf("view %+v https %+v", v, v.HTTPS)
	}
	if err := c.DeleteForward(context.Background(), zone, "*.apps", client.Condition{IfNoneMatch: true, IfMatch: "h2"}); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodDelete || got.path != "/api/v1/zones/example.com/forwards/%2A.apps" || got.ifNoneMatch != "" || got.ifMatch != `"h2"` {
		t.Fatalf("delete request %+v", got)
	}
}
