package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

func teamsGate(t *testing.T, noTeams bool) *fakegate.Server {
	t.Helper()
	g := fakegate.New(fakegate.Options{Token: "tok", Teams: []string{"team-a", "team-b"}, NoTeams: noTeams})
	t.Cleanup(g.Close)
	g.Seed(zone, "route53", client.RRset{Host: "other", Type: "A", TTL: 300, Values: []string{"192.0.2.9"}, Owner: "team-c"})
	return g
}

func TestTeamSelection(t *testing.T) {
	ctx := context.Background()
	g := teamsGate(t, false)
	c := newClient(t, g.URL, &sleeps{})
	me, err := c.Me(ctx)
	if err != nil || me.DefaultTeam != "team-a" {
		t.Fatalf("me %+v, err %v", me, err)
	}
	body := client.RRsetBody{TTL: 300, Values: []string{"192.0.2.1"}}
	rs, err := c.PutRRset(ctx, zone, "b", "A", body, client.Condition{IfNoneMatch: true, Team: "team-b"})
	if err != nil || rs.Owner != "team-b" || g.TeamHeaders["team-b"] != 1 {
		t.Fatalf("created %+v, err %v, headers %v", rs, err, g.TeamHeaders)
	}
	if err := c.DeleteRRset(ctx, zone, "b", "A", client.Condition{IfMatch: rs.Hash, Team: "team-a"}); !client.Is(err, 403, client.ReasonNotOwner) {
		t.Fatalf("delete for another team: expected 403 not_owner, got %v", err)
	}
	if _, err := c.PutRRset(ctx, zone, "z", "A", body, client.Condition{IfNoneMatch: true, Team: "team-z"}); !client.Is(err, 403, client.ReasonNotTeamMember) {
		t.Fatalf("expected 403 not_team_member, got %v", err)
	}
	if err := c.DeleteRRset(ctx, zone, "b", "A", client.Condition{IfMatch: rs.Hash}); err != nil {
		t.Fatalf("delete for the default team set: %v", err)
	}
}

func TestTeams(t *testing.T) {
	ctx := context.Background()
	g := teamsGate(t, false)
	c := newClient(t, g.URL, &sleeps{})
	tl, err := c.Teams(ctx)
	if err != nil || len(tl.Teams) != 3 || tl.Teams[2].Name != "team-c" || tl.Teams[2].Kind != client.TeamKindStore {
		t.Fatalf("teams %+v, err %v", tl, err)
	}
	td, err := c.Team(ctx, "Team-C")
	if err != nil || len(td.Owned) != 1 || td.Owned[0].Zone != zone || td.Owned[0].RRsets != 1 {
		t.Fatalf("team %+v, err %v", td, err)
	}
	if _, err := c.Team(ctx, "nope"); !client.IsNotFound(err) || errors.Is(err, client.ErrNoTeams) {
		t.Fatalf("unknown team: expected 404, got %v", err)
	}
}

func TestTeamsOldGate(t *testing.T) {
	ctx := context.Background()
	g := teamsGate(t, true)
	c := newClient(t, g.URL, &sleeps{})
	if me, err := c.Me(ctx); err != nil || me.DefaultTeam != "" {
		t.Fatalf("me %+v, err %v", me, err)
	}
	if _, err := c.Teams(ctx); !errors.Is(err, client.ErrNoTeams) {
		t.Fatalf("teams: expected ErrNoTeams, got %v", err)
	}
	if _, err := c.Team(ctx, "team-a"); !errors.Is(err, client.ErrNoTeams) {
		t.Fatalf("team: expected ErrNoTeams, got %v", err)
	}
	rs, err := c.PutRRset(ctx, zone, "b", "A", client.RRsetBody{TTL: 300, Values: []string{"192.0.2.1"}}, client.Condition{IfNoneMatch: true, Team: "team-b"})
	if err != nil || rs.Owner != "team-a" {
		t.Fatalf("a gate without teams ignores the header: %+v, err %v", rs, err)
	}
}
