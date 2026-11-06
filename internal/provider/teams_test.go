package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

func teamRecordTF(res, name, team string, ttl int) string {
	teamLine := ""
	if team != "" {
		teamLine = fmt.Sprintf("  team   = %q\n", team)
	}
	return fmt.Sprintf(`
resource "dnsgate_record_set" %q {
  zone   = %q
  name   = %q
  type   = "TXT"
  ttl    = %d
  values = ["v"]
%s}
`, res, testZone, name, ttl, teamLine)
}

func twoTeams(o *fakegate.Options) { o.Teams = []string{"team-a", "team-b"} }

// counters reads the write counters of the fake gate under its lock.
func counters(g *fakegate.Server) (writes int, headers map[string]int) {
	g.Mu.Lock()
	defer g.Mu.Unlock()
	headers = map[string]int{}
	for k, v := range g.TeamHeaders {
		headers[k] = v
	}
	return g.Writes, headers
}

func setOwner(g *fakegate.Server, host, team string) {
	g.Mutate(testZone, host, "TXT", func(rs *client.RRset) { rs.Owner = team })
}

func TestFakeRecordSet_team(t *testing.T) {
	clearEnv(t)
	g := newGate(t, twoTeams)
	p := providerConfig(g.URL)
	var writes int
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: func(*terraform.State) error {
			if g.Get(testZone, "b", "TXT") != nil || g.Get(testZone, "d", "TXT") != nil {
				return fmt.Errorf("record sets left after destroy")
			}
			if _, h := counters(g); h["team-a"] != 3 {
				return fmt.Errorf("team headers %v: the delete of b is made for team-a", h)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				// Created for the selected team, or for the default team.
				Config: p + teamRecordTF("b", "b", "team-b", 300) + teamRecordTF("d", "d", "", 300),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectKnownValue("dnsgate_record_set.b", tfjsonpath.New("owner_team"), knownvalue.StringExact("team-b")),
					plancheck.ExpectUnknownValue("dnsgate_record_set.d", tfjsonpath.New("owner_team")),
				}},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_record_set.b", "owner_team", "team-b"),
					resource.TestCheckResourceAttr("dnsgate_record_set.b", "owner", "team-b"),
					resource.TestCheckResourceAttr("dnsgate_record_set.d", "owner_team", "team-a"),
					resource.TestCheckNoResourceAttr("dnsgate_record_set.d", "team"),
					checkGate(g, func() error {
						if g.Get(testZone, "b", "TXT").Owner != "team-b" {
							return fmt.Errorf("b not owned by team-b in the gate")
						}
						if _, h := counters(g); h["team-b"] != 1 || len(h) != 1 {
							return fmt.Errorf("team headers %v", h)
						}
						return nil
					}),
				),
			},
			{
				// Changing team does not move the RRset: refused at plan time.
				Config:      p + teamRecordTF("b", "b", "team-a", 300) + teamRecordTF("d", "d", "", 300),
				ExpectError: regexp.MustCompile(`(?s)Record set owned by another team.*transfer request`),
			},
			{
				// Same with a content change.
				Config:      p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "", 300),
				ExpectError: regexp.MustCompile(`Record set owned by another team`),
			},
			{
				// Transferred in the gate: the new team is accepted, nothing is written.
				PreConfig: func() {
					setOwner(g, "b", "team-a")
					writes, _ = counters(g)
				},
				Config: p + teamRecordTF("b", "b", "team-a", 300) + teamRecordTF("d", "d", "", 300),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.b", plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_record_set.b", "team", "team-a"),
					resource.TestCheckResourceAttr("dnsgate_record_set.b", "owner_team", "team-a"),
					checkGate(g, func() error {
						if w, _ := counters(g); w != writes {
							return fmt.Errorf("%d writes for a team change", w-writes)
						}
						return nil
					}),
				),
			},
			{
				// Updates are made for the team.
				Config: p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "", 300),
				Check: checkGate(g, func() error {
					if _, h := counters(g); h["team-a"] != 1 {
						return fmt.Errorf("team headers %v", h)
					}
					return nil
				}),
			},
			{
				// Setting team to the owner team: nothing is written.
				Config: p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "team-a", 300),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.d", plancheck.ResourceActionUpdate),
				}},
				Check: checkGate(g, func() error {
					if w, h := counters(g); w != writes+1 || h["team-a"] != 1 {
						return fmt.Errorf("%d writes, team headers %v", w-writes, h)
					}
					return nil
				}),
			},
			{
				// Transferred away: a plan without change only warns...
				PreConfig: func() { setOwner(g, "d", "team-b") },
				Config:    p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "team-a", 300),
				PlanOnly:  true,
				Check:     resource.TestCheckResourceAttr("dnsgate_record_set.d", "owner_team", "team-b"),
			},
			{
				// ...and a change fails at plan time.
				Config:      p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "team-a", 600),
				ExpectError: regexp.MustCompile(`Record set owned by another team`),
			},
			{
				Config:      p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "team-a", 300) + teamRecordTF("z", "z", "team-z", 300),
				ExpectError: regexp.MustCompile(`(?s)Not a member of the team.*team-a, team-b`),
			},
			{
				PreConfig: func() { setOwner(g, "d", "team-a") },
				Config:    p + teamRecordTF("b", "b", "team-a", 600) + teamRecordTF("d", "d", "team-a", 300),
				PlanOnly:  true,
			},
		},
	})
}

func TestFakeRecordSet_teamOldGate(t *testing.T) {
	clearEnv(t)
	g := newGate(t, twoTeams, func(o *fakegate.Options) { o.NoTeams = true })
	p := providerConfig(g.URL)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config:      p + teamRecordTF("b", "b", "team-b", 300),
				ExpectError: regexp.MustCompile(`The gate does not support team selection`),
			},
			{
				// The first team is what such a gate writes for anyway.
				Config: p + teamRecordTF("a", "a", "team-a", 300) + teamRecordTF("d", "d", "", 300),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_record_set.a", "owner_team", "team-a"),
					resource.TestCheckResourceAttr("dnsgate_record_set.d", "owner_team", "team-a"),
				),
			},
		},
	})
}

func TestFakeTeamDataSources(t *testing.T) {
	clearEnv(t)
	g := newGate(t, twoTeams)
	g.TeamInfos = []client.TeamInfo{
		{Name: "team-b", Kind: client.TeamKindDeclared, Layer: "managed", Description: "Team B", Roles: []string{"writer"},
			Members: &client.TeamMembers{Groups: []string{"dns-b"}, Subjects: []client.SubjectMatcher{{Issuer: "ci", Claims: map[string][]string{"sub": {"repo:b/*"}}}}}},
		{Name: "team-a", Kind: client.TeamKindDeclared, Layer: "base", Roles: []string{"writer"}},
		{Name: "app-*", Kind: client.TeamKindFamily, Roles: []string{"apps"}, Family: &client.TeamFrom{Claim: "sub", Regex: "^repo:org/(.+)$", Prefix: "app-"}},
	}
	g.Strict = true
	g.Seed("example.org", "eurodns", client.RRset{Host: "@", Type: "A", TTL: 300, Values: []string{"192.0.2.1"}, Owner: "team-b"})
	cfg := providerConfig(g.URL) + `
data "dnsgate_me" "me" {}
data "dnsgate_teams" "all" {}
data "dnsgate_teams" "declared" {
  kind = "declared"
}
data "dnsgate_team" "b" {
  name = "team-b"
}
data "dnsgate_record_set" "other" {
  zone = "example.com"
  name = "other"
  type = "A"
}
data "dnsgate_record_sets" "b" {
  zone  = "example.com"
  owner = "team-b"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.dnsgate_me.me", "default_team", "team-a"),
					resource.TestCheckResourceAttr("data.dnsgate_me.me", "teams.#", "2"),
					resource.TestCheckResourceAttr("data.dnsgate_me.me", "category", "pipeline"),
					resource.TestCheckResourceAttr("data.dnsgate_teams.all", "strict", "true"),
					resource.TestCheckResourceAttr("data.dnsgate_teams.all", "names.#", "3"),
					resource.TestCheckResourceAttr("data.dnsgate_teams.all", "names.0", "app-*"),
					resource.TestCheckResourceAttr("data.dnsgate_teams.all", "teams.0.family.prefix", "app-"),
					resource.TestCheckNoResourceAttr("data.dnsgate_teams.all", "teams.0.members"),
					resource.TestCheckResourceAttr("data.dnsgate_teams.declared", "names.#", "2"),
					resource.TestCheckResourceAttr("data.dnsgate_teams.declared", "teams.1.description", "Team B"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "kind", "declared"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "layer", "managed"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "members.groups.0", "dns-b"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "members.subjects.0.claims.sub.0", "repo:b/*"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "owned.#", "2"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "owned.0.zone", "example.com"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "owned.1.rrsets", "1"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "rrsets", "2"),
					resource.TestCheckResourceAttr("data.dnsgate_team.b", "pending_transfers.#", "0"),
					resource.TestCheckResourceAttr("data.dnsgate_record_set.other", "owner_team", "team-b"),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.b", "record_sets.0.owner_team", "team-b"),
				),
			},
			{
				Config:      providerConfig(g.URL) + `data "dnsgate_team" "x" {` + "\n" + `  name = "nope"` + "\n}\n",
				ExpectError: regexp.MustCompile(`Team not found`),
			},
		},
	})
}

func TestFakeTeamDataSources_oldGate(t *testing.T) {
	clearEnv(t)
	g := newGate(t, twoTeams, func(o *fakegate.Options) { o.NoTeams = true })
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerConfig(g.URL) + `
data "dnsgate_me" "me" {}
data "dnsgate_teams" "all" {}
data "dnsgate_team" "a" {
  name = "team-a"
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.dnsgate_me.me", "default_team", "team-a"),
				resource.TestCheckResourceAttr("data.dnsgate_teams.all", "strict", "false"),
				resource.TestCheckResourceAttr("data.dnsgate_teams.all", "teams.#", "0"),
				resource.TestCheckResourceAttr("data.dnsgate_teams.all", "names.#", "0"),
				resource.TestCheckResourceAttr("data.dnsgate_team.a", "kind", ""),
				resource.TestCheckResourceAttr("data.dnsgate_team.a", "owned.#", "0"),
				resource.TestCheckResourceAttr("data.dnsgate_team.a", "rrsets", "0"),
			),
		}},
	})
}
