package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

const pipelineSC = "sc://org/project/dnsgate-x"

func policyGate(t *testing.T) *fakegate.Server {
	t.Helper()
	return newGate(t)
}

func gateRoleTF(hosts string) string {
	return fmt.Sprintf(`
resource "dnsgate_role" "x" {
  name        = "dnsgate-x"
  description = "DNS names of pipeline x"
  rules = [{
    zones   = ["example.com"]
    actions = ["dns.read", "dns.record.write"]
    hosts   = [%s]
    types   = ["CNAME", "TXT"]
  }]
}
`, hosts)
}

const gateBindingTF = `
resource "dnsgate_binding" "x" {
  name = "dnsgate-x"
  role = dnsgate_role.x.name
  team = "dnsgate-x"
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = ["` + pipelineSC + `"] }
  }]
}
`

func checkFake(g *fakegate.Server, f func(p *fakegate.Policy) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		g.Mu.Lock()
		defer g.Mu.Unlock()
		return f(g.Policy)
	}
}

func TestFakeGateRoleAndBinding(t *testing.T) {
	clearEnv(t)
	g := policyGate(t)
	p := providerConfig(g.URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: checkFake(g, func(p *fakegate.Policy) error {
			if len(p.Objects) != 0 {
				return fmt.Errorf("objects left after destroy: %v", p.Objects)
			}
			return nil
		}),
		Steps: []resource.TestStep{
			{
				Config: p + gateRoleTF(`"x.apps"`) + gateBindingTF,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_role.x", "id", "dnsgate-x"),
					resource.TestCheckResourceAttr("dnsgate_role.x", "delegation", "ci"),
					resource.TestCheckResourceAttr("dnsgate_role.x", "rebase_on_save", "false"),
					resource.TestCheckResourceAttr("dnsgate_role.x", "max_changes_per_request", "0"),
					resource.TestCheckResourceAttrSet("dnsgate_role.x", "etag"),
					resource.TestCheckResourceAttr("dnsgate_binding.x", "team", "dnsgate-x"),
					resource.TestCheckResourceAttr("dnsgate_binding.x", "subjects.0.claims.sub.0", pipelineSC),
					checkFake(g, func(p *fakegate.Policy) error {
						role := p.Objects["role/dnsgate-x"]
						if role == nil || role.Role.Rules[0].Records == nil || role.Role.Rules[0].Records.Hosts[0] != "x.apps" {
							return fmt.Errorf("role in the gate: %+v", role)
						}
						if p.IfNoneMatch != 2 || p.ManagedBy[0] != "terraform" {
							return fmt.Errorf("create preconditions %d, managed_by %v", p.IfNoneMatch, p.ManagedBy)
						}
						return nil
					}),
				),
			},
			{
				// In-place update, with the ETag of the state as If-Match.
				Config: p + gateRoleTF(`"x.apps", "_acme-challenge.x.apps"`) + gateBindingTF,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("dnsgate_role.x", plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction("dnsgate_binding.x", plancheck.ResourceActionNoop),
					},
				},
				Check: checkFake(g, func(p *fakegate.Policy) error {
					if hosts := p.Objects["role/dnsgate-x"].Role.Rules[0].Records.Hosts; len(hosts) != 2 || p.IfMatch != 1 {
						return fmt.Errorf("update: hosts %v, if-match %d", hosts, p.IfMatch)
					}
					return nil
				}),
			},
			{
				// Drift: changed in the gate outside Terraform; the plan restores it.
				PreConfig: func() {
					g.Mu.Lock()
					defer g.Mu.Unlock()
					obj := g.Policy.Objects["role/dnsgate-x"]
					obj.Role.Rules[0].Actions = []string{"dns.read"}
					obj.ETag = `"drifted"`
				},
				Config: p + gateRoleTF(`"x.apps", "_acme-challenge.x.apps"`) + gateBindingTF,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("dnsgate_role.x", plancheck.ResourceActionUpdate)},
				},
				Check: checkFake(g, func(p *fakegate.Policy) error {
					if a := p.Objects["role/dnsgate-x"].Role.Rules[0].Actions; len(a) != 2 {
						return fmt.Errorf("drift not corrected: %v", a)
					}
					return nil
				}),
			},
			{
				// Deleted outside Terraform: planned for creation again.
				PreConfig: func() {
					g.Mu.Lock()
					defer g.Mu.Unlock()
					delete(g.Policy.Objects, "binding/dnsgate-x")
				},
				Config: p + gateRoleTF(`"x.apps", "_acme-challenge.x.apps"`) + gateBindingTF,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("dnsgate_binding.x", plancheck.ResourceActionCreate)},
				},
			},
			{ResourceName: "dnsgate_role.x", ImportState: true, ImportStateId: "dnsgate-x", ImportStateVerify: true},
			{ResourceName: "dnsgate_binding.x", ImportState: true, ImportStateId: "dnsgate-x", ImportStateVerify: true},
		},
	})
}

func TestFakeGateBindingTeamFromAndGroups(t *testing.T) {
	clearEnv(t)
	g := policyGate(t)
	p := providerConfig(g.URL)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: p + `
resource "dnsgate_binding" "all" {
  name = "gate-pipelines"
  role = "pipeline-writer"
  team_from = {
    claim = "sub"
    regex = "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"
  }
  subjects = [{
    issuer = "azure-devops"
    claims = { sub = ["sc://org/project/dns-gate-*"] }
  }]
  groups = ["release-pipelines"]
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckNoResourceAttr("dnsgate_binding.all", "team"),
				resource.TestCheckResourceAttr("dnsgate_binding.all", "team_from.claim", "sub"),
				resource.TestCheckResourceAttr("dnsgate_binding.all", "groups.0", "release-pipelines"),
				checkFake(g, func(p *fakegate.Policy) error {
					b := p.Objects["binding/gate-pipelines"].Binding
					if b.TeamFrom == nil || b.Team != "" || len(b.Groups) != 1 {
						return fmt.Errorf("binding in the gate: %+v", b)
					}
					return nil
				}),
			),
		}},
	})
}

func TestFakeGateRoleBusyRetried(t *testing.T) {
	clearEnv(t)
	g := policyGate(t)
	func() { g.Mu.Lock(); defer g.Mu.Unlock(); g.Policy.Busy = 3 }()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerConfig(g.URL) + gateRoleTF(`"x.apps"`),
			Check: checkFake(g, func(p *fakegate.Policy) error {
				if p.BusyRefusals != 3 || p.Objects["role/dnsgate-x"] == nil {
					return fmt.Errorf("busy refusals %d", p.BusyRefusals)
				}
				return nil
			}),
		}},
	})
}

func TestFakeGateRoleErrors(t *testing.T) {
	clearEnv(t)
	g := policyGate(t)
	func() { g.Mu.Lock(); defer g.Mu.Unlock(); g.Policy.ForbiddenZone = "example.org" }()
	p := providerConfig(g.URL)
	outside := `
resource "dnsgate_role" "o" {
  name  = "outside"
  rules = [{ zones = ["example.org"], actions = ["dns.record.write"] }]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: p + outside, ExpectError: regexp.MustCompile(`(?s)invalid_policy.*rules\[0\]\.zones\[0\]: zone example.org is not delegated`)},
			{
				PreConfig: func() {
					g.Mu.Lock()
					defer g.Mu.Unlock()
					g.Policy.Objects["role/dnsgate-x"] = &client.DelegatedObject{Kind: "role", Name: "dnsgate-x", Role: &client.Role{Rules: []client.Rule{{Zones: []string{"example.com"}, Actions: []string{"dns.read"}}}}, Owner: client.DelegatedOwner{Delegation: "ci"}, ETag: `"other"`}
				},
				Config:      p + gateRoleTF(`"x.apps"`),
				ExpectError: regexp.MustCompile(`already exists[\s\S]*Import it`),
			},
			{
				PreConfig:   func() { func() { g.Mu.Lock(); defer g.Mu.Unlock(); g.Policy.Busy = 100 }() },
				Config:      p + `resource "dnsgate_role" "b" {` + "\n" + `  name = "busy"` + "\n" + `  rules = [{ zones = ["example.com"], actions = ["dns.read"] }]` + "\n}\n",
				ExpectError: regexp.MustCompile(`policy_busy`),
			},
			{
				Config:      p + `resource "dnsgate_binding" "n" {` + "\n" + `  name = "n"` + "\n" + `  role = "r"` + "\n" + `  groups = ["g"]` + "\n}\n",
				ExpectError: regexp.MustCompile(`one \(and only one\) of \[team,team_from\]`),
			},
			{
				Config:      p + `resource "dnsgate_role" "t" {` + "\n" + `  name = "t"` + "\n" + `  ephemeral_ttl = "soon"` + "\n" + `  rules = [{ zones = ["example.com"], actions = ["dns.read"] }]` + "\n}\n",
				ExpectError: regexp.MustCompile(`Invalid duration`),
			},
		},
	})
}

func TestFakeRoleNeedsDelegationFeature(t *testing.T) {
	clearEnv(t)
	g := newGate(t, func(o *fakegate.Options) { o.Features = []string{"rrset-api"} })
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: providerConfig(g.URL) + gateRoleTF(`"x.apps"`), ExpectError: regexp.MustCompile(`does not serve the delegation API`)},
		},
	})
}
