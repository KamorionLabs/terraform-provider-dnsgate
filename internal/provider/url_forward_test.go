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
	"strings"
)

const fwdZone = "example.org"

// newForwardGate is newGate plus a EuroDNS zone with URL forwards: a
// foreign forward on legacy and one of team-b on other.
func newForwardGate(t *testing.T, opts ...func(*fakegate.Options)) *fakegate.Server {
	t.Helper()
	g := newGate(t, opts...)
	g.Seed(fwdZone, "eurodns",
		client.RRset{Host: "legacy", Type: client.TypeURLForward, Forward: &client.Forward{Type: "302", URL: "https://old.example.net/"}},
		client.RRset{Host: "other", Type: client.TypeURLForward, Forward: &client.Forward{Type: "301", URL: "https://b.example.net/"}, Owner: "team-b"},
	)
	return g
}

func forwardTF(res, zone, name, typ, url, extra string) string {
	return fmt.Sprintf(`
resource "dnsgate_url_forward" %q {
  zone = %q
  name = %q
  type = %q
  url  = %q
%s}
`, res, zone, name, typ, url, extra)
}

func fwd(g *fakegate.Server, host string) *client.RRset {
	return g.Get(fwdZone, host, client.TypeURLForward)
}

func TestFakeURLForward_lifecycle(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	p := providerConfig(g.URL)
	frame := `  title       = "Shop"
  keywords    = "shop, example"
  description = "The example shop"
`
	base := forwardTF("go", fwdZone, "go", "301", "https://example.net/", "") +
		forwardTF("apex", fwdZone, "@", "frame", "https://shop.example.net/", frame)
	updated := forwardTF("go", fwdZone, "go", "302", "https://example.net/new", "") +
		forwardTF("apex", fwdZone, "@", "frame", "https://shop.example.net/", frame)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: func(*terraform.State) error {
			if fwd(g, "go") != nil || fwd(g, "@") != nil {
				return fmt.Errorf("forwards left after destroy")
			}
			if fwd(g, "legacy") == nil || fwd(g, "other") == nil {
				return fmt.Errorf("forwards of others were deleted")
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: p + base,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "id", "example.org/go"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "owner_team", "team-a"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "status", "managed"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "https_status", "inactive"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "require_https", "false"),
					resource.TestCheckNoResourceAttr("dnsgate_url_forward.go", "title"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.apex", "id", "example.org/@"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.apex", "keywords", "shop, example"),
					checkGate(g, func() error {
						f := fwd(g, "@")
						if f == nil || f.Forward.Type != "frame" || f.Forward.Description != "The example shop" || f.Owner != "team-a" {
							return fmt.Errorf("gate apex forward %+v", f)
						}
						if g.IfNoneMatch != 2 {
							return fmt.Errorf("creates without If-None-Match: %d", g.IfNoneMatch)
						}
						return nil
					}),
				),
			},
			{Config: p + base, PlanOnly: true},
			{
				// In-place update with If-Match: type and url.
				Config: p + updated,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_url_forward.go", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction("dnsgate_url_forward.apex", plancheck.ResourceActionNoop),
				}},
				Check: checkGate(g, func() error {
					if f := fwd(g, "go"); f.Forward.Type != "302" || f.Forward.URL != "https://example.net/new" || g.IfMatch != 1 {
						return fmt.Errorf("gate %+v, If-Match %d", f.Forward, g.IfMatch)
					}
					return nil
				}),
			},
			{
				// Frame fields removed by a change to a redirect.
				Config: p + forwardTF("go", fwdZone, "go", "302", "https://example.net/new", "") +
					forwardTF("apex", fwdZone, "@", "301", "https://shop.example.net/", ""),
				Check: checkGate(g, func() error {
					if f := fwd(g, "@").Forward; f.Type != "301" || f.Title != "" || f.Keywords != "" || f.Description != "" {
						return fmt.Errorf("gate apex forward %+v", f)
					}
					return nil
				}),
			},
			{
				// Drift in the gate: the plan restores the configuration.
				PreConfig: func() {
					g.Mutate(fwdZone, "go", client.TypeURLForward, func(rs *client.RRset) { rs.Forward.URL = "https://elsewhere.example.net/" })
				},
				Config: p + updated,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_url_forward.go", plancheck.ResourceActionUpdate),
				}},
				Check: checkGate(g, func() error {
					if u := fwd(g, "go").Forward.URL; u != "https://example.net/new" {
						return fmt.Errorf("drift not corrected: %s", u)
					}
					return nil
				}),
			},
			{
				// Deleted outside Terraform: created again.
				PreConfig: func() { g.Remove(fwdZone, "go", client.TypeURLForward) },
				Config:    p + updated,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_url_forward.go", plancheck.ResourceActionCreate),
				}},
			},
			{ResourceName: "dnsgate_url_forward.apex", ImportState: true, ImportStateId: "example.org/@", ImportStateVerify: true},
			{ResourceName: "dnsgate_url_forward.go", ImportState: true, ImportStateId: "Example.org./GO", ImportStateVerify: true},
		},
	})
}

func TestFakeURLForward_importIsNoop(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	g.Seed(fwdZone, "eurodns",
		client.RRset{Host: "promo", Type: client.TypeURLForward, Forward: &client.Forward{Type: "frame", URL: "https://promo.example.net/", Title: "Promo"}, Owner: "team-a"})
	cfg := providerConfig(g.URL) + forwardTF("promo", fwdZone, "promo", "frame", "https://promo.example.net/", "  title = \"Promo\"\n")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: cfg + "import {\n  to = dnsgate_url_forward.promo\n  id = \"example.org/promo\"\n}\n",
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_url_forward.promo", plancheck.ResourceActionNoop),
				}},
				Check: checkGate(g, func() error {
					if g.Writes != 0 {
						return fmt.Errorf("the import wrote %d times", g.Writes)
					}
					return nil
				}),
			},
			{Config: cfg, PlanOnly: true},
		},
	})
}

func TestFakeURLForward_refusals(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	g.Seed(fwdZone, "eurodns",
		client.RRset{Host: "mine", Type: client.TypeURLForward, Forward: &client.Forward{Type: "301", URL: "https://mine.example.net/"}, Owner: "team-a"})
	p := providerConfig(g.URL)
	importOf := func(res, id string) string {
		return fmt.Sprintf("import {\n  to = dnsgate_url_forward.%s\n  id = %q\n}\n", res, id)
	}
	redirect := func(res, zone, name string) string {
		return forwardTF(res, zone, name, "301", "https://example.net/", "")
	}
	for _, c := range []struct{ cfg, re string }{
		{redirect("mine", fwdZone, "mine"), `(?s)URL forward already exists.*id = "example.org/mine"`},
		{redirect("legacy", fwdZone, "legacy"), `(?s)URL forward exists outside the gate.*Adopt it.*example.org/legacy`},
		{redirect("r53", testZone, "go"), `(?s)exist only on zones whose DNS provider has them.*has no URL forwards`},
		{redirect("legacy", fwdZone, "legacy") + importOf("legacy", "example.org/legacy"), `URL forward not adopted`},
		{redirect("other", fwdZone, "other") + importOf("other", "example.org/other"), `owned by team "team-b"`},
		{redirect("nope", fwdZone, "nope") + importOf("nope", "example.org/nope"), `URL forward not found`},
		{redirect("bad", fwdZone, "bad") + importOf("bad", "example.org/bad/URLFWD"), `Invalid import id`},
	} {
		resource.UnitTest(t, resource.TestCase{
			ProtoV6ProviderFactories: testProviders,
			Steps:                    []resource.TestStep{{Config: p + c.cfg, ExpectError: regexp.MustCompile(c.re)}},
		})
	}
	if u := fwd(g, "mine").Forward.URL; u != "https://mine.example.net/" {
		t.Fatalf("existing forward overwritten: %s", u)
	}
	if u := fwd(g, "legacy").Forward.URL; u != "https://old.example.net/" {
		t.Fatalf("foreign forward overwritten: %s", u)
	}
}

func TestFakeURLForward_planTimeRefusals(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	p := providerConfig(g.URL)
	for _, c := range []struct{ cfg, re string }{
		{forwardTF("x", fwdZone, "x", "301", "https://example.net/", "  title = \"t\"\n"), `Only frame forwards have title`},
		{forwardTF("x", fwdZone, "x", "302", "https://example.net/", "  description = \"d\"\n"), `Only frame forwards have description`},
		{forwardTF("x", fwdZone, "x", "FRAME", "https://example.net/", ""), `value must be one of`},
		{forwardTF("x", fwdZone, "x", "308", "https://example.net/", ""), `value must be one of`},
		{forwardTF("x", fwdZone, "x", "301", "example.net", ""), `Invalid forward URL`},
		{forwardTF("x", fwdZone, "x", "301", "ftp://example.net/", ""), `Invalid forward URL`},
		{forwardTF("x", fwdZone, "x", "301", " https://example.net/", ""), `remove the spaces`},
		{forwardTF("x", fwdZone, "x", "frame", "https://example.net/", "  title = \" Shop\"\n"), `leading and trailing spaces`},
		{forwardTF("x", fwdZone, "x", "301", "https://user:pw@example.net/", ""), `user name and password`},
		{forwardTF("x", fwdZone, "x", "301", "https://example.net/?q=<x>", ""), `percent-encode`},
		{forwardTF("x", fwdZone, "x", "301", "https://example.net/a%zz", ""), `Invalid forward URL`},
		{forwardTF("x", fwdZone, "x", "301", "https://example.net/"+strings.Repeat("a", 2048), ""), `at most 2048 bytes`},
		{forwardTF("x", fwdZone, "x", "frame", "https://example.net/", "  title = \"<b>Shop</b>\"\n"), `plain text only`},
		{forwardTF("x", fwdZone, "x", "frame", "https://example.net/", "  keywords = \"it's\"\n"), `plain text only`},
		{forwardTF("x", fwdZone, "x", "frame", "https://example.net/", "  title = \"Shop\u202egnp\"\n"), `plain text only`},
		{forwardTF("x", fwdZone, "x", "301", "https://exämple.net/", ""), `punycode: xn--exmple-cua.net`},
		{forwardTF("x", fwdZone, "x", "frame", "https://example.net/", "  title = \""+strings.Repeat("t", 201)+"\"\n"), `at most 200 characters`},
		{forwardTF("x", fwdZone, "go.example.org", "301", "https://example.net/", ""), `write "go"`},
		{forwardTF("x", fwdZone, "Go", "301", "https://example.net/", ""), `Invalid name`},
		{recordSetTF("x", "x", "URLFWD", 300, "x"), `dnsgate_url_forward`},
	} {
		resource.UnitTest(t, resource.TestCase{
			ProtoV6ProviderFactories: testProviders,
			Steps:                    []resource.TestStep{{Config: p + c.cfg, ExpectError: regexp.MustCompile(c.re), PlanOnly: true}},
		})
	}
	if n := noRequests(g, "PUT"); n != 0 {
		t.Fatalf("plan-time refusals must not write, got %d", n)
	}
}

func TestFakeURLForward_requireHTTPS(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	p := providerConfig(g.URL)
	strict := forwardTF("go", fwdZone, "go", "301", "https://example.net/", "  require_https = true\n")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				// Plain HTTP only: refused, nothing written.
				Config:      p + strict,
				ExpectError: regexp.MustCompile(`(?s)answer plain HTTP.*subscription.*https_unavailable`),
			},
			{
				PreConfig: func() {
					if fwd(g, "go") != nil {
						t.Fatal("forward written despite require_https")
					}
					g.SetForwards(fwdZone, true, client.HTTPSActive)
				},
				Config: p + strict,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "require_https", "true"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "https_status", "active"),
				),
			},
			{Config: p + strict, PlanOnly: true},
			{
				// require_https alone: written again (no content change) so
				// that the gate checks HTTPS.
				PreConfig: func() { g.SetForwards(fwdZone, true, client.HTTPSInactive) },
				Config:    p + forwardTF("go", fwdZone, "go", "301", "https://example.net/", ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_url_forward.go", plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "require_https", "false"),
					resource.TestCheckResourceAttr("dnsgate_url_forward.go", "https_status", "inactive"),
				),
			},
			{
				Config:      p + strict,
				ExpectError: regexp.MustCompile(`https_unavailable`),
			},
			{
				// A certificate being issued does not answer HTTPS yet.
				PreConfig:   func() { g.SetForwards(fwdZone, true, client.HTTPSPending) },
				Config:      p + strict,
				ExpectError: regexp.MustCompile(`https_unavailable`),
			},
			{Config: p + forwardTF("go", fwdZone, "go", "301", "https://example.net/", "")},
		},
	})
}

func TestFakeURLForward_team(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t, twoTeams)
	p := providerConfig(g.URL)
	teamFwd := func(team, url string) string {
		return forwardTF("b", fwdZone, "b", "301", url, fmt.Sprintf("  team = %q\n", team))
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: func(*terraform.State) error {
			if fwd(g, "b") != nil {
				return fmt.Errorf("forward left after destroy")
			}
			if _, h := counters(g); h["team-b"] != 3 {
				return fmt.Errorf("team headers %v: create, update and delete are made for team-b", h)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: p + teamFwd("team-b", "https://example.net/"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectKnownValue("dnsgate_url_forward.b", tfjsonpath.New("owner_team"), knownvalue.StringExact("team-b")),
				}},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_url_forward.b", "owner_team", "team-b"),
					checkGate(g, func() error {
						if o := fwd(g, "b").Owner; o != "team-b" {
							return fmt.Errorf("owner %q in the gate", o)
						}
						return nil
					}),
				),
			},
			{
				Config:      p + teamFwd("team-a", "https://example.net/"),
				ExpectError: regexp.MustCompile(`(?s)URL forward owned by another team.*transfer request`),
			},
			{
				Config:      p + teamFwd("team-z", "https://example.net/"),
				ExpectError: regexp.MustCompile(`URL forward owned by another team`),
			},
			{Config: p + teamFwd("team-b", "https://example.net/b")},
		},
	})
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      p + forwardTF("z", fwdZone, "z", "301", "https://example.net/", "  team = \"team-z\"\n"),
			ExpectError: regexp.MustCompile(`Not a member of the team`),
		}},
	})
	if fwd(g, "z") != nil {
		t.Fatal("forward written for a team the identity is not a member of")
	}
}

func TestFakeURLForward_oldGate(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t, func(o *fakegate.Options) { o.Features = []string{client.FeaturePolicyDelegation, featureRRsetAPI} })
	p := providerConfig(g.URL)
	for _, cfg := range []string{
		forwardTF("go", fwdZone, "go", "301", "https://example.net/", ""),
		"data \"dnsgate_url_forward\" \"x\" {\n  zone = \"example.org\"\n  name = \"other\"\n}\n",
	} {
		resource.UnitTest(t, resource.TestCase{
			ProtoV6ProviderFactories: testProviders,
			Steps: []resource.TestStep{{
				Config:      p + cfg,
				ExpectError: regexp.MustCompile(`does not serve the URL forward API`),
			}},
		})
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps:                    []resource.TestStep{{Config: p + recordSetTF("a", "a", "A", 300, "192.0.2.1")}},
	})
}

func TestFakeURLForward_dataSource(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	g.Seed(fwdZone, "eurodns",
		client.RRset{Host: "@", Type: client.TypeURLForward, Forward: &client.Forward{Type: "frame", URL: "https://shop.example.net/", Title: "Shop"}, Owner: "team-a"})
	p := providerConfig(g.URL)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: p + `
data "dnsgate_url_forward" "apex" {
  zone = "example.org"
  name = "@"
}
data "dnsgate_url_forward" "legacy" {
  zone = "example.org."
  name = "Legacy"
}
data "dnsgate_record_sets" "forwards" {
  zone = "example.org"
  type = "URLFWD"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "id", "example.org/@"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "type", "frame"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "url", "https://shop.example.net/"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "title", "Shop"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "keywords", ""),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "owner_team", "team-a"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "status", "managed"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "https_status", "inactive"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.apex", "hash",
						client.ForwardHash(client.Forward{Type: "frame", URL: "https://shop.example.net/", Title: "Shop"})),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.legacy", "id", "example.org/legacy"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.legacy", "type", "302"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.legacy", "status", "foreign"),
					resource.TestCheckResourceAttr("data.dnsgate_url_forward.legacy", "owner_team", ""),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.forwards", "record_sets.#", "3"),
				),
			},
			{
				Config:      p + "data \"dnsgate_url_forward\" \"x\" {\n  zone = \"example.org\"\n  name = \"nope\"\n}\n",
				ExpectError: regexp.MustCompile(`URL forward not found`),
			},
		},
	})
}

func TestFakeURLForward_retriesAndPreconditions(t *testing.T) {
	clearEnv(t)
	g := newForwardGate(t)
	p := providerConfig(g.URL)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				// zone_locked then a lost answer: the retry finds the forward
				// created by the first attempt and reconciles.
				PreConfig: func() {
					g.AddFault(fakegate.Fault{Method: "PUT", Path: "/forwards/a", Status: 423, Reason: client.ReasonZoneLocked, RetryAfter: "1"})
					g.AddFault(fakegate.Fault{Method: "PUT", Path: "/forwards/a", Status: 502, Reason: client.ReasonUpstream, AfterWrite: true})
				},
				Config: p + forwardTF("a", fwdZone, "a", "301", "https://example.net/", ""),
				Check:  resource.TestCheckResourceAttr("dnsgate_url_forward.a", "status", "managed"),
			},
			{
				// Changed between the refresh and the write: 412, no retry.
				PreConfig: func() {
					g.AddFault(fakegate.Fault{Method: "PUT", Path: "/forwards/a", Status: 412, Reason: client.ReasonPrecondition})
				},
				Config:      p + forwardTF("a", fwdZone, "a", "302", "https://example.net/", ""),
				ExpectError: regexp.MustCompile(`URL forward changed outside Terraform`),
			},
			{
				// Tainted: the gate refuses, the reason is explained.
				PreConfig: func() {
					g.Mutate(fwdZone, "a", client.TypeURLForward, func(rs *client.RRset) { rs.Status = client.StatusTainted })
				},
				Config:      p + forwardTF("a", fwdZone, "a", "302", "https://example.net/", ""),
				ExpectError: regexp.MustCompile(`(?s)modified outside the gate.*tainted`),
			},
			{
				PreConfig: func() {
					g.Mutate(fwdZone, "a", client.TypeURLForward, func(rs *client.RRset) { rs.Status = client.StatusManaged })
				},
				Config: p + forwardTF("a", fwdZone, "a", "302", "https://example.net/", ""),
			},
		},
	})
}
