package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

var dkim = "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 8)

func TestFakeRecordSet_lifecycle(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	p := providerConfig(g.URL)
	base := recordSetTF("cname", "www", "CNAME", 300, "Target.Example.net") +
		recordSetTF("dkim", "s1._domainkey", "TXT", 300, dkim) +
		recordSetTF("mx", "@", "MX", 3600, "10 mx1.example.net", "20 mx2.example.net.") +
		recordSetTF("wild", "*.apps", "A", 60, "192.0.2.1")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		CheckDestroy: func(*terraform.State) error {
			for _, k := range [][2]string{{"www", "CNAME"}, {"s1._domainkey", "TXT"}, {"@", "MX"}, {"*.apps", "A"}} {
				if g.Get(testZone, k[0], k[1]) != nil {
					return fmt.Errorf("%s %s left after destroy", k[0], k[1])
				}
			}
			if g.Get(testZone, "legacy", "TXT") == nil || g.Get(testZone, "other", "A") == nil {
				return fmt.Errorf("records of others were deleted")
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				// The gate stores canonical forms ("target.example.net.", TXT split in
				// 255-byte strings): the plan after apply must be empty.
				Config: p + base,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_record_set.cname", "id", "example.com/www/CNAME"),
					resource.TestCheckResourceAttr("dnsgate_record_set.cname", "owner", "team-a"),
					resource.TestCheckResourceAttr("dnsgate_record_set.cname", "status", "managed"),
					resource.TestCheckTypeSetElemAttr("dnsgate_record_set.cname", "values.*", "Target.Example.net"),
					resource.TestCheckTypeSetElemAttr("dnsgate_record_set.dkim", "values.*", dkim),
					checkGate(g, func() error {
						if v := g.Get(testZone, "www", "CNAME").Values[0]; v != "Target.Example.net." {
							return fmt.Errorf("gate value %q", v)
						}
						if v := g.Get(testZone, "s1._domainkey", "TXT").Values[0]; !strings.HasPrefix(v, `"v=DKIM1`) || !strings.Contains(v, `" "`) {
							return fmt.Errorf("DKIM not chunked by the gate: %q", v)
						}
						if g.IfNoneMatch != 4 {
							return fmt.Errorf("creates without If-None-Match: %d", g.IfNoneMatch)
						}
						return nil
					}),
				),
			},
			{
				// Same records written another way: no change.
				Config: p + recordSetTF("cname", "www", "CNAME", 300, "target.example.net.") +
					recordSetTF("dkim", "s1._domainkey", "TXT", 300, `"`+dkim[:100]+`" "`+dkim[100:]+`"`) +
					recordSetTF("mx", "@", "MX", 3600, "20 MX2.example.net", "10 mx1.example.net.") +
					recordSetTF("wild", "*.apps", "A", 60, "192.0.2.1"),
				PlanOnly: true,
			},
			{
				// In-place update with If-Match.
				Config: p + strings.Replace(base, "ttl    = 60", "ttl    = 120", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.wild", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction("dnsgate_record_set.cname", plancheck.ResourceActionNoop),
				}},
				Check: checkGate(g, func() error {
					if rs := g.Get(testZone, "*.apps", "A"); rs.TTL != 120 || g.IfMatch != 1 {
						return fmt.Errorf("ttl %d, If-Match %d", rs.TTL, g.IfMatch)
					}
					return nil
				}),
			},
			{
				// Drift in the gate: the plan restores the configuration.
				PreConfig: func() {
					g.Mutate(testZone, "*.apps", "A", func(rs *client.RRset) { rs.Values = []string{"192.0.2.66"} })
				},
				Config: p + strings.Replace(base, "ttl    = 60", "ttl    = 120", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.wild", plancheck.ResourceActionUpdate),
				}},
				Check: checkGate(g, func() error {
					if v := g.Get(testZone, "*.apps", "A").Values; len(v) != 1 || v[0] != "192.0.2.1" {
						return fmt.Errorf("drift not corrected: %v", v)
					}
					return nil
				}),
			},
			{
				// Deleted outside Terraform: created again.
				PreConfig: func() { g.Remove(testZone, "@", "MX") },
				Config:    p + strings.Replace(base, "ttl    = 60", "ttl    = 120", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.mx", plancheck.ResourceActionCreate),
				}},
			},
			{
				ResourceName: "dnsgate_record_set.wild", ImportState: true, ImportStateId: "example.com/*.apps/A", ImportStateVerify: true,
			},
		},
	})
}

func TestFakeRecordSet_alias(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	p := providerConfig(g.URL)
	alias := func(name string, eth bool) string {
		return fmt.Sprintf(`
resource "dnsgate_record_set" "apex" {
  zone = %q
  name = "@"
  type = "A"
  alias {
    name                   = %q
    zone_id                = "Z2FDTNDATAQYW2"
    evaluate_target_health = %t
  }
}
`, testZone, name, eth)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: p + alias("d3rhbu34z338e9.CloudFront.net", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("dnsgate_record_set.apex", "alias.name", "d3rhbu34z338e9.CloudFront.net"),
					resource.TestCheckNoResourceAttr("dnsgate_record_set.apex", "ttl"),
					resource.TestCheckNoResourceAttr("dnsgate_record_set.apex", "values"),
					checkGate(g, func() error {
						rs := g.Get(testZone, "@", "A")
						if rs.Alias == nil || rs.Alias.Target != "d3rhbu34z338e9.cloudfront.net." {
							return fmt.Errorf("gate alias %+v", rs.Alias)
						}
						return nil
					}),
				),
			},
			{Config: p + alias("d3rhbu34z338e9.cloudfront.net.", false), PlanOnly: true},
			{
				Config: p + alias("d3rhbu34z338e9.cloudfront.net", true),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.apex", plancheck.ResourceActionUpdate),
				}},
			},
			{
				// Alias to values in place.
				Config: p + recordSetTF("apex", "@", "A", 300, "192.0.2.10"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("dnsgate_record_set.apex", plancheck.ResourceActionUpdate),
				}},
				Check: checkGate(g, func() error {
					if rs := g.Get(testZone, "@", "A"); rs.Alias != nil || rs.TTL != 300 {
						return fmt.Errorf("gate %+v", rs)
					}
					return nil
				}),
			},
		},
	})
}

// TestFakeRecordSet_migrationImportIsNoop is the migration path from
// aws_route53_record: RRsets adopted for the team in the gate, imported with
// import blocks from a configuration written in the AWS provider's style.
// The first plan shows only imports, no changes.
func TestFakeRecordSet_migrationImportIsNoop(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	g.Seed(testZone, "route53",
		client.RRset{Host: "www", Type: "CNAME", TTL: 300, Values: []string{"front.example.net."}, Owner: "team-a"},
		client.RRset{Host: "s1._domainkey", Type: "TXT", TTL: 300, Values: []string{dkim}, Owner: "team-a"},
		client.RRset{Host: "_dmarc", Type: "TXT", TTL: 300, Values: []string{"v=DMARC1; p=none"}, Owner: "team-a"},
		client.RRset{Host: "@", Type: "MX", TTL: 3600, Values: []string{"10 mx1.example.net.", "20 mx2.example.net."}, Owner: "team-a"},
		client.RRset{Host: "@", Type: "A", Alias: &client.Alias{Target: "d3rhbu34z338e9.cloudfront.net", HostedZoneID: "Z2FDTNDATAQYW2"}, Owner: "team-a"},
	)
	split := dkim[:255] + `""` + dkim[255:]
	cfg := providerConfig(g.URL) +
		recordSetTF("www", "www", "CNAME", 300, "front.example.net") +
		recordSetTF("dkim", "s1._domainkey", "TXT", 300, split) +
		recordSetTF("dmarc", "_dmarc", "TXT", 300, "v=DMARC1; p=none") +
		recordSetTF("mx", "@", "MX", 3600, "10 mx1.example.net", "20 mx2.example.net") + `
resource "dnsgate_record_set" "apex" {
  zone = "example.com"
  name = "@"
  type = "A"
  alias {
    name                   = "d3rhbu34z338e9.cloudfront.net"
    zone_id                = "Z2FDTNDATAQYW2"
    evaluate_target_health = false
  }
}
`
	var imports, checks []string
	for res, id := range map[string]string{"www": "www/CNAME", "dkim": "s1._domainkey/TXT", "dmarc": "_dmarc/TXT", "mx": "@/MX", "apex": "@/A"} {
		imports = append(imports, fmt.Sprintf("import {\n  to = dnsgate_record_set.%s\n  id = \"example.com/%s\"\n}\n", res, id))
		checks = append(checks, "dnsgate_record_set."+res)
	}
	var pc []plancheck.PlanCheck
	for _, addr := range checks {
		pc = append(pc, plancheck.ExpectResourceAction(addr, plancheck.ResourceActionNoop))
	}
	writes := 0
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config:           cfg + strings.Join(imports, "\n"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: pc},
				Check: checkGate(g, func() error {
					writes = g.Writes
					if writes != 0 {
						return fmt.Errorf("the import wrote %d RRsets", writes)
					}
					return nil
				}),
			},
			{Config: cfg, PlanOnly: true},
		},
	})
}

func TestFakeRecordSet_importRefusals(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	p := providerConfig(g.URL)
	for _, c := range []struct{ cfg, re string }{
		{recordSetTF("legacy", "legacy", "TXT", 600, "keep-me") + `import {
  to = dnsgate_record_set.legacy
  id = "example.com/legacy/TXT"
}`, `Record set not adopted`},
		{recordSetTF("other", "other", "A", 300, "192.0.2.9") + `import {
  to = dnsgate_record_set.other
  id = "example.com/other/A"
}`, `owned by team "team-b"`},
		{recordSetTF("nope", "nope", "A", 300, "192.0.2.9") + `import {
  to = dnsgate_record_set.nope
  id = "example.com/nope/A"
}`, `Record set not found`},
		{recordSetTF("bad", "bad", "A", 300, "192.0.2.9") + `import {
  to = dnsgate_record_set.bad
  id = "example.com/bad"
}`, `Invalid import id`},
	} {
		resource.UnitTest(t, resource.TestCase{
			ProtoV6ProviderFactories: testProviders,
			Steps:                    []resource.TestStep{{Config: p + c.cfg, ExpectError: regexp.MustCompile(c.re)}},
		})
	}
}

func TestFakeRecordSet_createRefusals(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	g.Seed(testZone, "route53", client.RRset{Host: "mine", Type: "A", TTL: 300, Values: []string{"192.0.2.7"}, Owner: "team-a"})
	p := providerConfig(g.URL)
	for _, c := range []struct{ cfg, re string }{
		{recordSetTF("mine", "mine", "A", 300, "192.0.2.8"), `(?s)already exists.*id = "example.com/mine/A"`},
		{recordSetTF("legacy", "legacy", "TXT", 300, "x"), `already exists in zone example.com`},
	} {
		resource.UnitTest(t, resource.TestCase{
			ProtoV6ProviderFactories: testProviders,
			Steps:                    []resource.TestStep{{Config: p + c.cfg, ExpectError: regexp.MustCompile(c.re)}},
		})
	}
	if v := g.Get(testZone, "mine", "A").Values[0]; v != "192.0.2.7" {
		t.Fatalf("existing RRset overwritten: %s", v)
	}
}

func TestFakeRecordSet_retriesAndPreconditions(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	p := providerConfig(g.URL)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				// zone_locked then a lost answer: the retry finds the RRset
				// created by the first attempt and reconciles.
				PreConfig: func() {
					g.AddFault(fakegate.Fault{Method: "PUT", Path: "/rrsets/a/A", Status: 423, Reason: client.ReasonZoneLocked, RetryAfter: "1"})
					g.AddFault(fakegate.Fault{Method: "PUT", Path: "/rrsets/a/A", Status: 502, Reason: client.ReasonUpstream, AfterWrite: true})
				},
				Config: p + recordSetTF("a", "a", "A", 300, "192.0.2.1"),
				Check:  resource.TestCheckResourceAttr("dnsgate_record_set.a", "status", "managed"),
			},
			{
				// Changed between the refresh and the write: 412, no retry.
				PreConfig: func() {
					g.AddFault(fakegate.Fault{Method: "PUT", Path: "/rrsets/a/A", Status: 412, Reason: client.ReasonPrecondition})
				},
				Config:      p + recordSetTF("a", "a", "A", 300, "192.0.2.2"),
				ExpectError: regexp.MustCompile(`changed in the gate since Terraform read it`),
			},
			{
				// Tainted: the gate refuses, the reason is explained.
				PreConfig: func() {
					g.Mutate(testZone, "a", "A", func(rs *client.RRset) { rs.Status = client.StatusTainted })
				},
				Config:      p + recordSetTF("a", "a", "A", 300, "192.0.2.3"),
				ExpectError: regexp.MustCompile(`(?s)modified outside the gate.*tainted`),
			},
			{
				PreConfig: func() {
					g.Mutate(testZone, "a", "A", func(rs *client.RRset) { rs.Status = client.StatusManaged })
				},
				Config: p + recordSetTF("a", "a", "A", 300, "192.0.2.3"),
			},
		},
	})
}

func TestFakeRecordSet_planTimeRefusals(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	p := providerConfig(g.URL)
	aliasAndValues := `
resource "dnsgate_record_set" "x" {
  zone   = "example.com"
  name   = "x"
  type   = "A"
  values = ["192.0.2.1"]
  alias {
    name                   = "d.cloudfront.net"
    zone_id                = "Z2FDTNDATAQYW2"
    evaluate_target_health = false
  }
}`
	noTTL := `
resource "dnsgate_record_set" "x" {
  zone   = "example.com"
  name   = "x"
  type   = "A"
  values = ["192.0.2.1"]
}`
	for _, c := range []struct{ cfg, re string }{
		{recordSetTF("fqdn", "www.example.com", "A", 300, "192.0.2.1"), `write "www"`},
		{recordSetTF("dot", "www.", "A", 300, "192.0.2.1"), `Invalid name`},
		{recordSetTF("upper", "WWW", "A", 300, "192.0.2.1"), `Invalid name`},
		{recordSetTF("wild", "a.*", "A", 300, "192.0.2.1"), `only as the first label`},
		{recordSetTF("soa", "@", "SOA", 300, "ns. host. 1 2 3 4 5"), `SOA record`},
		{recordSetTF("lower", "x", "a", 300, "192.0.2.1"), `Invalid record type`},
		{aliasAndValues, `Conflicting record data`},
		{noTTL, `ttl is required`},
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

func TestFakeProvider_detection(t *testing.T) {
	clearEnv(t)
	old := newGate(t, func(o *fakegate.Options) { o.Features = []string{client.FeaturePolicyDelegation} })
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      providerConfig(old.URL) + recordSetTF("a", "a", "A", 300, "192.0.2.1"),
			ExpectError: regexp.MustCompile(`does not serve the RRset API`),
		}},
	})
	notGate := newNotGate(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      providerConfig(notGate) + recordSetTF("a", "a", "A", 300, "192.0.2.1"),
			ExpectError: regexp.MustCompile(`Not a dns-gate`),
		}},
	})
	g := newGate(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      strings.Replace(providerConfig(g.URL), testToken, "wrong", 1) + recordSetTF("a", "a", "A", 300, "192.0.2.1"),
			ExpectError: regexp.MustCompile(`did not accept the token`),
		}},
	})
}
