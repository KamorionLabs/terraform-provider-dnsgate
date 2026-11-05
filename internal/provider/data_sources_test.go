package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

func TestFakeDataSources(t *testing.T) {
	clearEnv(t)
	g := newGate(t)
	g.Seed("example.org", "eurodns", client.RRset{Host: "@", Type: "A", TTL: 3600, Values: []string{"192.0.2.1"}, Owner: "team-a"})
	g.Seed(testZone, "route53",
		client.RRset{Host: "@", Type: "A", Alias: &client.Alias{Target: "d1.cloudfront.net", HostedZoneID: "Z2FDTNDATAQYW2"}, Owner: "team-a"},
		client.RRset{Host: "_acme-challenge.www", Type: "TXT", TTL: 60, Values: []string{"tok"}, Owner: "team-a"},
	)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: providerConfig(g.URL) + `
data "dnsgate_zones" "all" {}
data "dnsgate_zones" "r53" {
  dns_provider = "route53"
}
data "dnsgate_record_sets" "mine" {
  zone  = "example.com"
  owner = "team-a"
}
data "dnsgate_record_sets" "acme" {
  zone = "example.com"
  name = "_acme-challenge.*"
  type = "txt"
}
data "dnsgate_record_sets" "foreign" {
  zone   = "example.com"
  status = "foreign"
}
data "dnsgate_record_set" "apex" {
  zone = "example.com"
  name = "@"
  type = "A"
}
data "dnsgate_record_set" "other" {
  zone = "example.com"
  name = "other"
  type = "A"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.dnsgate_zones.all", "names.#", "2"),
					resource.TestCheckResourceAttr("data.dnsgate_zones.all", "zones.0.zone", "example.com"),
					resource.TestCheckResourceAttr("data.dnsgate_zones.all", "zones.0.foreign", "1"),
					resource.TestCheckResourceAttr("data.dnsgate_zones.r53", "names.#", "1"),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.mine", "record_sets.#", "2"),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.mine", "record_sets.0.id", "example.com/@/A"),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.mine", "record_sets.0.alias.zone_id", "Z2FDTNDATAQYW2"),
					resource.TestCheckNoResourceAttr("data.dnsgate_record_sets.mine", "record_sets.0.ttl"),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.acme", "record_sets.#", "1"),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.acme", "record_sets.0.values.0", `"tok"`),
					resource.TestCheckResourceAttr("data.dnsgate_record_sets.foreign", "record_sets.0.name", "legacy"),
					resource.TestCheckResourceAttr("data.dnsgate_record_set.apex", "alias.name", "d1.cloudfront.net."),
					resource.TestCheckResourceAttr("data.dnsgate_record_set.other", "owner", "team-b"),
					resource.TestCheckResourceAttr("data.dnsgate_record_set.other", "ttl", "300"),
					resource.TestCheckResourceAttrSet("data.dnsgate_record_set.other", "hash"),
				),
			},
			{
				Config:      providerConfig(g.URL) + `data "dnsgate_record_set" "x" {` + "\n" + `  zone = "example.com"` + "\n" + `  name = "nope"` + "\n" + `  type = "A"` + "\n}\n",
				ExpectError: regexp.MustCompile(`Record set not found`),
			},
		},
	})
}
