package provider

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Acceptance tests against a real dns-gate. They run only with TF_ACC=1 and:
//
//	DNSGATE_ENDPOINT   the gate
//	DNSGATE_TOKEN      (or the other provider environment) a token of an identity
//	                   allowed to write in the zone
//	DNSGATE_ACC_ZONE   a zone of the gate where the test may create and delete
//	                   RRsets named tf-acc-<timestamp>
func TestAccLiveRecordSet(t *testing.T) {
	zone := os.Getenv("DNSGATE_ACC_ZONE")
	if os.Getenv("TF_ACC") != "" && (zone == "" || os.Getenv("DNSGATE_ENDPOINT") == "") {
		t.Fatal("TF_ACC needs DNSGATE_ENDPOINT, DNSGATE_ACC_ZONE and credentials (DNSGATE_TOKEN...)")
	}
	name := fmt.Sprintf("tf-acc-%d", time.Now().Unix())
	cfg := func(ttl int, value string) string {
		return fmt.Sprintf(`
data "dnsgate_me" "me" {}

resource "dnsgate_record_set" "acc" {
  zone   = %q
  name   = %q
  type   = "TXT"
  ttl    = %d
  values = [%q]
  team   = data.dnsgate_me.me.default_team
}
`, zone, name, ttl, value)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"dnsgate": providerserver.NewProtocol6WithError(New("acc")()),
		},
		Steps: []resource.TestStep{
			{Config: cfg(300, "dns-gate acceptance "+name), Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("dnsgate_record_set.acc", "status", "managed"),
				resource.TestCheckResourceAttrPair("dnsgate_record_set.acc", "owner_team", "data.dnsgate_me.me", "default_team"),
			)},
			{Config: cfg(600, "dns-gate acceptance "+name+" updated")},
			{ResourceName: "dnsgate_record_set.acc", ImportState: true, ImportStateId: zone + "/" + name + "/TXT", ImportStateVerify: true, ImportStateVerifyIgnore: []string{"values", "team"}},
		},
	})
}
