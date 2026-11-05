package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/auth"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/fakegate"
)

const (
	testZone  = "example.com"
	testToken = "test-token"
)

// testProviders serve the provider with backoff waits skipped.
var testProviders = map[string]func() (tfprotov6.ProviderServer, error){
	"dnsgate": providerserver.NewProtocol6WithError(&dnsgateProvider{
		version: "test", newSTS: auth.DefaultSTSClient, newAzureCredential: auth.DefaultAzureCredential,
		ciHTTP: http.DefaultClient, sleep: func(context.Context, time.Duration) error { return nil },
	}),
}

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		if p, err := exec.LookPath("terraform"); err == nil {
			os.Setenv("TF_ACC_TERRAFORM_PATH", p)
		}
	}
	os.Setenv("CHECKPOINT_DISABLE", "1")
	os.Exit(m.Run())
}

func clearEnv(t *testing.T) {
	for _, k := range []string{envEndpoint, envToken, envTokenFile, envADOServiceConnectionID,
		auth.EnvADOOIDCRequestURI, auth.EnvADOAccessToken, auth.EnvGitHubRequestURL, auth.EnvGitHubRequestToken} {
		t.Setenv(k, "")
	}
}

// newGate starts a fake gate with records owned by team-a, team-b and nobody.
func newGate(t *testing.T, opts ...func(*fakegate.Options)) *fakegate.Server {
	t.Helper()
	o := fakegate.Options{Token: testToken, Teams: []string{"team-a"}}
	for _, f := range opts {
		f(&o)
	}
	g := fakegate.New(o)
	t.Cleanup(g.Close)
	g.Seed(testZone, "route53",
		client.RRset{Host: "legacy", Type: "TXT", TTL: 600, Values: []string{"keep-me"}},
		client.RRset{Host: "other", Type: "A", TTL: 300, Values: []string{"192.0.2.9"}, Owner: "team-b"},
	)
	return g
}

func providerConfig(url string) string {
	return fmt.Sprintf(`
provider "dnsgate" {
  endpoint    = %q
  max_retries = 3
  auth {
    token = %q
  }
}
`, url, testToken)
}

func quoted(values []string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, ", ")
}

func recordSetTF(res, name, typ string, ttl int, values ...string) string {
	return fmt.Sprintf(`
resource "dnsgate_record_set" %q {
  zone   = %q
  name   = %q
  type   = %q
  ttl    = %d
  values = [%s]
}
`, res, testZone, name, typ, ttl, quoted(values))
}

// checkGate runs f under the fake gate lock.
func checkGate(g *fakegate.Server, f func() error) func(*terraform.State) error {
	return func(*terraform.State) error { return f() }
}

func noRequests(g *fakegate.Server, method string) int {
	g.Mu.Lock()
	defer g.Mu.Unlock()
	n := 0
	for k, v := range g.Requests {
		if strings.HasPrefix(k, method+" ") {
			n += v
		}
	}
	return n
}

func newNotGate(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	return srv.URL
}
