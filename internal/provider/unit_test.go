package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/auth"
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

func emptyAuth() *authModel {
	return &authModel{Token: types.StringNull(), TokenFile: types.StringNull(), TokenCommand: types.ListNull(types.StringType)}
}

func cfgWith(a *authModel) providerModel {
	return providerModel{Endpoint: types.StringValue("https://gate.example.com"), MaxRetries: types.Int64Null(), RequestTimeout: types.StringNull(), Auth: a}
}

func testProvider(ci *http.Client) *dnsgateProvider {
	return &dnsgateProvider{version: "test", newSTS: auth.DefaultSTSClient, newAzureCredential: auth.DefaultAzureCredential, ciHTTP: ci}
}

func token(t *testing.T, p *dnsgateProvider, m providerModel) (string, error) {
	t.Helper()
	o, err := p.resolve(context.Background(), m)
	if err != nil {
		return "", err
	}
	return o.Tokens.Token(context.Background())
}

func TestResolveSettings(t *testing.T) {
	clearEnv(t)
	p := testProvider(nil)
	a := emptyAuth()
	a.Token = types.StringValue("t")
	m := cfgWith(a)
	m.MaxRetries, m.RequestTimeout = types.Int64Value(0), types.StringValue("5s")
	o, err := p.resolve(context.Background(), m)
	if err != nil || o.MaxRetries != -1 || o.RequestTimeout.Seconds() != 5 || !strings.HasPrefix(o.UserAgent, "terraform-provider-dnsgate/") {
		t.Fatalf("options %+v, err %v", o, err)
	}
	m.RequestTimeout = types.StringValue("soon")
	if _, err := p.resolve(context.Background(), m); err == nil || !strings.Contains(err.Error(), "request_timeout") {
		t.Fatalf("expected request_timeout error, got %v", err)
	}
	m = cfgWith(a)
	m.Endpoint = types.StringNull()
	if _, err := p.resolve(context.Background(), m); err == nil || !strings.Contains(err.Error(), envEndpoint) {
		t.Fatalf("expected endpoint error, got %v", err)
	}
	t.Setenv(envEndpoint, "https://env.example.com")
	if o, err := p.resolve(context.Background(), m); err != nil || o.BaseURL != "https://env.example.com" {
		t.Fatalf("endpoint from env: %+v %v", o, err)
	}
}

func TestResolveEnvTokens(t *testing.T) {
	clearEnv(t)
	p := testProvider(nil)
	if _, err := token(t, p, cfgWith(nil)); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("expected no credentials, got %v", err)
	}
	t.Setenv(envToken, "env-token")
	if tok, err := token(t, p, cfgWith(nil)); err != nil || tok != "env-token" {
		t.Fatalf("token %q err %v", tok, err)
	}
	t.Setenv(envTokenFile, "/nonexistent")
	if _, err := token(t, p, cfgWith(nil)); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("expected exclusivity error, got %v", err)
	}
}

func TestResolveExclusivity(t *testing.T) {
	clearEnv(t)
	p := testProvider(nil)
	if _, err := token(t, p, cfgWith(emptyAuth())); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected exactly one, got %v", err)
	}
	a := emptyAuth()
	a.Token = types.StringValue("t")
	a.AzureIdentity = &azureIdentityModel{Scope: types.StringValue("s"), TenantID: types.StringNull(), ClientID: types.StringNull()}
	if _, err := token(t, p, cfgWith(a)); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected exactly one, got %v", err)
	}
	a = emptyAuth()
	a.AWSWebIdentity = &awsWebIdentityModel{Audience: types.StringNull(), SigningAlgorithm: types.StringNull(), Region: types.StringNull(), DurationSeconds: types.Int64Null()}
	if _, err := token(t, p, cfgWith(a)); err == nil || !strings.Contains(err.Error(), "audience is required") {
		t.Fatalf("expected audience error, got %v", err)
	}
	a.AWSWebIdentity.Audience, a.AWSWebIdentity.SigningAlgorithm = types.StringValue("dns-gate"), types.StringValue("HS256")
	if _, err := token(t, p, cfgWith(a)); err == nil || !strings.Contains(err.Error(), "RS256 or ES384") {
		t.Fatalf("expected algorithm error, got %v", err)
	}
	a = emptyAuth()
	a.AzureDevOps = &azureDevOpsModel{ServiceConnectionID: types.StringNull()}
	a.GitHubActions = &githubActionsModel{Audience: types.StringValue("x")}
	if _, err := token(t, p, cfgWith(a)); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected CI exclusivity error, got %v", err)
	}
	a = emptyAuth()
	a.TokenCommand = types.ListValueMust(types.StringType, nil)
	a.Token = types.StringValue("t")
	if tok, err := token(t, p, cfgWith(a)); err != nil || tok != "t" {
		t.Fatalf("empty token_command ignored: %q %v", tok, err)
	}
}

func ciServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("serviceConnectionId") == "sc-id" && r.Header.Get("Authorization") == "Bearer job-token":
			_, _ = w.Write([]byte(`{"oidcToken":"ado-token"}`))
		case r.URL.Query().Get("audience") == "dns-gate" && r.Header.Get("Authorization") == "Bearer gha-request":
			_, _ = w.Write([]byte(`{"value":"gha-token"}`))
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveCIMethods(t *testing.T) {
	clearEnv(t)
	srv := ciServer(t)
	p := testProvider(srv.Client())
	withStatic := func(f func(a *authModel)) providerModel {
		a := emptyAuth()
		a.Token = types.StringValue("workstation")
		f(a)
		return cfgWith(a)
	}
	ado := func(a *authModel) { a.AzureDevOps = &azureDevOpsModel{ServiceConnectionID: types.StringNull()} }
	gha := func(a *authModel) { a.GitHubActions = &githubActionsModel{Audience: types.StringValue("dns-gate")} }

	// Outside CI: the other method.
	for _, f := range []func(*authModel){ado, gha} {
		if tok, err := token(t, p, withStatic(f)); err != nil || tok != "workstation" {
			t.Fatalf("outside CI: %q %v", tok, err)
		}
	}
	alone := emptyAuth()
	ado(alone)
	if _, err := token(t, p, cfgWith(alone)); err == nil || !strings.Contains(err.Error(), "only works inside an Azure DevOps job") {
		t.Fatalf("expected outside-a-job error, got %v", err)
	}

	// Inside Azure DevOps.
	t.Setenv(auth.EnvADOOIDCRequestURI, srv.URL+"/oidctoken")
	if _, err := token(t, p, withStatic(ado)); err == nil || !strings.Contains(err.Error(), "service_connection_id is required") {
		t.Fatalf("expected id error, got %v", err)
	}
	t.Setenv(envADOServiceConnectionID, "sc-id")
	if _, err := token(t, p, withStatic(ado)); err == nil || !strings.Contains(err.Error(), auth.EnvADOAccessToken) {
		t.Fatalf("expected access token error, got %v", err)
	}
	t.Setenv(auth.EnvADOAccessToken, "job-token")
	if tok, err := token(t, p, withStatic(ado)); err != nil || tok != "ado-token" {
		t.Fatalf("inside ADO: %q %v", tok, err)
	}

	// Inside GitHub Actions.
	t.Setenv(auth.EnvGitHubRequestURL, srv.URL+"/token")
	if _, err := token(t, p, withStatic(gha)); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("expected request token error, got %v", err)
	}
	t.Setenv(auth.EnvGitHubRequestToken, "gha-request")
	if tok, err := token(t, p, withStatic(gha)); err != nil || tok != "gha-token" {
		t.Fatalf("inside GitHub Actions: %q %v", tok, err)
	}
}

func TestParseRecordSetID(t *testing.T) {
	for id, want := range map[string]string{
		"example.com/www/A":             "example.com|www|A",
		"Example.com./@/mx":             "example.com|@|MX",
		"example.com/*.apps/cname":      "example.com|*.apps|CNAME",
		"example.com/www.example.com/A": "example.com|www|A",
		"example.com/example.com/A":     "example.com|@|A",
	} {
		z, n, ty, ok := parseRecordSetID(id)
		if got := z + "|" + n + "|" + ty; !ok || got != want {
			t.Errorf("%s: %s (ok %v), want %s", id, got, ok, want)
		}
	}
	for _, id := range []string{"example.com/www", "example.com/a.*/A", "example.com/www/A/x", "/www/A", "example.com/www/1A"} {
		if _, _, _, ok := parseRecordSetID(id); ok {
			t.Errorf("%s accepted", id)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{{"*", "a.b", true}, {"_acme-challenge.*", "_acme-challenge.www", true}, {"*.apps", "x.apps", true},
		{"*.apps", "apps", false}, {"w?w", "www", true}, {"@", "@", true}, {"www", "www2", false}} {
		if globMatch(c.p, c.s) != c.ok {
			t.Errorf("globMatch(%q, %q) != %v", c.p, c.s, c.ok)
		}
	}
}

func TestDescribe(t *testing.T) {
	err := &client.APIError{Status: 409, Method: "PUT", Path: "/x", Reason: client.ReasonForeignRRset, Message: "m", Details: []byte(`{"a":1}`), Attempts: 2}
	d := describe(err)
	for _, want := range []string{"Adopt it for your team", "foreign_rrset", "after 2 attempts", "Message: m", `Details: {"a":1}`} {
		if !strings.Contains(d, want) {
			t.Errorf("missing %q in %q", want, d)
		}
	}
	if describe(errors.New("plain")) != "plain" {
		t.Error("plain errors are passed through")
	}
}
