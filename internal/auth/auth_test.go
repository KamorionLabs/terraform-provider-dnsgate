package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func fakeJWT(exp time.Time) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":"x","exp":%d}`, exp.Unix()))) + ".sig"
}

func TestJWTExpiry(t *testing.T) {
	exp := time.Unix(2000000000, 0)
	if got := JWTExpiry(fakeJWT(exp)); !got.Equal(exp) {
		t.Fatalf("got %v", got)
	}
	if got := JWTExpiry("not-a-jwt"); !got.IsZero() {
		t.Fatalf("expected zero, got %v", got)
	}
}

func TestCachingRefetchesBeforeExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	src := NewCaching(func(context.Context) (string, time.Time, error) {
		calls++
		return fmt.Sprintf("tok-%d", calls), now.Add(10 * time.Minute), nil
	})
	src.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if tok, _ := src.Token(ctx); tok != "tok-1" {
			t.Fatalf("got %s", tok)
		}
	}
	now = now.Add(9 * time.Minute)
	if tok, _ := src.Token(ctx); tok != "tok-2" {
		t.Fatalf("expected refresh, got %s", tok)
	}
}

func TestFileTokenIsReReadWhenExpired(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	now := time.Now()
	if err := os.WriteFile(f, []byte(fakeJWT(now.Add(time.Minute))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := NewCaching(FileFetch(f))
	first, err := src.Token(context.Background())
	if err != nil || strings.HasSuffix(first, "\n") {
		t.Fatalf("token %q, err %v", first, err)
	}
	second := fakeJWT(now.Add(time.Hour))
	if err := os.WriteFile(f, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, _ := src.Token(context.Background()); tok != second {
		t.Fatal("rotated token not picked up")
	}
}

func TestCommandToken(t *testing.T) {
	src := NewCaching(CommandFetch([]string{"sh", "-c", "echo cmd-token"}))
	if tok, err := src.Token(context.Background()); err != nil || tok != "cmd-token" {
		t.Fatalf("token %q, err %v", tok, err)
	}
	bad := NewCaching(CommandFetch([]string{"sh", "-c", "echo boom >&2; exit 3"}))
	if _, err := bad.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

type fakeSTS struct {
	in  *sts.GetWebIdentityTokenInput
	exp time.Time
}

func (f *fakeSTS) GetWebIdentityToken(_ context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.in = in
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String("aws-jwt"), Expiration: &f.exp}, nil
}

func TestAWSWebIdentityToken(t *testing.T) {
	fake := &fakeSTS{exp: time.Now().Add(time.Hour)}
	src := NewCaching(AWSWebIdentityFetch(
		AWSWebIdentityConfig{Audience: "dns-gate", SigningAlgorithm: "ES384", DurationSeconds: 900},
		func(context.Context) (STSTokenAPI, error) { return fake, nil },
	))
	tok, err := src.Token(context.Background())
	if err != nil || tok != "aws-jwt" {
		t.Fatalf("token %q, err %v", tok, err)
	}
	if fake.in.Audience[0] != "dns-gate" || *fake.in.SigningAlgorithm != "ES384" || *fake.in.DurationSeconds != 900 {
		t.Fatalf("unexpected input %+v", fake.in)
	}
}

type fakeAzureCredential struct {
	calls int
	opts  policy.TokenRequestOptions
	exp   time.Time
	err   error
}

func (f *fakeAzureCredential) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	f.opts = o
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "entra-token", ExpiresOn: f.exp}, nil
}

func TestAzureIdentityToken(t *testing.T) {
	fake := &fakeAzureCredential{exp: time.Now().Add(time.Hour)}
	var got AzureIdentityConfig
	src := NewCaching(AzureFetch(
		AzureIdentityConfig{Scope: "api://dns-gate/.default", TenantID: "tenant", ClientID: "client"},
		func(c AzureIdentityConfig) (azcore.TokenCredential, error) { got = c; return fake, nil },
	))
	for i := 0; i < 3; i++ {
		if tok, err := src.Token(context.Background()); err != nil || tok != "entra-token" {
			t.Fatalf("token %q, err %v", tok, err)
		}
	}
	if fake.calls != 1 || fake.opts.Scopes[0] != "api://dns-gate/.default" || fake.opts.TenantID != "tenant" || got.ClientID != "client" {
		t.Fatalf("calls %d, request %+v / %+v", fake.calls, fake.opts, got)
	}
	fake.err = errors.New("no credential")
	src = NewCaching(AzureFetch(AzureIdentityConfig{Scope: "s"}, func(AzureIdentityConfig) (azcore.TokenCredential, error) { return fake, nil }))
	if _, err := src.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Fatalf("expected credential error, got %v", err)
	}
}

func TestAzureDevOpsToken(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Query().Get("api-version") != adoOIDCAPIVersion || r.URL.Query().Get("serviceConnectionId") != "sc-id" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer job-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"oidcToken":"ado-token"}`))
	}))
	defer srv.Close()
	src := NewCaching(AzureDevOpsFetch(AzureDevOpsConfig{ServiceConnectionID: "sc-id", RequestURI: srv.URL + "/oidctoken", AccessToken: "job-token"}, srv.Client()))
	for i := 0; i < 2; i++ {
		if tok, err := src.Token(context.Background()); err != nil || tok != "ado-token" {
			t.Fatalf("token %q, err %v", tok, err)
		}
	}
	if calls != 1 {
		t.Fatalf("token not cached: %d calls", calls)
	}
	bad := NewCaching(AzureDevOpsFetch(AzureDevOpsConfig{ServiceConnectionID: "sc-id", RequestURI: srv.URL, AccessToken: "wrong"}, srv.Client()))
	if _, err := bad.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected HTTP 401, got %v", err)
	}
}

func TestGitHubActionsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("audience") != "dns-gate" || r.URL.Query().Get("x") != "1" || r.Header.Get("Authorization") != "Bearer req-token" {
			http.Error(w, "bad request "+r.URL.String(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"value":"gha-token"}`))
	}))
	defer srv.Close()
	src := NewCaching(GitHubActionsFetch(GitHubActionsConfig{Audience: "dns-gate", RequestURL: srv.URL + "/token?x=1", RequestToken: "req-token"}, srv.Client()))
	if tok, err := src.Token(context.Background()); err != nil || tok != "gha-token" {
		t.Fatalf("token %q, err %v", tok, err)
	}
	bad := NewCaching(GitHubActionsFetch(GitHubActionsConfig{Audience: "other", RequestURL: srv.URL, RequestToken: "req-token"}, srv.Client()))
	if _, err := bad.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected HTTP 400, got %v", err)
	}
}
