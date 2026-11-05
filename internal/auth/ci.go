package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Azure DevOps job environment.
const (
	EnvADOOIDCRequestURI = "SYSTEM_OIDCREQUESTURI"
	EnvADOAccessToken    = "SYSTEM_ACCESSTOKEN"
	adoOIDCAPIVersion    = "7.1"
)

// GitHub Actions job environment (permissions: id-token: write).
const (
	EnvGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// InAzureDevOpsJob reports whether the process runs in an Azure DevOps job
// able to request OIDC tokens.
func InAzureDevOpsJob() bool { return os.Getenv(EnvADOOIDCRequestURI) != "" }

// InGitHubActionsJob reports whether the process runs in a GitHub Actions job
// allowed to request OIDC tokens.
func InGitHubActionsJob() bool { return os.Getenv(EnvGitHubRequestURL) != "" }

// AzureDevOpsConfig configures the Azure DevOps OIDC token request.
type AzureDevOpsConfig struct {
	ServiceConnectionID string
	RequestURI          string
	AccessToken         string
}

// AzureDevOpsFetch obtains the OIDC token Azure DevOps issues for a service
// connection (issuer https://vstoken.dev.azure.com/<organization id>,
// subject sc://<organization>/<project>/<service connection>).
func AzureDevOpsFetch(cfg AzureDevOpsConfig, client *http.Client) FetchFunc {
	return func(ctx context.Context) (string, time.Time, error) {
		u, err := url.Parse(cfg.RequestURI)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("%s: %w", EnvADOOIDCRequestURI, err)
		}
		q := u.Query()
		q.Set("api-version", adoOIDCAPIVersion)
		q.Set("serviceConnectionId", cfg.ServiceConnectionID)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(nil))
		if err != nil {
			return "", time.Time{}, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-TFS-FedAuthRedirect", "Suppress")
		body, status, err := doSmall(client, req)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("azure devops oidc token: %w", err)
		}
		if status != http.StatusOK {
			return "", time.Time{}, fmt.Errorf("azure devops oidc token for service connection %s: HTTP %d: %s",
				cfg.ServiceConnectionID, status, strings.TrimSpace(string(body)))
		}
		var out struct {
			OIDCToken string `json:"oidcToken"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", time.Time{}, fmt.Errorf("azure devops oidc token: %w", err)
		}
		if out.OIDCToken == "" {
			return "", time.Time{}, errors.New("azure devops returned no oidcToken")
		}
		return out.OIDCToken, time.Time{}, nil
	}
}

// GitHubActionsConfig configures the GitHub Actions OIDC token request.
type GitHubActionsConfig struct {
	Audience     string
	RequestURL   string
	RequestToken string
}

// GitHubActionsFetch obtains the OIDC token GitHub Actions issues for the
// job (issuer https://token.actions.githubusercontent.com) with the gate's
// audience.
func GitHubActionsFetch(cfg GitHubActionsConfig, client *http.Client) FetchFunc {
	return func(ctx context.Context) (string, time.Time, error) {
		u, err := url.Parse(cfg.RequestURL)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("%s: %w", EnvGitHubRequestURL, err)
		}
		q := u.Query()
		q.Set("audience", cfg.Audience)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", time.Time{}, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.RequestToken)
		req.Header.Set("Accept", "application/json")
		body, status, err := doSmall(client, req)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("github actions oidc token: %w", err)
		}
		if status != http.StatusOK {
			return "", time.Time{}, fmt.Errorf("github actions oidc token: HTTP %d: %s", status, strings.TrimSpace(string(body)))
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", time.Time{}, fmt.Errorf("github actions oidc token: %w", err)
		}
		if out.Value == "" {
			return "", time.Time{}, errors.New("github actions returned no token")
		}
		return out.Value, time.Time{}, nil
	}
}

func doSmall(client *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, err
}
