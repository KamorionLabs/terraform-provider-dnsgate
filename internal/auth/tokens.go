// Package auth obtains the bearer tokens the provider sends to dns-gate:
// static tokens, token files, token commands, AWS STS web identity tokens
// (IAM outbound identity federation), Microsoft Entra ID tokens, and the
// OIDC tokens of CI systems (Azure DevOps, GitHub Actions).
package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TokenSource returns a bearer token, renewed as needed. Safe for concurrent use.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// RefreshMargin renews a token this long before it expires.
const RefreshMargin = 2 * time.Minute

// defaultTokenLifetime is used when a token carries no readable exp claim.
const defaultTokenLifetime = 5 * time.Minute

// FetchFunc obtains a fresh token and, when known, its expiry.
type FetchFunc func(ctx context.Context) (token string, expiry time.Time, err error)

// Caching is a TokenSource that calls its FetchFunc again shortly before the
// token expires (expiry from the fetch, else the exp claim of a JWT, else
// five minutes).
type Caching struct {
	fetch  FetchFunc
	now    func() time.Time
	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewCaching returns a caching TokenSource.
func NewCaching(f FetchFunc) *Caching { return &Caching{fetch: f, now: time.Now} }

// Token implements TokenSource.
func (c *Caching) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Add(RefreshMargin).Before(c.expiry) {
		return c.token, nil
	}
	tok, exp, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", errors.New("empty token")
	}
	if exp.IsZero() {
		exp = JWTExpiry(tok)
	}
	if exp.IsZero() {
		exp = c.now().Add(defaultTokenLifetime)
	}
	c.token, c.expiry = tok, exp
	return tok, nil
}

// JWTExpiry reads the exp claim without verifying the signature (the gate
// verifies it); zero if the token is not a readable JWT.
func JWTExpiry(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}
	}
	sec, err := claims.Exp.Int64()
	if err != nil || sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// Static is a fixed token.
type Static string

// Token implements TokenSource.
func (s Static) Token(context.Context) (string, error) { return strings.TrimSpace(string(s)), nil }

// FileFetch reads the token from a file, re-read on every fetch (projected
// Kubernetes tokens, CI OIDC token files).
func FileFetch(path string) FetchFunc {
	return func(context.Context) (string, time.Time, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("read token file: %w", err)
		}
		return string(b), time.Time{}, nil
	}
}

// CommandFetch runs argv and reads the token on its standard output.
func CommandFetch(argv []string) FetchFunc {
	return func(ctx context.Context) (string, time.Time, error) {
		if len(argv) == 0 {
			return "", time.Time{}, errors.New("empty token command")
		}
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return "", time.Time{}, fmt.Errorf("token command %q: %w: %s", argv[0], err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), time.Time{}, nil
	}
}
