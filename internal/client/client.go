// Package client is a small Go client for the REST API of dns-gate:
// discovery, zones, per-RRset reads and conditional writes, and the policy
// delegation API. It retries with backoff on 423 zone_locked, 429, 5xx and
// transport errors, honours Retry-After, bounds every attempt with a
// timeout, and is safe for concurrent use.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// InfoPath is the gate's discovery document.
const InfoPath = "/.well-known/dns-gate"

// TokenSource returns the bearer token sent to the gate.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Options configure a Client.
type Options struct {
	BaseURL string
	Tokens  TokenSource
	// HTTPClient defaults to a pooled client sized for Terraform parallelism.
	HTTPClient *http.Client
	UserAgent  string
	// MaxRetries is the number of retries after the first attempt (default 10).
	MaxRetries int
	// RequestTimeout bounds each attempt (default 60s).
	RequestTimeout time.Duration
	// BaseWait is the first backoff wait, doubled on each retry (default 1s);
	// MaxWait caps one wait, Retry-After included (default 30s).
	BaseWait time.Duration
	MaxWait  time.Duration
	// Sleep is replaced in tests.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client talks to one gate.
type Client struct {
	base *url.URL
	opts Options
	hc   *http.Client
}

// New returns a client. MaxRetries < 0 disables retries.
func New(o Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(o.BaseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint %q: an absolute http(s) URL is expected", o.BaseURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid endpoint %q: http or https expected", o.BaseURL)
	}
	if o.MaxRetries == 0 {
		o.MaxRetries = 10
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 60 * time.Second
	}
	if o.BaseWait <= 0 {
		o.BaseWait = time.Second
	}
	if o.MaxWait <= 0 {
		o.MaxWait = 30 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	hc := o.HTTPClient
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConns = 128
		tr.MaxIdleConnsPerHost = 64
		hc = &http.Client{Transport: tr}
	}
	return &Client{base: u, opts: o, hc: hc}, nil
}

// BaseURL is the gate endpoint.
func (c *Client) BaseURL() string { return c.base.String() }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryable reports whether an answer is worth another attempt.
func retryable(status int, reason string) bool {
	switch {
	case status == http.StatusLocked, status == http.StatusTooManyRequests:
		return true
	case status == http.StatusConflict && reason == ReasonPolicyBusy, reason == ReasonStoreUnavailable:
		return true
	case status >= 500 && status != http.StatusNotImplemented && status != http.StatusHTTPVersionNotSupported:
		return true
	}
	return false
}

// ParseRetryAfter reads delay-seconds or an HTTP date, 0 when absent or invalid.
func ParseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(time.Until(at), 0)
	}
	return 0
}

func (c *Client) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, c.opts.MaxWait)
	}
	d := c.opts.BaseWait << (attempt - 1)
	if d <= 0 || d > c.opts.MaxWait {
		d = c.opts.MaxWait
	}
	return time.Duration(float64(d) * (0.5 + rand.Float64()))
}

// do sends a request with retries and decodes a JSON answer into out. It
// returns the headers of the last answer.
func (c *Client) do(ctx context.Context, method, path string, hdr http.Header, in, out any) (http.Header, error) {
	return c.doAuth(ctx, method, path, hdr, in, out, true)
}

func (c *Client) doAuth(ctx context.Context, method, path string, hdr http.Header, in, out any, authn bool) (http.Header, error) {
	var payload []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	for attempt := 1; ; attempt++ {
		h, status, body, err := c.once(ctx, method, path, hdr, payload, authn)
		if err == nil && status >= 200 && status <= 299 {
			if out != nil && len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, out); err != nil {
					return h, &DecodeError{Method: method, Path: path, Err: err}
				}
			}
			return h, nil
		}
		var apiErr *APIError
		retry := false
		var retryAfter time.Duration
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			var tokErr *tokenError
			if errors.As(err, &tokErr) {
				return nil, err
			}
			retry = isTransient(err)
		} else {
			apiErr = decodeError(method, path, status, body)
			apiErr.Attempts = attempt
			retry = retryable(status, apiErr.Reason)
			retryAfter = ParseRetryAfter(h.Get("Retry-After"))
		}
		if !retry || attempt > c.opts.MaxRetries {
			if apiErr != nil {
				return h, apiErr
			}
			return nil, fmt.Errorf("dns-gate: %s %s: %w", method, path, err)
		}
		d := c.backoff(attempt, retryAfter)
		fields := map[string]any{"method": method, "path": path, "attempt": attempt, "wait": d.String()}
		if apiErr != nil {
			fields["status"], fields["reason"] = apiErr.Status, apiErr.Reason
		} else {
			fields["error"] = err.Error()
		}
		tflog.Warn(ctx, "dns-gate request failed, retrying", fields)
		if serr := c.opts.Sleep(ctx, d); serr != nil {
			last := error(apiErr)
			if apiErr == nil {
				last = err
			}
			return nil, errors.Join(last, fmt.Errorf("stopped retrying %s %s: %w", method, path, serr))
		}
	}
}

// DecodeError is a 2xx answer whose body is not the JSON expected.
type DecodeError struct {
	Method, Path string
	Err          error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("dns-gate: decode %s %s: %v", e.Method, e.Path, e.Err)
}
func (e *DecodeError) Unwrap() error { return e.Err }

type tokenError struct{ err error }

func (e *tokenError) Error() string { return "dns-gate token: " + e.err.Error() }
func (e *tokenError) Unwrap() error { return e.err }

// isTransient: network errors and per-attempt timeouts.
func isTransient(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

func (c *Client) once(ctx context.Context, method, path string, hdr http.Header, payload []byte, authn bool) (http.Header, int, []byte, error) {
	actx, cancel := context.WithTimeout(ctx, c.opts.RequestTimeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(actx, method, c.base.String()+path, body)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.opts.UserAgent != "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if authn && c.opts.Tokens != nil {
		tok, err := c.opts.Tokens.Token(ctx)
		if err != nil {
			return nil, 0, nil, &tokenError{err: err}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, 0, nil, err
	}
	return resp.Header, resp.StatusCode, b, nil
}

func decodeError(method, path string, status int, body []byte) *APIError {
	e := &APIError{Status: status, Method: method, Path: path, Body: string(body)}
	var eb struct {
		Reason  string            `json:"reason"`
		Message string            `json:"message"`
		Details json.RawMessage   `json:"details"`
		Errors  []ValidationError `json:"errors"`
	}
	if json.Unmarshal(body, &eb) == nil {
		e.Reason, e.Message, e.Details, e.Errors = eb.Reason, eb.Message, eb.Details, eb.Errors
	}
	return e
}

// unquoteETag strips W/ and quotes from an ETag.
func unquoteETag(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "W/")
	if s, err := strconv.Unquote(v); err == nil {
		return s
	}
	return strings.Trim(v, `"`)
}

// Info reads the discovery document, without authentication. ErrNotGate
// when the endpoint does not serve one.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	var info Info
	_, err := c.doAuth(ctx, http.MethodGet, InfoPath, nil, nil, &info, false)
	if err != nil {
		if e, ok := AsAPIError(err); ok && (e.Status == http.StatusNotFound || e.Status == http.StatusMethodNotAllowed || e.Status == http.StatusBadRequest) {
			return nil, ErrNotGate
		}
		var de *DecodeError
		if errors.As(err, &de) {
			return nil, ErrNotGate
		}
		return nil, err
	}
	if info.Version == "" && info.Features == nil {
		return nil, ErrNotGate
	}
	return &info, nil
}

// Me returns the identity the gate sees.
func (c *Client) Me(ctx context.Context) (*Me, error) {
	var me Me
	if _, err := c.do(ctx, http.MethodGet, "/api/v1/me", nil, nil, &me); err != nil {
		return nil, err
	}
	return &me, nil
}
