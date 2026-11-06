package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// FeatureForwards is advertised by gates that serve the URL forward API
// (/api/v1/zones/{zone}/forwards).
const FeatureForwards = "forwards"

// TypeURLForward is the RRset type of the URL forward of a host in the
// gate inventory. It is never a DNS record type.
const TypeURLForward = "URLFWD"

// Forward types.
const (
	ForwardPermanent = "301"
	ForwardTemporary = "302"
	ForwardFrame     = "frame"
)

// ForwardTypes are the forward types, in display order.
var ForwardTypes = []string{ForwardPermanent, ForwardTemporary, ForwardFrame}

// HTTPS statuses of the forwards of a zone (HTTPSRedirect.Status).
const (
	HTTPSActive      = "active"
	HTTPSPending     = "pending"
	HTTPSNoForward   = "no_forward"
	HTTPSInactive    = "inactive"
	HTTPSUnsupported = "unsupported"
	HTTPSUnknown     = "unknown"
)

// Reasons of the URL forward API.
const (
	ReasonInvalidForward   = "invalid_forward"
	ReasonHTTPSUnavailable = "https_unavailable"
)

// Forward is the URL forward of a host: a 301 or 302 redirect to URL, or a
// frame showing it. Title, Keywords and Description only apply to frames.
type Forward struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Title       string `json:"title,omitempty"`
	Keywords    string `json:"keywords,omitempty"`
	Description string `json:"description,omitempty"`
}

// HTTPSRedirect tells whether the forwards of a zone answer HTTPS requests.
type HTTPSRedirect struct {
	Status       string `json:"status"`
	Subscription string `json:"subscription,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Message      string `json:"message,omitempty"`
}

// AnswersHTTPS reports whether require_https is accepted with this status.
func (h *HTTPSRedirect) AnswersHTTPS() bool {
	return h != nil && (h.Status == HTTPSActive || h.Status == HTTPSNoForward)
}

// ForwardView is GET /api/v1/zones/{zone}/forwards/{host}: the forward as an
// RRset of type URLFWD with its ownership, and the HTTPS status of the
// forwards of the zone.
type ForwardView struct {
	RRset
	HTTPS *HTTPSRedirect `json:"https,omitempty"`
}

// ForwardList is GET /api/v1/zones/{zone}/forwards.
type ForwardList struct {
	Zone     string         `json:"zone"`
	HTTPS    *HTTPSRedirect `json:"https,omitempty"`
	Forwards []RRset        `json:"forwards"`
}

// ForwardBody is the body of PUT /api/v1/zones/{zone}/forwards/{host}.
// RequireHTTPS refuses the write (409 https_unavailable) unless the
// forwards of the zone answer HTTPS; the gate does not store it.
type ForwardBody struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	Title        string `json:"title,omitempty"`
	Keywords     string `json:"keywords,omitempty"`
	Description  string `json:"description,omitempty"`
	RequireHTTPS bool   `json:"require_https"`
}

// Forward returns the forward of the body.
func (b ForwardBody) Forward() Forward {
	return Forward{Type: b.Type, URL: b.URL, Title: b.Title, Keywords: b.Keywords, Description: b.Description}
}

// ForwardHash is the content hash (ETag) of a forward, as the gate computes
// it: the RRset hash of TTL 0 and the single value
// "forward <type> <n>:<url> <n>:<title> <n>:<keywords> <n>:<description>",
// n being the length in bytes of the field that follows.
func ForwardHash(f Forward) string {
	var b strings.Builder
	b.WriteString("forward " + strings.ToLower(f.Type))
	for _, v := range []string{f.URL, f.Title, f.Keywords, f.Description} {
		fmt.Fprintf(&b, " %d:%s", len(v), v)
	}
	v := b.String()
	h := sha256.New()
	fmt.Fprintf(h, "ttl=0\n%d:%s\n", len(v), v)
	return hex.EncodeToString(h.Sum(nil))
}

// ForwardPath is the path of the forward of a host ("@" for the apex).
func ForwardPath(zone, host string) string {
	return zonePath(zone) + "/forwards/" + escapeSegment(host)
}

// ListForwards returns the URL forwards of a zone with their ownership.
func (c *Client) ListForwards(ctx context.Context, zone string) (*ForwardList, error) {
	var l ForwardList
	if _, err := c.do(ctx, http.MethodGet, zonePath(zone)+"/forwards", nil, nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// GetForward reads the forward of a host. A 404 is returned as an APIError
// (IsNotFound).
func (c *Client) GetForward(ctx context.Context, zone, host string) (*ForwardView, error) {
	var v ForwardView
	h, err := c.do(ctx, http.MethodGet, ForwardPath(zone, host), nil, nil, &v)
	if err != nil {
		return nil, err
	}
	withETag(&v.RRset, h)
	return &v, nil
}

// PutForward creates or replaces the forward of a host under a precondition
// and returns it as written (Hash from the ETag).
func (c *Client) PutForward(ctx context.Context, zone, host string, body ForwardBody, cond Condition) (*ForwardView, error) {
	var v ForwardView
	h, err := c.do(ctx, http.MethodPut, ForwardPath(zone, host), condHeader(cond), body, &v)
	if err != nil {
		return nil, err
	}
	withETag(&v.RRset, h)
	return &v, nil
}

// DeleteForward removes the forward of a host under a precondition (If-Match
// only). Deleting a forward that does not exist succeeds.
func (c *Client) DeleteForward(ctx context.Context, zone, host string, cond Condition) error {
	cond.IfNoneMatch = false
	_, err := c.do(ctx, http.MethodDelete, ForwardPath(zone, host), condHeader(cond), nil, nil)
	return err
}
