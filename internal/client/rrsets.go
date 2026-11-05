package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeZone lowercases a zone name and strips its trailing dot.
func NormalizeZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

func zonePath(zone string) string {
	return "/api/v1/zones/" + url.PathEscape(NormalizeZone(zone))
}

// RRsetPath is the path of one RRset; host is relative ("@" for the apex,
// "*" wildcards allowed) and escaped as one path segment.
func RRsetPath(zone, host, typ string) string {
	return zonePath(zone) + "/rrsets/" + escapeSegment(host) + "/" + url.PathEscape(strings.ToUpper(typ))
}

// escapeSegment escapes a path segment, "*" included, so that no proxy or
// router reads it as a pattern.
func escapeSegment(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "*", "%2A")
}

// Zones lists the zones the caller can read.
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var zs []Zone
	if _, err := c.do(ctx, http.MethodGet, "/api/v1/zones", nil, nil, &zs); err != nil {
		return nil, err
	}
	return zs, nil
}

// Inventory returns every RRset of a zone with its ownership.
func (c *Client) Inventory(ctx context.Context, zone string) (*Inventory, error) {
	var inv Inventory
	h, err := c.do(ctx, http.MethodGet, zonePath(zone)+"/rrsets", nil, nil, &inv)
	if err != nil {
		return nil, err
	}
	inv.ETag = unquoteETag(h.Get("ETag"))
	return &inv, nil
}

func withETag(s *RRset, h http.Header) *RRset {
	if tag := unquoteETag(h.Get("ETag")); tag != "" {
		s.Hash = tag
	}
	return s
}

// GetRRset reads one RRset. A 404 is returned as an APIError (IsNotFound).
func (c *Client) GetRRset(ctx context.Context, zone, host, typ string) (*RRset, error) {
	var s RRset
	h, err := c.do(ctx, http.MethodGet, RRsetPath(zone, host, typ), nil, nil, &s)
	if err != nil {
		return nil, err
	}
	return withETag(&s, h), nil
}

func condHeader(cond Condition) http.Header {
	hdr := http.Header{}
	if cond.IfNoneMatch {
		hdr.Set("If-None-Match", "*")
	}
	if cond.IfMatch != "" {
		hdr.Set("If-Match", strconv.Quote(cond.IfMatch))
	}
	return hdr
}

// PutRRset creates or replaces one RRset under a precondition and returns
// the RRset as written (Hash from the ETag).
func (c *Client) PutRRset(ctx context.Context, zone, host, typ string, body RRsetBody, cond Condition) (*RRset, error) {
	var s RRset
	h, err := c.do(ctx, http.MethodPut, RRsetPath(zone, host, typ), condHeader(cond), body, &s)
	if err != nil {
		return nil, err
	}
	return withETag(&s, h), nil
}

// DeleteRRset removes one RRset, with If-Match when ifMatch is set.
func (c *Client) DeleteRRset(ctx context.Context, zone, host, typ, ifMatch string) error {
	_, err := c.do(ctx, http.MethodDelete, RRsetPath(zone, host, typ), condHeader(Condition{IfMatch: ifMatch}), nil, nil)
	return err
}
