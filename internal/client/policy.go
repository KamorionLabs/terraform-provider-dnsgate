package client

import (
	"context"
	"net/http"
	"net/url"
)

// FeaturePolicyDelegation is advertised by gates that serve the delegation
// API (/api/v1/policy/delegated).
const FeaturePolicyDelegation = "policy-delegation"

// DelegatedPath is the delegation API of the gate.
const DelegatedPath = "/api/v1/policy/delegated"

// Wire types of the delegation API (dns-gate internal/uiapi/policy.go).

type RecordScope struct {
	Hosts []string `json:"hosts,omitempty"`
	Types []string `json:"types,omitempty"`
}

type Rule struct {
	Zones   []string     `json:"zones"`
	Actions []string     `json:"actions"`
	Records *RecordScope `json:"records,omitempty"`
}

type Role struct {
	Description          string `json:"description,omitempty"`
	Rules                []Rule `json:"rules"`
	RebaseOnSave         bool   `json:"rebase_on_save,omitempty"`
	EphemeralTTL         string `json:"ephemeral_ttl,omitempty"`
	MaxChangesPerRequest int    `json:"max_changes_per_request,omitempty"`
}

type TeamFrom struct {
	Claim  string `json:"claim"`
	Regex  string `json:"regex"`
	Prefix string `json:"prefix,omitempty"`
}

type SubjectMatcher struct {
	Issuer string              `json:"issuer"`
	Claims map[string][]string `json:"claims,omitempty"`
}

type Binding struct {
	Role     string           `json:"role"`
	Team     string           `json:"team"`
	TeamFrom *TeamFrom        `json:"team_from,omitempty"`
	Groups   []string         `json:"groups,omitempty"`
	Subjects []SubjectMatcher `json:"subjects,omitempty"`
}

type DelegatedOwner struct {
	Delegation string `json:"delegation"`
	ManagedBy  string `json:"managed_by,omitempty"`
	CreatedBy  string `json:"created_by"`
	UpdatedBy  string `json:"updated_by"`
}

type DelegatedObject struct {
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Role       *Role          `json:"role,omitempty"`
	Binding    *Binding       `json:"binding,omitempty"`
	Owner      DelegatedOwner `json:"owner"`
	ETag       string         `json:"etag"`
	RevisionID string         `json:"revision_id,omitempty"`
}

type ImpactItem struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type DelegatedResult struct {
	Object     *DelegatedObject `json:"object,omitempty"`
	Changed    bool             `json:"changed"`
	RevisionID string           `json:"revision_id"`
	Impact     []ImpactItem     `json:"impact"`
}

// DelegatedRoleRequest is the body of PUT .../roles/{name}.
type DelegatedRoleRequest struct {
	Role
	Delegation string `json:"delegation,omitempty"`
	ManagedBy  string `json:"managed_by,omitempty"`
}

// DelegatedBindingRequest is the body of PUT .../bindings/{name}.
type DelegatedBindingRequest struct {
	Binding
	Delegation string `json:"delegation,omitempty"`
	ManagedBy  string `json:"managed_by,omitempty"`
}

// Kinds of delegated objects.
const (
	KindRole    = "role"
	KindBinding = "binding"
)

func delegatedObjectPath(kind, name string) string {
	return DelegatedPath + "/" + kind + "s/" + url.PathEscape(name)
}

// GetDelegated reads a delegated object; nil when it does not exist (or is
// no longer delegated, for example after a takeover by an administrator).
func (c *Client) GetDelegated(ctx context.Context, kind, name string) (*DelegatedObject, error) {
	var obj DelegatedObject
	_, err := c.do(ctx, http.MethodGet, delegatedObjectPath(kind, name), nil, nil, &obj)
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// PutDelegated creates or replaces a delegated object.
func (c *Client) PutDelegated(ctx context.Context, kind, name string, cond Condition, body any) (*DelegatedResult, error) {
	var res DelegatedResult
	hdr := http.Header{}
	if cond.IfNoneMatch {
		hdr.Set("If-None-Match", "*")
	}
	if cond.IfMatch != "" {
		hdr.Set("If-Match", cond.IfMatch)
	}
	if _, err := c.do(ctx, http.MethodPut, delegatedObjectPath(kind, name), hdr, body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// DeleteDelegated removes a delegated object; a missing object is not an error.
func (c *Client) DeleteDelegated(ctx context.Context, kind, name string) error {
	_, err := c.do(ctx, http.MethodDelete, delegatedObjectPath(kind, name), nil, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}
