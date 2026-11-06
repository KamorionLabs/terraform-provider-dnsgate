package provider

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// Same syntax as the gate (internal/server/rrsetapi.go).
var (
	typeRe  = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}$`)
	labelRe = regexp.MustCompile(`^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)$`)
	zoneRe  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)
)

// validName checks a host relative to the zone: "@" for the apex, lowercase
// labels, "*" only as the first label. It returns the problem, "" if valid.
func validName(name string) string {
	if name == "@" {
		return ""
	}
	if name == "" || len(name) > 253 || strings.HasSuffix(name, ".") || name != strings.ToLower(name) {
		return "use a lowercase name relative to the zone, without trailing dot, or @ for the apex"
	}
	for i, l := range strings.Split(name, ".") {
		if !labelRe.MatchString(l) || (l == "*" && i != 0) {
			return "each label is [a-z0-9_-] (at most 63 characters), and * is allowed only as the first label"
		}
	}
	return ""
}

type nameValidator struct{}

func (nameValidator) Description(context.Context) string {
	return "lowercase name relative to the zone, @ for the apex, * only as the first label"
}
func (v nameValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (nameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if problem := validName(v); problem != "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid name", fmt.Sprintf("%q: %s.", v, problem))
	}
}

type zoneValidator struct{}

func (zoneValidator) Description(context.Context) string {
	return "lowercase zone name without trailing dot"
}
func (v zoneValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (zoneValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if !zoneRe.MatchString(v) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid zone name",
			fmt.Sprintf("Use the lowercase zone name without trailing dot, for example %q.", strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")))
	}
}

type typeValidator struct{}

func (typeValidator) Description(context.Context) string {
	return "uppercase record type, not SOA nor URLFWD"
}
func (v typeValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (typeValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	switch {
	case !typeRe.MatchString(v):
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid record type", fmt.Sprintf("%q: use the uppercase record type, for example \"A\" or \"TXT\".", v))
	case v == "SOA":
		resp.Diagnostics.AddAttributeError(req.Path, "Record set cannot be managed", "The SOA record is managed by the DNS provider and cannot be managed through the gate.")
	case v == client.TypeURLForward:
		resp.Diagnostics.AddAttributeError(req.Path, "Record set cannot be managed", "URLFWD is the URL forward of a host, not a DNS record type: manage it with the dnsgate_url_forward resource.")
	}
}

// validForwardURL checks a forward target as the gate does: an absolute
// http:// or https:// URL without spaces. It returns the problem, "" if valid.
func validForwardURL(v string) string {
	u, err := url.Parse(v)
	switch {
	case strings.ContainsAny(v, " \t\r\n"):
		return "remove the spaces"
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return "use an absolute http:// or https:// URL, for example \"https://www.example.com/\""
	}
	return ""
}

type forwardURLValidator struct{}

func (forwardURLValidator) Description(context.Context) string {
	return "absolute http:// or https:// URL without spaces"
}
func (v forwardURLValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (forwardURLValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if problem := validForwardURL(v); problem != "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid forward URL", fmt.Sprintf("%q: %s.", v, problem))
	}
}

// trimmedValidator refuses empty strings and leading or trailing spaces,
// which the gate would remove.
type trimmedValidator struct{}

func (trimmedValidator) Description(context.Context) string {
	return "non-empty, without leading or trailing spaces"
}
func (v trimmedValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (trimmedValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if v == "" || strings.TrimSpace(v) != v {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			fmt.Sprintf("%q: the gate removes leading and trailing spaces; write %q, or remove the attribute.", v, strings.TrimSpace(v)))
	}
}
