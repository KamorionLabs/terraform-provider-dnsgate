package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// reasonHelp explains the gate's refusal reasons.
var reasonHelp = map[string]string{
	client.ReasonForbidden:        "The gate policy does not allow this identity to do this (zone, host pattern or record type outside its roles, or a protected record).",
	client.ReasonNotOwner:         "This RRset is owned by another team in the gate (or by another of your teams than the one set in team). Only its owner team can modify or delete it; ownership moves through a transfer request approved in the gate.",
	client.ReasonNotTeamMember:    "The provider identity is not a member of the team set in team (sent as X-DNS-Gate-Team). The dnsgate_me data source lists its teams.",
	client.ReasonTeamMismatch:     "The team of the request is not the team of the plan it applies.",
	client.ReasonForeignRRset:     "This RRset exists in the zone but was not created or adopted through the gate. Adopt it for your team in the gate first (web UI, Zones page, or POST /api/v1/zones/{zone}/adopt), then import it.",
	client.ReasonTainted:          "This RRset was modified outside the gate (for example in the provider console). Writes are blocked until a gate administrator reviews and re-adopts it.",
	client.ReasonPrecondition:     "The RRset changed in the gate since Terraform last read it (another run, the web UI or an administrator). Run terraform plan again to see the difference, then apply.",
	client.ReasonZoneLocked:       "Another write on this zone held the gate lock for longer than the provider retries (max_retries). Retry later, or raise max_retries.",
	client.ReasonUpstream:         "The DNS provider behind the gate failed or refused the change.",
	client.ReasonInvalid:          "The gate refused the request as invalid for this zone's DNS provider (record type, TTL or value).",
	client.ReasonTooManyChanges:   "The change exceeds the maximum number of RRset changes per request allowed for this identity.",
	client.ReasonInvalidForward:   "The gate refused the URL forward: type must be 301, 302 or frame, url an absolute http:// or https:// URL, and title, keywords and description apply to frame forwards only.",
	client.ReasonHTTPSUnavailable: "require_https is set, but the URL forwards of this zone answer plain HTTP only. At EuroDNS a forward answers HTTPS only when the domain has an HTTPS redirect subscription, a paid product ordered at the DNS provider, outside the gate. Order it, or set require_https = false to accept a forward that answers plain HTTP only (the target url may be https:// either way).",
	"invalid_policy":              "The gate refused the object: it is outside the limits of the delegation (policy.delegations in the gate configuration) or of the managed policy. The errors below name the offending fields.",
	"delegation_required":         "This identity matches several delegations: set the delegation attribute.",
	"name_taken":                  "The name is used by a role of the base policy or by a managed role edited by humans. Choose another name.",
	"policy_busy":                 "The gate policy kept changing concurrently and the retries were exhausted. Run the operation again.",
	"policy_not_editable":         "The managed policy of the gate is disabled (policy.editable is false).",
	"reauth_required":             "A human identity must have signed in recently to change the gate policy.",
	client.ReasonStoreUnavailable: "The gate's store (ownership, locks, audit) was unavailable and the retries were exhausted. Retry later.",
	"unauthenticated":             "The gate did not accept the token: check the auth block (issuer, audience, expiry) against the gate's issuers.",
}

// addAPIError turns an error into a readable diagnostic.
func addAPIError(diags *diag.Diagnostics, summary string, err error) {
	diags.AddError(summary, describe(err))
}

func describe(err error) string {
	e, ok := client.AsAPIError(err)
	if !ok {
		return err.Error()
	}
	var b strings.Builder
	if help, ok := reasonHelp[e.Reason]; ok {
		fmt.Fprintf(&b, "%s\n\n", help)
	} else if e.Status == 401 {
		fmt.Fprintf(&b, "%s\n\n", reasonHelp["unauthenticated"])
	}
	fmt.Fprintf(&b, "Gate reason: %s (HTTP %d on %s %s", firstNonEmpty(e.Reason, "unknown"), e.Status, e.Method, e.Path)
	if e.Attempts > 1 {
		fmt.Fprintf(&b, ", after %d attempts", e.Attempts)
	}
	b.WriteString(")\n")
	if e.Message != "" {
		fmt.Fprintf(&b, "Message: %s\n", e.Message)
	}
	for _, v := range e.Errors {
		fmt.Fprintf(&b, "  - %s: %s\n", firstNonEmpty(v.Path, "(document)"), v.Message)
	}
	if len(e.Details) > 0 && string(e.Details) != "null" {
		fmt.Fprintf(&b, "Details: %s\n", truncate(string(e.Details), 2000))
	}
	if e.Reason == "" && e.Body != "" {
		fmt.Fprintf(&b, "Response: %s", truncate(e.Body, 2000))
	}
	return strings.TrimRight(b.String(), "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
