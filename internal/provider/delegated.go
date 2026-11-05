package provider

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// managedBy labels the objects this provider writes in the gate.
const managedBy = "terraform"

// gateNameRe is the name syntax of gate roles, bindings and teams.
var gateNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

func requireDelegation(pd *providerData, diags *diag.Diagnostics, resourceType string) bool {
	if !pd.info.HasFeature(client.FeaturePolicyDelegation) {
		diags.AddError("The dns-gate does not serve the delegation API",
			fmt.Sprintf("%s needs a gate that advertises the %q feature (GET %s). Upgrade the gate.", resourceType, client.FeaturePolicyDelegation, client.InfoPath))
		return false
	}
	return true
}

// nameAttribute is the stable name of a delegated object.
func nameAttribute(kind string) schema.StringAttribute {
	return schema.StringAttribute{
		Required: true,
		MarkdownDescription: fmt.Sprintf("Name of the %s in the gate, a lowercase identifier (`[a-z0-9._-]`, up to 64 characters). "+
			"Changing it replaces the %s.", kind, kind),
		PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		Validators:    []validator.String{stringvalidator.RegexMatches(gateNameRe, "must be a lowercase identifier")},
	}
}

// commonDelegatedAttributes are id, delegation and etag.
func commonDelegatedAttributes(kind string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "The name.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"delegation": schema.StringAttribute{
			Optional: true,
			Computed: true,
			MarkdownDescription: fmt.Sprintf("Gate delegation (`policy.delegations[].name`) that owns the %s. Needed only when the "+
				"provider identity matches several delegations; otherwise the gate picks the only one. Changing it replaces the %s.", kind, kind),
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplaceIfConfigured()},
		},
		"etag": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: fmt.Sprintf("Version of the %s in the gate, sent back as `If-Match` on updates so that a concurrent change is detected.", kind),
		},
	}
}

func optionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func importByName(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !gateNameRe.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected the name of the object in the gate (a lowercase identifier), got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

func readDelegated(ctx context.Context, c *client.Client, kind, name string, diags *diag.Diagnostics) *client.DelegatedObject {
	obj, err := c.GetDelegated(ctx, kind, name)
	if err != nil {
		addAPIError(diags, fmt.Sprintf("Cannot read gate %s %s", kind, name), err)
		return nil
	}
	if obj == nil {
		tflog.Info(ctx, "delegated object not found in the gate (deleted, or taken over by an administrator)", map[string]any{"kind": kind, "name": name})
	}
	return obj
}

func putDelegated(ctx context.Context, c *client.Client, kind, name string, cond client.Condition, body any, diags *diag.Diagnostics, done func(*client.DelegatedObject)) {
	res, err := c.PutDelegated(ctx, kind, name, cond, body)
	if err != nil {
		if client.IsPrecondition(err) {
			if cond.IfNoneMatch {
				diags.AddError(fmt.Sprintf("Gate %s %q already exists", kind, name),
					fmt.Sprintf("A delegated %s with this name already exists in the gate. Import it (id %q) or choose another name.", kind, name))
			} else {
				diags.AddError(fmt.Sprintf("Gate %s %q changed outside Terraform", kind, name),
					"The object changed in the gate since Terraform last read it (another stack or an administrator). Run terraform plan again to see the difference, then apply.")
			}
			return
		}
		addAPIError(diags, fmt.Sprintf("Cannot write gate %s %s", kind, name), err)
		return
	}
	for _, it := range res.Impact {
		if it.Kind == "warning" {
			tflog.Warn(ctx, "gate policy impact", map[string]any{"kind": kind, "name": name, "message": it.Message})
		}
	}
	if res.Object == nil {
		diags.AddError(fmt.Sprintf("Cannot write gate %s %s", kind, name), "the gate answered without the object")
		return
	}
	done(res.Object)
}

func deleteDelegated(ctx context.Context, c *client.Client, kind, name string, diags *diag.Diagnostics) {
	if err := c.DeleteDelegated(ctx, kind, name); err != nil {
		addAPIError(diags, fmt.Sprintf("Cannot delete gate %s %s", kind, name), err)
	}
}

// durationString validates a Go duration.
type durationString struct{}

func (durationString) Description(context.Context) string {
	return "must be a Go duration, for example 24h"
}
func (v durationString) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (durationString) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if d, err := time.ParseDuration(req.ConfigValue.ValueString()); err != nil || d <= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", fmt.Sprintf("%q is not a positive Go duration (for example 24h).", req.ConfigValue.ValueString()))
	}
}
