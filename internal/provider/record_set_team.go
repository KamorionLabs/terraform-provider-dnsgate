package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ModifyPlan checks the team of a record set before anything is written.
//
// The gate decides ownership: a write made for team B on an RRset of team A
// is refused (403 not_owner), and the provider never moves an RRset to
// another team by itself (a delete and re-create would leave the name
// without records for a while, and the gate reserves a deleted RRset for
// its team anyway). Ownership moves only through a transfer request
// approved in the gate; once applied, the refreshed owner_team matches the
// new team and the plan goes through. So:
//
//   - create: the identity must be a member of team (and the gate must
//     support team selection, unless team is the identity's first team);
//     owner_team is planned as team;
//   - a change of team or content while owner_team differs from team: error
//     at plan time, explaining the transfer;
//   - no change while owner_team differs from team (the RRset was
//     transferred away): warning, since the next write would be refused.
func (r *recordSetResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.pd == nil {
		return
	}
	var plan recordSetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.Team.IsUnknown() || plan.Team.IsNull() {
		return
	}
	team := plan.Team.ValueString()
	if req.State.Raw.IsNull() {
		r.checkTeam(ctx, team, &resp.Diagnostics)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("owner_team"), team)...)
		return
	}
	var state recordSetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	changed := !plan.Team.Equal(state.Team) || !sameContent(&plan, &state)
	owner := firstNonEmpty(state.OwnerTeam.ValueString(), state.Owner.ValueString())
	if owner == "" || owner == team {
		if changed {
			r.checkTeam(ctx, team, &resp.Diagnostics)
		}
		return
	}
	zone, name, typ := state.key()
	detail := fmt.Sprintf("%s %s in %s is owned by team %q in the gate, and this configuration sets team = %q. ", name, typ, zone, owner, team) +
		"Terraform does not move an RRset to another team. Ownership moves only through a transfer request approved in the " +
		"gate (web UI, or POST /api/v1/zones/" + zone + "/transfers, approved by a member of the owner team or a holder of " +
		"dns.ownership.approve). Once the transfer is applied, plan again: owner_team then matches team. " +
		"To keep the current owner, set team = \"" + owner + "\" (or remove team if it is the default team of this identity)."
	if changed {
		resp.Diagnostics.AddAttributeError(path.Root("team"), "Record set owned by another team", detail)
		return
	}
	resp.Diagnostics.AddAttributeWarning(path.Root("team"), "Record set owned by another team",
		detail+" Until then, any change or destroy of this record set will be refused.")
}

// checkTeam reports, at plan time, a team the identity cannot act for.
// Errors reading /api/v1/me are left to the write, which the gate checks.
func (r *recordSetResource) checkTeam(ctx context.Context, team string, diags *diag.Diagnostics) {
	me, err := r.pd.whoami(ctx)
	if err != nil {
		tflog.Debug(ctx, "cannot read /api/v1/me, team not checked at plan time", map[string]any{"error": err.Error()})
		return
	}
	if !contains(me.Teams, team) {
		diags.AddAttributeError(path.Root("team"), "Not a member of the team",
			fmt.Sprintf("The provider identity (%s) acts for the teams [%s] in the gate, not for %q.",
				firstNonEmpty(me.Name, me.Subject), strings.Join(me.Teams, ", "), team))
		return
	}
	if me.DefaultTeam == "" && me.Teams[0] != team {
		diags.AddAttributeError(path.Root("team"), "The gate does not support team selection",
			fmt.Sprintf("The gate (version %s) writes for the first team of the identity, %q, and ignores the "+
				"X-DNS-Gate-Team header. Upgrade the gate to a version with teams, or remove team.",
				firstNonEmpty(r.pd.info.Version, "unknown"), me.Teams[0]))
	}
}

// sameContent reports whether plan and state hold the same records (the
// plan modifiers keep the state form of equivalent values).
func sameContent(a, b *recordSetModel) bool {
	if !a.TTL.Equal(b.TTL) || !a.Values.Equal(b.Values) {
		return false
	}
	if a.Alias == nil || b.Alias == nil {
		return a.Alias == nil && b.Alias == nil
	}
	return a.Alias.Name.Equal(b.Alias.Name) && a.Alias.ZoneID.Equal(b.Alias.ZoneID) &&
		a.Alias.EvaluateTargetHealth.Equal(b.Alias.EvaluateTargetHealth)
}
