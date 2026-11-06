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
	if req.State.Raw.IsNull() {
		planCreateTeam(ctx, r.pd, plan.Team.ValueString(), resp)
		return
	}
	var state recordSetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name, typ := state.key()
	planTeamChange(ctx, r.pd, teamChange{
		Team:    plan.Team.ValueString(),
		Owner:   firstNonEmpty(state.OwnerTeam.ValueString(), state.Owner.ValueString()),
		Changed: !plan.Team.Equal(state.Team) || !sameContent(&plan, &state),
		Zone:    zone, Object: name + " " + typ, Kind: "Record set", Noun: "an RRset",
	}, &resp.Diagnostics)
}

// planCreateTeam checks the team of a new object and plans it as its owner team.
func planCreateTeam(ctx context.Context, pd *providerData, team string, resp *resource.ModifyPlanResponse) {
	checkTeam(ctx, pd, team, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("owner_team"), team)...)
}

// teamChange is the team of an existing owned object (record set or URL
// forward) in a plan.
type teamChange struct {
	// Team is the planned team, Owner the owner team in the state.
	Team, Owner string
	// Changed tells whether team or the content changes.
	Changed bool
	// Zone, Object ("www A"), Kind ("Record set") and Noun ("an RRset")
	// name the object in the diagnostics.
	Zone, Object, Kind, Noun string
}

// planTeamChange refuses a change of an object owned by another team than
// team, and warns when such an object does not change.
func planTeamChange(ctx context.Context, pd *providerData, c teamChange, diags *diag.Diagnostics) {
	if c.Owner == "" || c.Owner == c.Team {
		if c.Changed {
			checkTeam(ctx, pd, c.Team, diags)
		}
		return
	}
	detail := fmt.Sprintf("%s in %s is owned by team %q in the gate, and this configuration sets team = %q. ", c.Object, c.Zone, c.Owner, c.Team) +
		"Terraform does not move " + c.Noun + " to another team. Ownership moves only through a transfer request approved in the " +
		"gate (web UI, or POST /api/v1/zones/" + c.Zone + "/transfers, approved by a member of the owner team or a holder of " +
		"dns.ownership.approve). Once the transfer is applied, plan again: owner_team then matches team. " +
		"To keep the current owner, set team = \"" + c.Owner + "\" (or remove team if it is the default team of this identity)."
	if c.Changed {
		diags.AddAttributeError(path.Root("team"), c.Kind+" owned by another team", detail)
		return
	}
	diags.AddAttributeWarning(path.Root("team"), c.Kind+" owned by another team",
		detail+" Until then, any change or destroy of "+c.Object+" will be refused.")
}

// checkTeam reports, at plan time, a team the identity cannot act for.
// Errors reading /api/v1/me are left to the write, which the gate checks.
func checkTeam(ctx context.Context, pd *providerData, team string, diags *diag.Diagnostics) {
	me, err := pd.whoami(ctx)
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
				firstNonEmpty(pd.info.Version, "unknown"), me.Teams[0]))
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
