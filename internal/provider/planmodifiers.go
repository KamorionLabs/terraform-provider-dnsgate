package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/rdata"
)

// valuesEquivalent keeps the values of the state in the plan when the
// configuration holds the same records written differently (see package
// rdata), so that neither an import nor a cosmetic difference shows a
// change. A null configuration (alias record sets) plans null.
type valuesEquivalent struct{}

func (valuesEquivalent) Description(context.Context) string {
	return "Keeps the stored values when the configured values are the same records written differently."
}
func (m valuesEquivalent) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (valuesEquivalent) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.ConfigValue.IsNull() {
		resp.PlanValue = types.SetNull(types.StringType)
		return
	}
	if req.ConfigValue.IsUnknown() || req.StateValue.IsNull() || req.StateValue.IsUnknown() {
		return
	}
	var typ types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("type"), &typ)...)
	if resp.Diagnostics.HasError() || typ.IsUnknown() || typ.IsNull() {
		return
	}
	cfg, ok1 := knownStrings(req.ConfigValue)
	st, ok2 := knownStrings(req.StateValue)
	if ok1 && ok2 && rdata.SetEqual(typ.ValueString(), cfg, st) {
		resp.PlanValue = req.StateValue
	}
}

// aliasNameEquivalent keeps the alias target of the state when the
// configuration names the same target (case, trailing dot).
type aliasNameEquivalent struct{}

func (aliasNameEquivalent) Description(context.Context) string {
	return "Keeps the stored alias target when the configured one differs only by case or a trailing dot."
}
func (m aliasNameEquivalent) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (aliasNameEquivalent) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsNull() {
		resp.PlanValue = types.StringNull()
		return
	}
	if req.ConfigValue.IsUnknown() || req.StateValue.IsNull() || req.StateValue.IsUnknown() {
		return
	}
	if rdata.NameEqual(req.ConfigValue.ValueString(), req.StateValue.ValueString()) {
		resp.PlanValue = req.StateValue
	}
}

func knownStrings(s types.Set) ([]string, bool) {
	out := make([]string, 0, len(s.Elements()))
	for _, e := range s.Elements() {
		v, ok := e.(types.String)
		if !ok || v.IsUnknown() || v.IsNull() {
			return nil, false
		}
		out = append(out, v.ValueString())
	}
	return out, true
}
