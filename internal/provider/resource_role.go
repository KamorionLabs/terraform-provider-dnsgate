package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = (*roleResource)(nil)
	_ resource.ResourceWithImportState = (*roleResource)(nil)
)

type roleResource struct {
	pd *providerData
}

func newRoleResource() resource.Resource { return &roleResource{} }

type roleModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	Rules        []ruleModel  `tfsdk:"rules"`
	RebaseOnSave types.Bool   `tfsdk:"rebase_on_save"`
	EphemeralTTL types.String `tfsdk:"ephemeral_ttl"`
	MaxChanges   types.Int64  `tfsdk:"max_changes_per_request"`
	Delegation   types.String `tfsdk:"delegation"`
	ETag         types.String `tfsdk:"etag"`
}

type ruleModel struct {
	Zones   []string `tfsdk:"zones"`
	Actions []string `tfsdk:"actions"`
	Hosts   []string `tfsdk:"hosts"`
	Types   []string `tfsdk:"types"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nonEmpty := []validator.List{listvalidator.SizeAtLeast(1)}
	attrs := commonDelegatedAttributes("role")
	attrs["name"] = nameAttribute("role")
	attrs["description"] = schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "Free text shown in the gate UI.",
		Validators:          []validator.String{stringvalidator.LengthBetween(1, 500)},
	}
	attrs["rules"] = schema.ListNestedAttribute{
		Required: true,
		MarkdownDescription: "Grants of the role. Each rule must stay within the delegation of the provider identity " +
			"(`allow.zones`, `allow.actions`, `allow.records`) and within `policy.bounds` of the gate.",
		Validators: nonEmpty,
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"zones": schema.ListAttribute{
				Required: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Zone globs (`*` wildcards), for example `example.com` or `*.example.com`.",
			},
			"actions": schema.ListAttribute{
				Required: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Actions: `dns.read`, `dns.record.write`, `dns.record.adopt`, `dns.zone.admin`, `domain.read`, `ui.read` " +
					"(as far as the delegation allows; `policy.*` actions are never delegated).",
			},
			"hosts": schema.ListAttribute{
				Optional: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Host patterns relative to the zone: `@` is the apex, `*` one label, `**` one or more labels. " +
					"Omit to cover every host (if the delegation allows it).",
			},
			"types": schema.ListAttribute{
				Optional: true, ElementType: types.StringType, Validators: nonEmpty,
				MarkdownDescription: "Record types, `*` for any. Omit to cover every type (if the delegation allows it).",
			},
		}},
	}
	attrs["rebase_on_save"] = schema.BoolAttribute{
		Optional: true, Computed: true, Default: booldefault.StaticBool(false),
		MarkdownDescription: "On a full-zone PUT, ignore differences outside the role's scope instead of refusing them (stale zones sent by ACME clients). Default `false`.",
	}
	attrs["ephemeral_ttl"] = schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "Go duration after which the RRsets created through the role expire and are removed by the gate (ACME challenges), for example `24h`.",
		Validators:          []validator.String{durationString{}},
	}
	attrs["max_changes_per_request"] = schema.Int64Attribute{
		Optional: true, Computed: true, Default: int64default.StaticInt64(0),
		MarkdownDescription: "Blast-radius limit (RRset changes per request), `0` for the gate default, at most 1000.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A role of the dns-gate managed policy, owned by a policy delegation of the gate. " +
			"The gate validates it against the delegation of the provider identity and activates the change at once, " +
			"without approval. Bind it with `dnsgate_binding`.",
		Attributes: attrs,
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd := providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
	if pd == nil || !requireDelegation(pd, &resp.Diagnostics, "dnsgate_role") {
		return
	}
	r.pd = pd
}

func (m *roleModel) request() client.DelegatedRoleRequest {
	req := client.DelegatedRoleRequest{
		Role: client.Role{
			Description:          m.Description.ValueString(),
			RebaseOnSave:         m.RebaseOnSave.ValueBool(),
			EphemeralTTL:         m.EphemeralTTL.ValueString(),
			MaxChangesPerRequest: int(m.MaxChanges.ValueInt64()),
			Rules:                []client.Rule{},
		},
		Delegation: m.Delegation.ValueString(),
		ManagedBy:  managedBy,
	}
	for _, rule := range m.Rules {
		gr := client.Rule{Zones: rule.Zones, Actions: rule.Actions}
		if len(rule.Hosts) > 0 || len(rule.Types) > 0 {
			gr.Records = &client.RecordScope{Hosts: rule.Hosts, Types: rule.Types}
		}
		req.Rules = append(req.Rules, gr)
	}
	return req
}

func (m *roleModel) fromObject(obj *client.DelegatedObject) {
	m.ID, m.Name = types.StringValue(obj.Name), types.StringValue(obj.Name)
	m.Delegation, m.ETag = types.StringValue(obj.Owner.Delegation), types.StringValue(obj.ETag)
	role := obj.Role
	if role == nil {
		role = &client.Role{}
	}
	m.Description = optionalString(role.Description)
	m.EphemeralTTL = optionalString(role.EphemeralTTL)
	m.RebaseOnSave = types.BoolValue(role.RebaseOnSave)
	m.MaxChanges = types.Int64Value(int64(role.MaxChangesPerRequest))
	m.Rules = make([]ruleModel, 0, len(role.Rules))
	for _, rule := range role.Rules {
		rm := ruleModel{Zones: rule.Zones, Actions: rule.Actions}
		if rule.Records != nil {
			rm.Hosts, rm.Types = nilIfEmpty(rule.Records.Hosts), nilIfEmpty(rule.Records.Types)
		}
		m.Rules = append(m.Rules, rm)
	}
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.pd.client, client.KindRole, plan.Name.ValueString(), client.Condition{IfNoneMatch: true}, plan.request(), &resp.Diagnostics, func(obj *client.DelegatedObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj := readDelegated(ctx, r.pd.client, client.KindRole, state.Name.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if obj == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromObject(obj)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.pd.client, client.KindRole, plan.Name.ValueString(), client.Condition{IfMatch: state.ETag.ValueString()}, plan.request(), &resp.Diagnostics, func(obj *client.DelegatedObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteDelegated(ctx, r.pd.client, client.KindRole, state.Name.ValueString(), &resp.Diagnostics)
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp)
}
