package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = (*bindingResource)(nil)
	_ resource.ResourceWithImportState = (*bindingResource)(nil)
)

type bindingResource struct {
	pd *providerData
}

func newBindingResource() resource.Resource { return &bindingResource{} }

type bindingModel struct {
	ID         types.String   `tfsdk:"id"`
	Name       types.String   `tfsdk:"name"`
	Role       types.String   `tfsdk:"role"`
	Team       types.String   `tfsdk:"team"`
	TeamFrom   *teamFromModel `tfsdk:"team_from"`
	Subjects   []subjectModel `tfsdk:"subjects"`
	Groups     []string       `tfsdk:"groups"`
	Delegation types.String   `tfsdk:"delegation"`
	ETag       types.String   `tfsdk:"etag"`
}

type teamFromModel struct {
	Claim  types.String `tfsdk:"claim"`
	Regex  types.String `tfsdk:"regex"`
	Prefix types.String `tfsdk:"prefix"`
}

type subjectModel struct {
	Issuer types.String        `tfsdk:"issuer"`
	Claims map[string][]string `tfsdk:"claims"`
}

func (r *bindingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_binding"
}

func (r *bindingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := commonDelegatedAttributes("binding")
	attrs["name"] = nameAttribute("binding")
	attrs["role"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "Role granted: an `dnsgate_role` of the same delegation, or a base or managed role " +
			"listed in the `allow.roles` of the delegation.",
		Validators: []validator.String{stringvalidator.RegexMatches(gateNameRe, "must be a lowercase identifier")},
	}
	attrs["team"] = schema.StringAttribute{
		Optional: true,
		MarkdownDescription: "Owner team of the RRsets created through the binding. Allowed when it matches the " +
			"`allow.teams.names` of the delegation, or when it is the team that `allow.teams.from_subject` derives from the " +
			"single, literal subject claim of the binding (\"team from the subject\"). Exactly one of `team` and `team_from`.",
		Validators: []validator.String{
			stringvalidator.RegexMatches(gateNameRe, "must be a lowercase identifier"),
			stringvalidator.ExactlyOneOf(path.MatchRoot("team"), path.MatchRoot("team_from")),
		},
	}
	attrs["team_from"] = schema.SingleNestedAttribute{
		Optional: true,
		MarkdownDescription: "Derive the team of each subject from one of its claims; must be exactly the " +
			"`allow.teams.from_subject` rule of the delegation.",
		Attributes: map[string]schema.Attribute{
			"claim":  schema.StringAttribute{Required: true, MarkdownDescription: "String claim, typically `sub`."},
			"regex":  schema.StringAttribute{Required: true, MarkdownDescription: "Anchored RE2 expression with exactly one capture group."},
			"prefix": schema.StringAttribute{Optional: true, MarkdownDescription: "Prefix of the derived team."},
		},
	}
	attrs["subjects"] = schema.ListNestedAttribute{
		Optional: true,
		MarkdownDescription: "Identities bound, each an issuer of the gate plus claim globs that must all match. Each must be " +
			"covered by the `allow.binding_subjects` of the delegation. At least one of `subjects` and `groups`.",
		Validators: []validator.List{
			listvalidator.SizeAtLeast(1),
			listvalidator.AtLeastOneOf(path.MatchRoot("subjects"), path.MatchRoot("groups")),
		},
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"issuer": schema.StringAttribute{Required: true, MarkdownDescription: "Issuer name in the gate configuration (`issuers[].name`)."},
			"claims": schema.MapAttribute{
				Required:            true,
				ElementType:         types.ListType{ElemType: types.StringType},
				MarkdownDescription: "Claim name to accepted globs, for example `{ sub = [\"sc://org/project/dns-gate-web\"] }`.",
				Validators:          []validator.Map{mapvalidator.SizeAtLeast(1)},
			},
		}},
	}
	attrs["groups"] = schema.ListAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: "Gate groups whose members are bound, among the `allow.groups` of the delegation.",
		Validators:          []validator.List{listvalidator.SizeAtLeast(1)},
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A binding of the dns-gate managed policy, owned by a policy delegation of the gate " +
			"(gate mode only): it grants a role, acting for a team, to identities. The gate validates it against the " +
			"delegation of the provider identity and activates the change at once, without approval.",
		Attributes: attrs,
	}
}

func (r *bindingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd := providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
	if pd == nil || !requireDelegation(pd, &resp.Diagnostics, "dnsgate_binding") {
		return
	}
	r.pd = pd
}

func (m *bindingModel) request() client.DelegatedBindingRequest {
	req := client.DelegatedBindingRequest{
		Binding:    client.Binding{Role: m.Role.ValueString(), Team: m.Team.ValueString(), Groups: m.Groups},
		Delegation: m.Delegation.ValueString(),
		ManagedBy:  managedBy,
	}
	if m.TeamFrom != nil {
		req.TeamFrom = &client.TeamFrom{Claim: m.TeamFrom.Claim.ValueString(), Regex: m.TeamFrom.Regex.ValueString(), Prefix: m.TeamFrom.Prefix.ValueString()}
	}
	for _, s := range m.Subjects {
		req.Subjects = append(req.Subjects, client.SubjectMatcher{Issuer: s.Issuer.ValueString(), Claims: s.Claims})
	}
	return req
}

func (m *bindingModel) fromObject(obj *client.DelegatedObject) {
	m.ID, m.Name = types.StringValue(obj.Name), types.StringValue(obj.Name)
	m.Delegation, m.ETag = types.StringValue(obj.Owner.Delegation), types.StringValue(obj.ETag)
	b := obj.Binding
	if b == nil {
		b = &client.Binding{}
	}
	m.Role, m.Team = types.StringValue(b.Role), optionalString(b.Team)
	m.TeamFrom = nil
	if b.TeamFrom != nil {
		m.TeamFrom = &teamFromModel{Claim: types.StringValue(b.TeamFrom.Claim), Regex: types.StringValue(b.TeamFrom.Regex), Prefix: optionalString(b.TeamFrom.Prefix)}
	}
	m.Groups = nilIfEmpty(b.Groups)
	m.Subjects = nil
	for _, s := range b.Subjects {
		m.Subjects = append(m.Subjects, subjectModel{Issuer: types.StringValue(s.Issuer), Claims: s.Claims})
	}
}

func (r *bindingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan bindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.pd.client, client.KindBinding, plan.Name.ValueString(), client.Condition{IfNoneMatch: true}, plan.request(), &resp.Diagnostics, func(obj *client.DelegatedObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *bindingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state bindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj := readDelegated(ctx, r.pd.client, client.KindBinding, state.Name.ValueString(), &resp.Diagnostics)
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

func (r *bindingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state bindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	putDelegated(ctx, r.pd.client, client.KindBinding, plan.Name.ValueString(), client.Condition{IfMatch: state.ETag.ValueString()}, plan.request(), &resp.Diagnostics, func(obj *client.DelegatedObject) {
		plan.fromObject(obj)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	})
}

func (r *bindingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state bindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteDelegated(ctx, r.pd.client, client.KindBinding, state.Name.ValueString(), &resp.Diagnostics)
}

func (r *bindingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByName(ctx, req, resp)
}
