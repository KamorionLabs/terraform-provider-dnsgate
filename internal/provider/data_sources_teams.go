package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// dnsgate_me

type meDataSource struct{ pd *providerData }

func newMeDataSource() datasource.DataSource { return &meDataSource{} }

type meDataModel struct {
	Subject     types.String `tfsdk:"subject"`
	Name        types.String `tfsdk:"name"`
	Category    types.String `tfsdk:"category"`
	Roles       types.List   `tfsdk:"roles"`
	Teams       types.List   `tfsdk:"teams"`
	Groups      types.List   `tfsdk:"groups"`
	DefaultTeam types.String `tfsdk:"default_team"`
}

func (d *meDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_me"
}

func (d *meDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The identity of the provider as the gate sees it (`GET /api/v1/me`): roles, teams and the default team " +
			"it writes for.",
		Attributes: map[string]schema.Attribute{
			"subject":  schema.StringAttribute{Computed: true, MarkdownDescription: "`<issuer>:<subject id>`."},
			"name":     schema.StringAttribute{Computed: true, MarkdownDescription: "Display name."},
			"category": schema.StringAttribute{Computed: true, MarkdownDescription: "`human`, `pipeline`, `workload`..."},
			"roles":    schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Roles granted by the gate policy."},
			"teams": schema.ListAttribute{
				Computed: true, ElementType: types.StringType,
				MarkdownDescription: "Teams the identity acts for, the default team first.",
			},
			"groups": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Groups of the identity."},
			"default_team": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Team the identity writes for unless a resource sets `team`: owner of the RRsets it creates. " +
					"Gates without teams do not report it: it is then the first of `teams`, the team those gates write for. " +
					"Empty when the identity has no team.",
			},
		},
	}
}

func (d *meDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
}

func (d *meDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	me, err := d.pd.client.Me(ctx)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot read the identity", err)
		return
	}
	def := me.DefaultTeam
	if def == "" && len(me.Teams) > 0 {
		def = me.Teams[0]
	}
	data := meDataModel{
		Subject: types.StringValue(me.Subject), Name: types.StringValue(me.Name), Category: types.StringValue(me.Category),
		Roles: stringList(me.Roles), Teams: stringList(me.Teams), Groups: stringList(me.Groups), DefaultTeam: types.StringValue(def),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func stringList(values []string) types.List {
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

// Team attributes shared by dnsgate_teams and dnsgate_team.

type teamMembersModel struct {
	Groups   []string             `tfsdk:"groups"`
	Subjects []teamMemberSubjects `tfsdk:"subjects"`
}

type teamMemberSubjects struct {
	Issuer types.String        `tfsdk:"issuer"`
	Claims map[string][]string `tfsdk:"claims"`
}

type teamFamilyModel struct {
	Claim  types.String `tfsdk:"claim"`
	Regex  types.String `tfsdk:"regex"`
	Prefix types.String `tfsdk:"prefix"`
}

type teamInfoModel struct {
	Name        types.String      `tfsdk:"name"`
	Kind        types.String      `tfsdk:"kind"`
	Layer       types.String      `tfsdk:"layer"`
	Description types.String      `tfsdk:"description"`
	Members     *teamMembersModel `tfsdk:"members"`
	Roles       types.List        `tfsdk:"roles"`
	VirtualKeys types.List        `tfsdk:"virtual_keys"`
	Family      *teamFamilyModel  `tfsdk:"family"`
	Issuer      types.String      `tfsdk:"issuer"`
	Warning     types.String      `tfsdk:"warning"`
}

const teamKinds = "`declared` (teams block of the gate configuration or of its managed policy), `auto` (named by a binding " +
	"or a virtual key without being declared, during the migration to the teams block), `family` (teams derived from a " +
	"claim by `team_from`, name `<prefix>*`), `claim` (teams taken from the `team_claim` of an issuer, name `*`), `store` " +
	"(owns RRsets but named nowhere in the policy)"

func teamInfoAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"name":        schema.StringAttribute{Computed: true, MarkdownDescription: "Team name."},
		"kind":        schema.StringAttribute{Computed: true, MarkdownDescription: "Where the team comes from: " + teamKinds + "."},
		"layer":       schema.StringAttribute{Computed: true, MarkdownDescription: "`base` (gate configuration file) or `managed` (managed policy) for declared teams, empty otherwise."},
		"description": schema.StringAttribute{Computed: true},
		"members": schema.SingleNestedAttribute{
			Computed: true,
			MarkdownDescription: "Members of a declared team. Null unless the identity holds `policy.read` in the gate, and for " +
				"teams that are not declared.",
			Attributes: map[string]schema.Attribute{
				"groups": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Policy groups."},
				"subjects": schema.ListNestedAttribute{
					Computed:            true,
					MarkdownDescription: "Subject matchers: an issuer and the claims a token must carry.",
					NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
						"issuer": schema.StringAttribute{Computed: true},
						"claims": schema.MapAttribute{Computed: true, ElementType: types.ListType{ElemType: types.StringType}},
					}},
				},
			},
		},
		"roles":        schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Roles of the bindings and virtual keys naming the team."},
		"virtual_keys": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Virtual keys acting for the team."},
		"family": schema.SingleNestedAttribute{
			Computed:            true,
			MarkdownDescription: "Derivation of a `family` team, null otherwise.",
			Attributes: map[string]schema.Attribute{
				"claim":  schema.StringAttribute{Computed: true},
				"regex":  schema.StringAttribute{Computed: true},
				"prefix": schema.StringAttribute{Computed: true},
			},
		},
		"issuer":  schema.StringAttribute{Computed: true, MarkdownDescription: "Issuer of a `claim` team."},
		"warning": schema.StringAttribute{Computed: true, MarkdownDescription: "Why the gate flags the team (for example undeclared), empty otherwise."},
	}
}

func teamInfo(t *client.TeamInfo) teamInfoModel {
	m := teamInfoModel{
		Name: types.StringValue(t.Name), Kind: types.StringValue(t.Kind), Layer: types.StringValue(t.Layer),
		Description: types.StringValue(t.Description), Roles: stringList(t.Roles), VirtualKeys: stringList(t.VirtualKeys),
		Issuer: types.StringValue(t.Issuer), Warning: types.StringValue(t.Warning),
	}
	if t.Members != nil {
		m.Members = &teamMembersModel{Groups: t.Members.Groups, Subjects: []teamMemberSubjects{}}
		if m.Members.Groups == nil {
			m.Members.Groups = []string{}
		}
		for _, s := range t.Members.Subjects {
			m.Members.Subjects = append(m.Members.Subjects, teamMemberSubjects{Issuer: types.StringValue(s.Issuer), Claims: s.Claims})
		}
	}
	if t.Family != nil {
		m.Family = &teamFamilyModel{Claim: types.StringValue(t.Family.Claim), Regex: types.StringValue(t.Family.Regex), Prefix: types.StringValue(t.Family.Prefix)}
	}
	return m
}

func noTeamsWarning(diags *diag.Diagnostics, pd *providerData) {
	diags.AddWarning("The dns-gate has no teams API",
		fmt.Sprintf("The gate (version %s) does not serve GET /api/v1/teams: it predates first-class teams. The data source is "+
			"empty. Upgrade the gate to list teams.", firstNonEmpty(pd.info.Version, "unknown")))
}

// dnsgate_teams

type teamsDataSource struct{ pd *providerData }

func newTeamsDataSource() datasource.DataSource { return &teamsDataSource{} }

type teamsDataModel struct {
	Kind   types.String    `tfsdk:"kind"`
	Strict types.Bool      `tfsdk:"strict"`
	Names  types.List      `tfsdk:"names"`
	Teams  []teamInfoModel `tfsdk:"teams"`
}

func (d *teamsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_teams"
}

func (d *teamsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The teams of the gate policy (`GET /api/v1/teams`). Teams own RRsets; the gate declares them with " +
			"their members in its policy. Empty, with a warning, on gates without teams.",
		Attributes: map[string]schema.Attribute{
			"kind": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Keep only the teams of this kind: " + teamKinds + ".",
				Validators: []validator.String{stringvalidator.OneOf(client.TeamKindDeclared, client.TeamKindAuto,
					client.TeamKindFamily, client.TeamKindClaim, client.TeamKindStore)},
			},
			"strict": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the gate requires every team named by its policy to be declared (its configuration has a `teams` block).",
			},
			"names": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Names of the teams, sorted."},
			"teams": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Teams sorted by name.",
				NestedObject:        schema.NestedAttributeObject{Attributes: teamInfoAttributes()},
			},
		},
	}
}

func (d *teamsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
}

func (d *teamsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data teamsDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Strict, data.Teams = types.BoolValue(false), []teamInfoModel{}
	tl, err := d.pd.client.Teams(ctx)
	switch {
	case errors.Is(err, client.ErrNoTeams):
		noTeamsWarning(&resp.Diagnostics, d.pd)
		tl = &client.TeamList{}
	case err != nil:
		addAPIError(&resp.Diagnostics, "Cannot list the teams", err)
		return
	}
	data.Strict = types.BoolValue(tl.Strict)
	sort.Slice(tl.Teams, func(i, j int) bool { return tl.Teams[i].Name < tl.Teams[j].Name })
	names := []string{}
	for i := range tl.Teams {
		t := &tl.Teams[i]
		if k := data.Kind.ValueString(); k != "" && k != t.Kind {
			continue
		}
		data.Teams = append(data.Teams, teamInfo(t))
		names = append(names, t.Name)
	}
	data.Names = stringList(names)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// dnsgate_team

type teamDataSource struct{ pd *providerData }

func newTeamDataSource() datasource.DataSource { return &teamDataSource{} }

type teamOwnedModel struct {
	Zone       types.String `tfsdk:"zone"`
	RRsets     types.Int64  `tfsdk:"rrsets"`
	Tombstones types.Int64  `tfsdk:"tombstones"`
}

type teamTransferModel struct {
	ID        types.String `tfsdk:"id"`
	Kind      types.String `tfsdk:"kind"`
	Zone      types.String `tfsdk:"zone"`
	FromTeam  types.String `tfsdk:"from_team"`
	ToTeam    types.String `tfsdk:"to_team"`
	RRsets    types.List   `tfsdk:"rrsets"`
	Requester types.String `tfsdk:"requester"`
	ExpiresAt types.String `tfsdk:"expires_at"`
}

type teamDataModel struct {
	teamInfoModel
	Owned            []teamOwnedModel    `tfsdk:"owned"`
	RRsets           types.Int64         `tfsdk:"rrsets"`
	PendingTransfers []teamTransferModel `tfsdk:"pending_transfers"`
}

func (d *teamDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_team"
}

func (d *teamDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := teamInfoAttributes()
	attrs["name"] = schema.StringAttribute{Required: true, MarkdownDescription: "Team name."}
	attrs["owned"] = schema.ListNestedAttribute{
		Computed: true,
		MarkdownDescription: "What the team owns per zone, among the zones the identity can read, sorted by zone. Tombstones are " +
			"RRsets the team deleted recently, still reserved for it. The gate caches these counts for up to a minute.",
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"zone":       schema.StringAttribute{Computed: true},
			"rrsets":     schema.Int64Attribute{Computed: true},
			"tombstones": schema.Int64Attribute{Computed: true},
		}},
	}
	attrs["rrsets"] = schema.Int64Attribute{Computed: true, MarkdownDescription: "RRsets owned in the readable zones, in total."}
	attrs["pending_transfers"] = schema.ListNestedAttribute{
		Computed:            true,
		MarkdownDescription: "Ownership transfer requests from or to the team waiting for approval.",
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true},
			"kind":       schema.StringAttribute{Computed: true, MarkdownDescription: "`rrsets` (RRsets of one zone) or `rename` (every RRset of a team)."},
			"zone":       schema.StringAttribute{Computed: true, MarkdownDescription: "Empty for a rename."},
			"from_team":  schema.StringAttribute{Computed: true},
			"to_team":    schema.StringAttribute{Computed: true},
			"rrsets":     schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "`<name>/<type>` of the RRsets."},
			"requester":  schema.StringAttribute{Computed: true},
			"expires_at": schema.StringAttribute{Computed: true, MarkdownDescription: "RFC 3339."},
		}},
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "One team of the gate policy (`GET /api/v1/teams/{team}`): where it comes from, its members and roles, " +
			"what it owns per zone and its pending ownership transfers. Fails if the gate does not know the team; empty, with " +
			"a warning, on gates without teams.",
		Attributes: attrs,
	}
}

func (d *teamDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
}

func (d *teamDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg teamDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := cfg.Name.ValueString()
	td, err := d.pd.client.Team(ctx, name)
	switch {
	case errors.Is(err, client.ErrNoTeams):
		noTeamsWarning(&resp.Diagnostics, d.pd)
		td = &client.TeamDetail{TeamInfo: client.TeamInfo{Name: name}}
	case client.IsNotFound(err):
		resp.Diagnostics.AddError("Team not found", fmt.Sprintf("The gate knows no team %q (or it owns nothing in the zones this identity can read).", name))
		return
	case err != nil:
		addAPIError(&resp.Diagnostics, "Cannot read the team "+name, err)
		return
	}
	data := teamDataModel{teamInfoModel: teamInfo(&td.TeamInfo), Owned: []teamOwnedModel{}, PendingTransfers: []teamTransferModel{}}
	data.Name = cfg.Name
	sort.Slice(td.Owned, func(i, j int) bool { return td.Owned[i].Zone < td.Owned[j].Zone })
	total := 0
	for _, o := range td.Owned {
		total += o.RRsets
		data.Owned = append(data.Owned, teamOwnedModel{Zone: types.StringValue(o.Zone), RRsets: types.Int64Value(int64(o.RRsets)),
			Tombstones: types.Int64Value(int64(o.Tombstones))})
	}
	data.RRsets = types.Int64Value(int64(total))
	for _, t := range td.Transfers {
		sets := make([]string, 0, len(t.RRsets))
		for _, rs := range t.RRsets {
			sets = append(sets, rs.Host+"/"+strings.ToUpper(rs.Type))
		}
		expires := ""
		if t.ExpiresAt != nil {
			expires = t.ExpiresAt.UTC().Format(time.RFC3339)
		}
		data.PendingTransfers = append(data.PendingTransfers, teamTransferModel{
			ID: types.StringValue(t.ID), Kind: types.StringValue(t.Kind), Zone: types.StringValue(t.Zone),
			FromTeam: types.StringValue(t.FromTeam), ToTeam: types.StringValue(t.ToTeam), RRsets: stringList(sets),
			Requester: types.StringValue(t.Requester.Display()), ExpiresAt: types.StringValue(expires),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
