package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/client"
)

// dnsgate_zones

type zonesDataSource struct{ pd *providerData }

func newZonesDataSource() datasource.DataSource { return &zonesDataSource{} }

type zoneModel struct {
	Zone        types.String `tfsdk:"zone"`
	DNSProvider types.String `tfsdk:"dns_provider"`
	Unmanaged   types.Bool   `tfsdk:"unmanaged"`
	RRsets      types.Int64  `tfsdk:"rrsets"`
	Managed     types.Int64  `tfsdk:"managed"`
	Tainted     types.Int64  `tfsdk:"tainted"`
	Pending     types.Int64  `tfsdk:"pending"`
	Foreign     types.Int64  `tfsdk:"foreign"`
}

type zonesDataModel struct {
	DNSProvider      types.String `tfsdk:"dns_provider"`
	IncludeUnmanaged types.Bool   `tfsdk:"include_unmanaged"`
	Names            types.List   `tfsdk:"names"`
	Zones            []zoneModel  `tfsdk:"zones"`
}

func (d *zonesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_zones"
}

func (d *zonesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The zones the provider identity can read in the gate, with their ownership counts.",
		Attributes: map[string]schema.Attribute{
			"dns_provider": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Keep only the zones of this DNS provider instance or kind, as the gate names it (for example `route53`).",
			},
			"include_unmanaged": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Also list the zones discovered in the provider account but not managed by the gate " +
					"(read-only). Default `false`.",
			},
			"names": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Zone names, sorted."},
			"zones": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Zones sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"zone":         schema.StringAttribute{Computed: true},
					"dns_provider": schema.StringAttribute{Computed: true, MarkdownDescription: "DNS provider of the zone in the gate."},
					"unmanaged":    schema.BoolAttribute{Computed: true, MarkdownDescription: "Discovered, not managed: read-only."},
					"rrsets":       schema.Int64Attribute{Computed: true, MarkdownDescription: "RRsets in the zone."},
					"managed":      schema.Int64Attribute{Computed: true, MarkdownDescription: "RRsets owned by the gate."},
					"tainted":      schema.Int64Attribute{Computed: true, MarkdownDescription: "RRsets modified outside the gate."},
					"pending":      schema.Int64Attribute{Computed: true},
					"foreign":      schema.Int64Attribute{Computed: true, MarkdownDescription: "RRsets not owned by the gate."},
				}},
			},
		},
	}
}

func (d *zonesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
}

func (d *zonesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data zonesDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zs, err := d.pd.client.Zones(ctx)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot list the zones", err)
		return
	}
	sort.Slice(zs, func(i, j int) bool { return zs[i].Zone < zs[j].Zone })
	data.Zones = []zoneModel{}
	names := []attr.Value{}
	for _, z := range zs {
		if z.Unmanaged && !data.IncludeUnmanaged.ValueBool() {
			continue
		}
		if p := data.DNSProvider.ValueString(); p != "" && !strings.EqualFold(p, z.Provider) {
			continue
		}
		data.Zones = append(data.Zones, zoneModel{
			Zone: types.StringValue(z.Zone), DNSProvider: types.StringValue(z.Provider), Unmanaged: types.BoolValue(z.Unmanaged),
			RRsets: types.Int64Value(int64(z.RRsets)), Managed: types.Int64Value(int64(z.Managed)), Tainted: types.Int64Value(int64(z.Tainted)),
			Pending: types.Int64Value(int64(z.Pending)), Foreign: types.Int64Value(int64(z.Foreign)),
		})
		names = append(names, types.StringValue(z.Zone))
	}
	data.Names = types.ListValueMust(types.StringType, names)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Shared RRset attributes of the data sources.

var aliasAttrTypes = map[string]attr.Type{
	"name": types.StringType, "zone_id": types.StringType, "evaluate_target_health": types.BoolType,
}

func aliasObject(a *client.Alias) types.Object {
	if a == nil {
		return types.ObjectNull(aliasAttrTypes)
	}
	return types.ObjectValueMust(aliasAttrTypes, map[string]attr.Value{
		"name": types.StringValue(a.Target), "zone_id": types.StringValue(a.HostedZoneID),
		"evaluate_target_health": types.BoolValue(a.EvaluateTargetHealth),
	})
}

func aliasSchema() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Computed:            true,
		MarkdownDescription: "Alias target, null for records with values.",
		Attributes: map[string]schema.Attribute{
			"name":                   schema.StringAttribute{Computed: true},
			"zone_id":                schema.StringAttribute{Computed: true},
			"evaluate_target_health": schema.BoolAttribute{Computed: true},
		},
	}
}

func ttlValue(rs *client.RRset) types.Int64 {
	if rs.Alias != nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(rs.TTL))
}

// dnsgate_record_sets

type recordSetsDataSource struct{ pd *providerData }

func newRecordSetsDataSource() datasource.DataSource { return &recordSetsDataSource{} }

type recordSetsItem struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Type      types.String `tfsdk:"type"`
	TTL       types.Int64  `tfsdk:"ttl"`
	Values    types.List   `tfsdk:"values"`
	Alias     types.Object `tfsdk:"alias"`
	Owner     types.String `tfsdk:"owner"`
	Status    types.String `tfsdk:"status"`
	Protected types.Bool   `tfsdk:"protected"`
	ReadOnly  types.String `tfsdk:"read_only"`
	Hash      types.String `tfsdk:"hash"`
	CreatedBy types.String `tfsdk:"created_by"`
	UpdatedBy types.String `tfsdk:"updated_by"`
}

type recordSetsDataModel struct {
	Zone       types.String     `tfsdk:"zone"`
	Name       types.String     `tfsdk:"name"`
	Type       types.String     `tfsdk:"type"`
	Owner      types.String     `tfsdk:"owner"`
	Status     types.String     `tfsdk:"status"`
	RecordSets []recordSetsItem `tfsdk:"record_sets"`
}

func (d *recordSetsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record_sets"
}

func (d *recordSetsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The RRsets of a zone with their ownership in the gate (the zone inventory), optionally filtered.",
		Attributes: map[string]schema.Attribute{
			"zone": schema.StringAttribute{Required: true, MarkdownDescription: "Zone name, for example `example.com`."},
			"name": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Glob on the name relative to the zone: `*` matches any characters (dots included), `?` one " +
					"character; `@` is the apex. For example `_acme-challenge.*` or `*.apps`.",
			},
			"type":   schema.StringAttribute{Optional: true, MarkdownDescription: "Keep only this record type (case-insensitive)."},
			"owner":  schema.StringAttribute{Optional: true, MarkdownDescription: "Keep only the RRsets owned by this team."},
			"status": schema.StringAttribute{Optional: true, MarkdownDescription: "Keep only this status: `managed`, `pending`, `tainted`, `foreign`, `missing`."},
			"record_sets": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Matching RRsets sorted by name then type.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id":         schema.StringAttribute{Computed: true, MarkdownDescription: "`<zone>/<name>/<type>`, the import id of `dnsgate_record_set`."},
					"name":       schema.StringAttribute{Computed: true},
					"type":       schema.StringAttribute{Computed: true},
					"ttl":        schema.Int64Attribute{Computed: true, MarkdownDescription: "Null for aliases."},
					"values":     schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Sorted values, as the gate stores them."},
					"alias":      aliasSchema(),
					"owner":      schema.StringAttribute{Computed: true, MarkdownDescription: "Owner team, empty when not owned."},
					"status":     schema.StringAttribute{Computed: true},
					"protected":  schema.BoolAttribute{Computed: true, MarkdownDescription: "Protected by the gate configuration: never written."},
					"read_only":  schema.StringAttribute{Computed: true, MarkdownDescription: "Why the gate never writes this RRset, empty otherwise."},
					"hash":       schema.StringAttribute{Computed: true, MarkdownDescription: "Content hash (the ETag of the RRset)."},
					"created_by": schema.StringAttribute{Computed: true},
					"updated_by": schema.StringAttribute{Computed: true},
				}},
			},
		},
	}
}

func (d *recordSetsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
}

func (d *recordSetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data recordSetsDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone := client.NormalizeZone(data.Zone.ValueString())
	inv, err := d.pd.client.Inventory(ctx, zone)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot read the zone "+zone, err)
		return
	}
	sets := inv.RRsets
	sort.Slice(sets, func(i, j int) bool {
		return sets[i].Host < sets[j].Host || sets[i].Host == sets[j].Host && sets[i].Type < sets[j].Type
	})
	data.RecordSets = []recordSetsItem{}
	for i := range sets {
		rs := &sets[i]
		switch {
		case !data.Name.IsNull() && !globMatch(strings.ToLower(data.Name.ValueString()), rs.Host),
			!data.Type.IsNull() && !strings.EqualFold(data.Type.ValueString(), rs.Type),
			!data.Owner.IsNull() && data.Owner.ValueString() != rs.Owner,
			!data.Status.IsNull() && !strings.EqualFold(data.Status.ValueString(), rs.Status):
			continue
		}
		values := append([]string(nil), rs.Values...)
		sort.Strings(values)
		vals := make([]attr.Value, len(values))
		for k, v := range values {
			vals[k] = types.StringValue(v)
		}
		data.RecordSets = append(data.RecordSets, recordSetsItem{
			ID: types.StringValue(recordSetID(zone, rs.Host, rs.Type)), Name: types.StringValue(rs.Host), Type: types.StringValue(rs.Type),
			TTL: ttlValue(rs), Values: types.ListValueMust(types.StringType, vals), Alias: aliasObject(rs.Alias),
			Owner: types.StringValue(rs.Owner), Status: types.StringValue(rs.Status), Protected: types.BoolValue(rs.Protected),
			ReadOnly: types.StringValue(rs.ReadOnly), Hash: types.StringValue(rs.Hash),
			CreatedBy: types.StringValue(rs.CreatedBy.Display()), UpdatedBy: types.StringValue(rs.UpdatedBy.Display()),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// globMatch is the gate's glob: "*" any sequence of characters, "?" one.
func globMatch(pattern, s string) bool {
	p, str := []rune(pattern), []rune(s)
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(str) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == str[si]):
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// dnsgate_record_set

type recordSetDataSource struct{ pd *providerData }

func newRecordSetDataSource() datasource.DataSource { return &recordSetDataSource{} }

type recordSetDataModel struct {
	ID        types.String `tfsdk:"id"`
	Zone      types.String `tfsdk:"zone"`
	Name      types.String `tfsdk:"name"`
	Type      types.String `tfsdk:"type"`
	TTL       types.Int64  `tfsdk:"ttl"`
	Values    types.Set    `tfsdk:"values"`
	Alias     types.Object `tfsdk:"alias"`
	Owner     types.String `tfsdk:"owner"`
	Status    types.String `tfsdk:"status"`
	Protected types.Bool   `tfsdk:"protected"`
	Hash      types.String `tfsdk:"hash"`
}

func (d *recordSetDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record_set"
}

func (d *recordSetDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "One RRset of a zone served by the gate, whoever owns it. Fails if it does not exist.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, MarkdownDescription: "`<zone>/<name>/<type>`."},
			"zone":      schema.StringAttribute{Required: true},
			"name":      schema.StringAttribute{Required: true, MarkdownDescription: "Name relative to the zone, `@` for the apex."},
			"type":      schema.StringAttribute{Required: true},
			"ttl":       schema.Int64Attribute{Computed: true, MarkdownDescription: "Null for aliases."},
			"values":    schema.SetAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Values as the gate stores them."},
			"alias":     aliasSchema(),
			"owner":     schema.StringAttribute{Computed: true},
			"status":    schema.StringAttribute{Computed: true},
			"protected": schema.BoolAttribute{Computed: true},
			"hash":      schema.StringAttribute{Computed: true, MarkdownDescription: "Content hash (the ETag of the RRset)."},
		},
	}
}

func (d *recordSetDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
	if d.pd != nil {
		requireRRsetAPI(d.pd, &resp.Diagnostics)
	}
}

func (d *recordSetDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data recordSetDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone := client.NormalizeZone(data.Zone.ValueString())
	name, typ := strings.ToLower(data.Name.ValueString()), strings.ToUpper(data.Type.ValueString())
	rs, err := d.pd.client.GetRRset(ctx, zone, name, typ)
	if client.IsNotFound(err) {
		resp.Diagnostics.AddError("Record set not found", fmt.Sprintf("No %s record named %s in zone %s.", typ, name, zone))
		return
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot read the record set", err)
		return
	}
	data.ID = types.StringValue(recordSetID(zone, name, typ))
	data.TTL = ttlValue(rs)
	data.Values = stringSet(rs.Values)
	if rs.Alias != nil {
		data.Values = types.SetNull(types.StringType)
	}
	data.Alias = aliasObject(rs.Alias)
	data.Owner, data.Status = types.StringValue(rs.Owner), types.StringValue(rs.Status)
	data.Protected, data.Hash = types.BoolValue(rs.Protected), types.StringValue(rs.Hash)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
