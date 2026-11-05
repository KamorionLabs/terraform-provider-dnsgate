package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	"github.com/KamorionLabs/terraform-provider-dnsgate/internal/rdata"
)

// privateHash is the private state key holding the content hash of the
// RRset as last read or written, sent back as If-Match.
const privateHash = "hash"

var (
	_ resource.ResourceWithConfigure      = (*recordSetResource)(nil)
	_ resource.ResourceWithImportState    = (*recordSetResource)(nil)
	_ resource.ResourceWithValidateConfig = (*recordSetResource)(nil)
)

type recordSetResource struct {
	pd *providerData
}

func newRecordSetResource() resource.Resource { return &recordSetResource{} }

type recordSetModel struct {
	ID     types.String `tfsdk:"id"`
	Zone   types.String `tfsdk:"zone"`
	Name   types.String `tfsdk:"name"`
	Type   types.String `tfsdk:"type"`
	TTL    types.Int64  `tfsdk:"ttl"`
	Values types.Set    `tfsdk:"values"`
	Alias  *aliasModel  `tfsdk:"alias"`
	Owner  types.String `tfsdk:"owner"`
	Status types.String `tfsdk:"status"`
}

type aliasModel struct {
	Name                 types.String `tfsdk:"name"`
	ZoneID               types.String `tfsdk:"zone_id"`
	EvaluateTargetHealth types.Bool   `tfsdk:"evaluate_target_health"`
}

func (r *recordSetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_record_set"
}

func (r *recordSetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "All records of one name and type (an RRset) in a zone served by a dns-gate, whatever the DNS " +
			"provider behind it. The RRset is owned by the team of the provider identity in the gate: the gate refuses " +
			"changes from other teams and records every change in its audit trail. Creation fails if the RRset already " +
			"exists: adopt it in the gate, then import it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`<zone>/<name>/<type>`, also the import id.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"zone": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Zone name, lowercase without trailing dot, for example `example.com`. Changing it replaces the record set.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{zoneValidator{}},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name relative to the zone, lowercase, without trailing dot: `www`, `_dmarc`, `*.apps`, " +
					"`@` for the apex. Changing it replaces the record set.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{nameValidator{}},
			},
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Record type, uppercase: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `SRV`, `NS`... The types " +
					"accepted depend on the DNS provider of the zone; SOA is never managed. Changing it replaces the record set.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{typeValidator{}},
			},
			"ttl": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "TTL in seconds. Required with `values`, not allowed with `alias` (the TTL of an alias " +
					"is the target's). Some DNS providers accept only a closed list of TTLs (EuroDNS).",
			},
			"values": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Record data, one entry per record, in zone file presentation format: `192.0.2.1`, " +
					"`10 mx.example.net.`, `v=spf1 -all`. Exactly one of `values` and `alias`. Values are compared by meaning, " +
					"not by text (see *Value comparison*): target names with or without trailing dot and in any case, TXT " +
					"values quoted or not, split in 255-byte strings or not, are the same records.",
				Validators:    []validator.Set{setvalidator.SizeAtLeast(1)},
				PlanModifiers: []planmodifier.Set{valuesEquivalent{}},
			},
			"owner": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Team that owns the RRset in the gate.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Ownership status in the gate: `managed`, `pending`, `tainted` (modified outside the gate, " +
					"writes blocked until reviewed), `foreign` (not owned by the gate).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
		Blocks: map[string]schema.Block{
			"alias": schema.SingleNestedBlock{
				MarkdownDescription: "Alias target (Route53 alias records, for example to a CloudFront distribution or a load " +
					"balancer), instead of `values` and `ttl`. Only for zones whose DNS provider supports aliases.",
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Optional: true,
						Computed: true,
						MarkdownDescription: "DNS name of the target, for example `d111111abcdef8.cloudfront.net`. Compared " +
							"case-insensitively, trailing dot optional. Required in this block.",
						PlanModifiers: []planmodifier.String{aliasNameEquivalent{}},
					},
					"zone_id": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Hosted zone id of the target, for example `Z2FDTNDATAQYW2` for CloudFront. Required in this block.",
					},
					"evaluate_target_health": schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Whether the alias answers depend on the health of the target. Required in this block.",
					},
				},
			},
		},
	}
}

func (r *recordSetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, resp.Diagnostics.AddError)
	if r.pd != nil {
		requireRRsetAPI(r.pd, &resp.Diagnostics)
	}
}

// requireRRsetAPI refuses gates without the RRset API: their 404 for an
// unknown route would read as a deleted RRset.
func requireRRsetAPI(pd *providerData, diags *diag.Diagnostics) {
	if !pd.info.HasFeature(featureRRsetAPI) {
		diags.AddError("The dns-gate does not serve the RRset API",
			fmt.Sprintf("dnsgate_record_set needs a gate that advertises the %q feature (GET %s, version %s here). Upgrade the gate.",
				featureRRsetAPI, client.InfoPath, firstNonEmpty(pd.info.Version, "unknown")))
	}
}

const featureRRsetAPI = "rrset-api"

func (r *recordSetResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg recordSetModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !cfg.Zone.IsUnknown() && !cfg.Name.IsUnknown() && !cfg.Zone.IsNull() {
		zone, name := cfg.Zone.ValueString(), cfg.Name.ValueString()
		if name == zone || strings.HasSuffix(name, "."+zone) {
			rel := strings.TrimSuffix(strings.TrimSuffix(name, zone), ".")
			resp.Diagnostics.AddAttributeError(path.Root("name"), "Name must be relative to the zone",
				fmt.Sprintf("%q is a fully qualified name in zone %s: write %q.", name, zone, firstNonEmpty(rel, "@")))
		}
	}
	hasAlias := cfg.Alias != nil
	if !cfg.Values.IsUnknown() {
		switch hasValues := !cfg.Values.IsNull(); {
		case hasValues && hasAlias:
			resp.Diagnostics.AddAttributeError(path.Root("alias"), "Conflicting record data", "Set either values (with ttl) or an alias block, not both.")
		case !hasValues && !hasAlias:
			resp.Diagnostics.AddAttributeError(path.Root("values"), "Missing record data", "Set values (with ttl), or an alias block.")
		case hasValues && cfg.TTL.IsNull():
			resp.Diagnostics.AddAttributeError(path.Root("ttl"), "Missing TTL", "ttl is required with values.")
		}
	}
	if hasAlias {
		if !cfg.TTL.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("ttl"), "TTL not allowed with an alias", "An alias record set takes the TTL of its target: remove ttl.")
		}
		for name, v := range map[string]attr.Value{"name": cfg.Alias.Name, "zone_id": cfg.Alias.ZoneID, "evaluate_target_health": cfg.Alias.EvaluateTargetHealth} {
			if v.IsNull() {
				resp.Diagnostics.AddAttributeError(path.Root("alias").AtName(name), "Missing alias attribute", "alias."+name+" is required.")
			}
		}
	}
	if !cfg.TTL.IsNull() && !cfg.TTL.IsUnknown() && cfg.TTL.ValueInt64() <= 0 {
		resp.Diagnostics.AddAttributeError(path.Root("ttl"), "Invalid TTL", "ttl must be a positive number of seconds.")
	}
	if cfg.Type.IsUnknown() || cfg.Type.IsNull() || cfg.Values.IsNull() || cfg.Values.IsUnknown() {
		return
	}
	typ := cfg.Type.ValueString()
	for _, e := range cfg.Values.Elements() {
		s, ok := e.(types.String)
		if !ok || s.IsUnknown() || s.IsNull() {
			continue
		}
		if rdata.Known(typ) && rdata.Parse(typ, s.ValueString()) == nil {
			resp.Diagnostics.AddAttributeWarning(path.Root("values"), "Value not understood",
				fmt.Sprintf("%q is not a valid %s value in zone file syntax. It is sent as is, and compared with what the gate "+
					"returns as an exact string, so a value the gate rewrites will show a difference on every plan.", s.ValueString(), typ))
		}
	}
}

func (m *recordSetModel) key() (zone, name, typ string) {
	return m.Zone.ValueString(), m.Name.ValueString(), m.Type.ValueString()
}

func recordSetID(zone, name, typ string) string { return zone + "/" + name + "/" + typ }

func (m *recordSetModel) body(ctx context.Context, diags *diag.Diagnostics) client.RRsetBody {
	if m.Alias != nil {
		return client.RRsetBody{Alias: &client.Alias{
			Target:               m.Alias.Name.ValueString(),
			HostedZoneID:         m.Alias.ZoneID.ValueString(),
			EvaluateTargetHealth: m.Alias.EvaluateTargetHealth.ValueBool(),
		}}
	}
	var values []string
	diags.Append(m.Values.ElementsAs(ctx, &values, false)...)
	sort.Strings(values)
	return client.RRsetBody{TTL: int(m.TTL.ValueInt64()), Values: values}
}

// equivalent reports whether the gate holds the desired content.
func equivalent(typ string, want client.RRsetBody, got *client.RRset) bool {
	if want.Alias != nil {
		return got.Alias != nil && rdata.NameEqual(want.Alias.Target, got.Alias.Target) &&
			strings.EqualFold(want.Alias.HostedZoneID, got.Alias.HostedZoneID) &&
			want.Alias.EvaluateTargetHealth == got.Alias.EvaluateTargetHealth
	}
	return got.Alias == nil && want.TTL == got.TTL && rdata.SetEqual(typ, want.Values, got.Values)
}

type privateState interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

func getHash(ctx context.Context, p privateState, diags *diag.Diagnostics) string {
	b, d := p.GetKey(ctx, privateHash)
	diags.Append(d...)
	var h string
	if len(b) > 0 {
		_ = json.Unmarshal(b, &h)
	}
	return h
}

func setHash(ctx context.Context, p privateState, hash string, diags *diag.Diagnostics) {
	b, _ := json.Marshal(hash)
	diags.Append(p.SetKey(ctx, privateHash, b)...)
}

// written records the gate's answer in the state: the planned values stay
// (the gate may write them in its canonical form), the gate decides owner
// and status.
func (r *recordSetResource) written(ctx context.Context, plan *recordSetModel, want client.RRsetBody, got *client.RRset, diags *diag.Diagnostics) {
	zone, name, typ := plan.key()
	plan.ID = types.StringValue(recordSetID(zone, name, typ))
	plan.Owner = types.StringValue(got.Owner)
	plan.Status = types.StringValue(firstNonEmpty(got.Status, client.StatusManaged))
	if !equivalent(typ, want, got) {
		diags.AddWarning("The gate stored different record data",
			fmt.Sprintf("%s %s in %s: the gate answered with %s, which the provider does not recognise as the configured content. "+
				"The next plan will show a difference: write the value as the gate stores it.", name, typ, zone, describeContent(got)))
	}
}

func describeContent(rs *client.RRset) string {
	if rs.Alias != nil {
		return fmt.Sprintf("alias %s (%s, evaluate_target_health=%t)", rs.Alias.Target, rs.Alias.HostedZoneID, rs.Alias.EvaluateTargetHealth)
	}
	q := make([]string, len(rs.Values))
	for i, v := range rs.Values {
		q[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf("ttl %d, values [%s]", rs.TTL, strings.Join(q, ", "))
}

// reconcile handles a 412 answered after a retry: an earlier attempt may
// have been applied before its answer was lost. The write is a success if
// the gate now holds the desired content.
func (r *recordSetResource) reconcile(ctx context.Context, zone, name, typ string, want client.RRsetBody, err error) (*client.RRset, bool) {
	e, ok := client.AsAPIError(err)
	if !ok || e.Status != http.StatusPreconditionFailed || e.Attempts < 2 {
		return nil, false
	}
	got, gerr := r.pd.client.GetRRset(ctx, zone, name, typ)
	if gerr != nil || !equivalent(typ, want, got) {
		return nil, false
	}
	tflog.Info(ctx, "write refused after a retry, but the gate holds the desired content: an earlier attempt was applied",
		map[string]any{"zone": zone, "name": name, "type": typ})
	return got, true
}

func (r *recordSetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan recordSetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name, typ := plan.key()
	want := plan.body(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.pd.client.PutRRset(ctx, zone, name, typ, want, client.Condition{IfNoneMatch: true})
	if err != nil {
		var ok bool
		if got, ok = r.reconcile(ctx, zone, name, typ, want, err); !ok {
			r.createError(&resp.Diagnostics, zone, name, typ, err)
			return
		}
	}
	r.written(ctx, &plan, want, got, &resp.Diagnostics)
	setHash(ctx, resp.Private, got.Hash, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *recordSetResource) createError(diags *diag.Diagnostics, zone, name, typ string, err error) {
	id := recordSetID(zone, name, typ)
	switch {
	case client.IsPrecondition(err):
		diags.AddError("Record set already exists",
			fmt.Sprintf("%s %s already exists in zone %s. If your team owns it in the gate, import it:\n\n"+
				"  import {\n    to = dnsgate_record_set.<name>\n    id = %q\n  }\n\n"+
				"If it was created outside the gate, adopt it for your team in the gate first (web UI or POST /api/v1/zones/%s/adopt).",
				name, typ, zone, id, zone))
	case client.Is(err, http.StatusConflict, client.ReasonForeignRRset):
		diags.AddError("Record set exists outside the gate", fmt.Sprintf("%s %s already exists in zone %s and is not owned by the gate.\n\n%s",
			name, typ, zone, describe(err)))
	default:
		addAPIError(diags, "Cannot create the record set "+id, err)
	}
}

func (r *recordSetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state recordSetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name, typ := state.key()
	got, err := r.pd.client.GetRRset(ctx, zone, name, typ)
	if client.IsNotFound(err) {
		tflog.Info(ctx, "record set not found in the gate, removing it from the state", map[string]any{"zone": zone, "name": name, "type": typ})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Cannot read the record set "+recordSetID(zone, name, typ), err)
		return
	}
	if got.Status == client.StatusMissing {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromGate(got)
	statusWarning(&resp.Diagnostics, zone, got)
	setHash(ctx, resp.Private, got.Hash, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// fromGate sets the content of the state from the gate, keeping the stored
// values and alias target when they are the same records.
func (m *recordSetModel) fromGate(got *client.RRset) {
	zone, name, typ := m.key()
	m.ID = types.StringValue(recordSetID(zone, name, typ))
	m.Owner = types.StringValue(got.Owner)
	m.Status = types.StringValue(got.Status)
	if got.Alias != nil {
		target := got.Alias.Target
		if m.Alias != nil && !m.Alias.Name.IsNull() && rdata.NameEqual(m.Alias.Name.ValueString(), target) {
			target = m.Alias.Name.ValueString()
		}
		zoneID := got.Alias.HostedZoneID
		if m.Alias != nil && strings.EqualFold(m.Alias.ZoneID.ValueString(), zoneID) {
			zoneID = m.Alias.ZoneID.ValueString()
		}
		m.Alias = &aliasModel{Name: types.StringValue(target), ZoneID: types.StringValue(zoneID),
			EvaluateTargetHealth: types.BoolValue(got.Alias.EvaluateTargetHealth)}
		m.TTL, m.Values = types.Int64Null(), types.SetNull(types.StringType)
		return
	}
	m.Alias = nil
	m.TTL = types.Int64Value(int64(got.TTL))
	if prior, ok := knownStrings(m.Values); ok && !m.Values.IsNull() && rdata.SetEqual(typ, prior, got.Values) {
		return
	}
	m.Values = stringSet(got.Values)
}

func statusWarning(diags *diag.Diagnostics, zone string, got *client.RRset) {
	switch got.Status {
	case client.StatusTainted:
		diags.AddWarning("Record set tainted in the gate",
			fmt.Sprintf("%s %s in %s was modified outside the gate. %s", got.Host, got.Type, zone, reasonHelp[client.ReasonTainted]))
	case client.StatusForeign:
		diags.AddWarning("Record set not owned by the gate",
			fmt.Sprintf("%s %s in %s is no longer owned by the gate (foreign): changes will be refused. %s", got.Host, got.Type, zone, reasonHelp[client.ReasonForeignRRset]))
	}
}

func stringSet(values []string) types.Set {
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, elems)
}

func (r *recordSetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan recordSetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name, typ := plan.key()
	want := plan.body(ctx, &resp.Diagnostics)
	hash := getHash(ctx, req.Private, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.pd.client.PutRRset(ctx, zone, name, typ, want, client.Condition{IfMatch: hash})
	if err != nil {
		var ok bool
		if got, ok = r.reconcile(ctx, zone, name, typ, want, err); !ok {
			if client.IsPrecondition(err) {
				resp.Diagnostics.AddError("Record set changed outside Terraform",
					fmt.Sprintf("%s %s in %s changed in the gate since Terraform read it. %s", name, typ, zone, reasonHelp[client.ReasonPrecondition]))
				return
			}
			addAPIError(&resp.Diagnostics, "Cannot update the record set "+recordSetID(zone, name, typ), err)
			return
		}
	}
	r.written(ctx, &plan, want, got, &resp.Diagnostics)
	setHash(ctx, resp.Private, got.Hash, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *recordSetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state recordSetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	hash := getHash(ctx, req.Private, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	zone, name, typ := state.key()
	err := r.pd.client.DeleteRRset(ctx, zone, name, typ, hash)
	if err == nil || client.IsNotFound(err) {
		return
	}
	if e, ok := client.AsAPIError(err); ok && e.Status == http.StatusPreconditionFailed {
		if e.Attempts > 1 {
			if _, gerr := r.pd.client.GetRRset(ctx, zone, name, typ); client.IsNotFound(gerr) {
				return
			}
		}
		resp.Diagnostics.AddError("Record set changed outside Terraform",
			fmt.Sprintf("%s %s in %s changed in the gate since Terraform read it, so it was not deleted. %s", name, typ, zone, reasonHelp[client.ReasonPrecondition]))
		return
	}
	addAPIError(&resp.Diagnostics, "Cannot delete the record set "+recordSetID(zone, name, typ), err)
}

// ImportState accepts "<zone>/<name>/<type>". The gate only lets a team
// manage the RRsets it owns: foreign RRsets must be adopted first.
func (r *recordSetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	zone, name, typ, ok := parseRecordSetID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id",
			fmt.Sprintf("Expected <zone>/<name>/<type>, for example example.com/www/A or example.com/@/MX, got %q.", req.ID))
		return
	}
	got, err := r.pd.client.GetRRset(ctx, zone, name, typ)
	switch {
	case client.IsNotFound(err):
		resp.Diagnostics.AddError("Record set not found", fmt.Sprintf("No %s record named %s in zone %s (or the zone is not served by the gate).", typ, name, zone))
		return
	case client.Is(err, http.StatusConflict, client.ReasonForeignRRset):
		resp.Diagnostics.AddError("Record set not adopted", importForeignHelp(zone, name, typ))
		return
	case err != nil:
		addAPIError(&resp.Diagnostics, "Cannot read the record set "+req.ID, err)
		return
	case got.Status == client.StatusForeign:
		resp.Diagnostics.AddError("Record set not adopted", importForeignHelp(zone, name, typ))
		return
	case got.Status == client.StatusMissing:
		resp.Diagnostics.AddError("Record set not found", fmt.Sprintf("%s %s is owned in the gate but missing from zone %s.", name, typ, zone))
		return
	case got.ReadOnly != "":
		resp.Diagnostics.AddError("Record set cannot be managed", fmt.Sprintf("%s %s in %s is read-only in the gate (%s).", name, typ, zone, got.ReadOnly))
		return
	}
	if me, merr := r.pd.client.Me(ctx); merr == nil && got.Owner != "" && len(me.Teams) > 0 && !contains(me.Teams, got.Owner) {
		resp.Diagnostics.AddError("Record set owned by another team",
			fmt.Sprintf("%s %s in %s is owned by team %q in the gate; this identity acts for %s. Only the owner team can manage it: "+
				"import it from that team's configuration, or have it transferred in the gate.", name, typ, zone, got.Owner, strings.Join(me.Teams, ", ")))
		return
	} else if merr != nil {
		tflog.Debug(ctx, "cannot read /api/v1/me, ownership not checked at import", map[string]any{"error": merr.Error()})
	}
	statusWarning(&resp.Diagnostics, zone, got)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), recordSetID(zone, name, typ))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("zone"), zone)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), typ)...)
}

func importForeignHelp(zone, name, typ string) string {
	return fmt.Sprintf("%s %s in %s exists but is not owned by the gate (foreign): the gate only lets a team manage the RRsets it "+
		"created or adopted. Adopt it for your team first, in the gate web UI (zone page, select the RRset, Adopt) or with "+
		"POST /api/v1/zones/%s/adopt/preview then /adopt, then run the import again.", name, typ, zone, zone)
}

func parseRecordSetID(id string) (zone, name, typ string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return "", "", "", false
	}
	zone = client.NormalizeZone(parts[0])
	name = strings.ToLower(strings.TrimSpace(parts[1]))
	if name == "" || name == zone {
		name = "@"
	}
	name = strings.TrimSuffix(strings.TrimSuffix(name, "."+zone), ".")
	typ = strings.ToUpper(strings.TrimSpace(parts[2]))
	if !zoneRe.MatchString(zone) || validName(name) != "" || !typeRe.MatchString(typ) {
		return "", "", "", false
	}
	return zone, name, typ, true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
